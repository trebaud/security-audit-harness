#!/usr/bin/env bash
# Installs the harness into a repository.
#
#   ./install.sh <repo-path> [--force] [--scope <path>]
#
# Copies three things into the target repo:
#
#   .agents/skills/security-audit/
#   .agents/skills/scan/                    (split audit across git worktrees)
#   security/audit/rules.json
#
# each at the same path it has here. .agents/skills/ is where Codex, OpenCode and
# other Agent Skills clients look; Claude Code reads .claude/skills/ only, so it
# also links .claude/skills/<name> -> ../../.agents/skills/<name> for each skill.
# It also creates the audit's home,
# security/audit/ (with its gitignored reports/ subfolder), where the skill
# writes run.sarif and baseline.sarif and where rules.json lives. It appends
# the scratch paths to the repo's .gitignore.
#
# rules.json is seeded from this repo's own copy, which is a starting point
# every project is expected to edit. Only that one file is copied out of
# security/audit/, never the folder: a baseline.sarif from dogfooding the
# harness on itself must not seed anyone else's repo.
#
# It never overwrites an existing file unless --force is passed, and it never
# touches an existing baseline.sarif or rules.json (those are the project's
# memory). The project's own THREAT_MODEL.md (repo root by default) is created
# by the skill on its first run.
#
# The SARIF tool has no wrapper here: the skills and reviewers run
# the copy installed at .agents/skills/security-audit/scripts/sarif.mjs, so the
# version that wrote a baseline is the version that reads it.
set -euo pipefail

HARNESS_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SKILL_SRC="$HARNESS_ROOT/.agents/skills/security-audit"
SKILL_DEST=".agents/skills/security-audit"
SCAN_SRC="$HARNESS_ROOT/.agents/skills/scan"
SCAN_DEST=".agents/skills/scan"
AUDIT_DIR="security/audit"
USAGE='usage: ./install.sh <repo-path> [--force] [--scope <path>]'

# Files the installer never replaces, even with --force: they hold the project's decisions.
PRESERVED=("$AUDIT_DIR/baseline.sarif" "$AUDIT_DIR/rules.json")

GITIGNORE_BLOCK='
# security-audit scratch output: one run'"'"'s SARIF (after the merge it holds only
# that run'"'"'s new results, with exploit details), the local audit reports and
# the scan skill'"'"'s run folders
security/audit/run.sarif
security/audit/reports/
security/audit/scan/
'

fail() { printf 'install: %s\n' "$1" >&2; exit 1; }

repo=""
force=0
scope="src"
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) printf '%s\n' "$USAGE"; exit 0 ;;
        --force) force=1 ;;
        --scope) shift; [ $# -gt 0 ] || fail "--scope needs a path"; scope="$1" ;;
        -*) fail "unknown flag $1"$'\n'"$USAGE" ;;
        *) [ -z "$repo" ] || fail "unexpected argument $1"$'\n'"$USAGE"; repo="$1" ;;
    esac
    shift
done

[ -n "$repo" ] || fail "needs a repo path"$'\n'"$USAGE"
[ -d "$repo" ] || fail "$repo is not a directory"
[[ "$scope" =~ ^[A-Za-z0-9_./-]+$ ]] || fail "--scope must be a plain relative path, got \"$scope\""
[ -d "$SKILL_SRC" ] || fail "$SKILL_SRC is missing; run install.sh from a complete checkout"
[ -d "$SCAN_SRC" ] || fail "$SCAN_SRC is missing; run install.sh from a complete checkout"
[ -f "$HARNESS_ROOT/$AUDIT_DIR/rules.json" ] || fail "$HARNESS_ROOT/$AUDIT_DIR/rules.json is missing"
target=$(cd -- "$repo" && pwd)
[ "$target" != "$HARNESS_ROOT" ] || fail "the target repo is the harness itself"

written=()
skipped=()

is_preserved() {
    local candidate="$1" p
    for p in "${PRESERVED[@]}"; do [ "$p" = "$candidate" ] && return 0; done
    return 1
}

# copy <source file> <path relative to the target repo>
copy() {
    local src="$1" rel="$2" dest="$target/$2"
    if [ -e "$dest" ] && { is_preserved "$rel" || [ "$force" -eq 0 ]; }; then
        skipped+=("$rel")
        return 0
    fi
    mkdir -p -- "$(dirname -- "$dest")"
    cp -- "$src" "$dest"
    written+=("$rel")
}

# copy_tree <source dir> <destination prefix in the target repo>
# Skips what a local checkout accumulates but a target repo must never receive:
# Finder metadata.
copy_tree() {
    local src_dir="$1" dest_prefix="$2" file
    while IFS= read -r file; do
        copy "$file" "${dest_prefix}${file#"$src_dir"/}"
    done < <(find "$src_dir" -type f ! -name '.DS_Store' | sort)
}

# The audit's home. reports/ is gitignored, so it only ever exists locally.
mkdir -p -- "$target/$AUDIT_DIR/reports"

copy_tree "$SKILL_SRC" "$SKILL_DEST/"
copy_tree "$SCAN_SRC" "$SCAN_DEST/"
copy "$HARNESS_ROOT/$AUDIT_DIR/rules.json" "$AUDIT_DIR/rules.json"

# Claude Code discovery: a relative link, so it survives a clone and resolves in a worktree.
for name in security-audit scan; do
    link=".claude/skills/$name"
    if [ -e "$target/$link" ] || [ -L "$target/$link" ]; then
        skipped+=("$link")
        continue
    fi
    mkdir -p -- "$target/.claude/skills"
    ln -s "../../.agents/skills/$name" "$target/$link"
    written+=("$link -> .agents/skills/$name")
done

gitignore="$target/.gitignore"
if [ -f "$gitignore" ] && grep -qF "$AUDIT_DIR/run.sarif" "$gitignore"; then
    if grep -qF "$AUDIT_DIR/scan/" "$gitignore"; then
        skipped+=(".gitignore (already ignores the scratch paths)")
    else
        # Installed before the scan skill existed: add its run folder only.
        [ -z "$(tail -c 1 -- "$gitignore")" ] || printf '\n' >> "$gitignore"
        printf '%s\n' "$AUDIT_DIR/scan/" >> "$gitignore"
        written+=(".gitignore (appended $AUDIT_DIR/scan/)")
    fi
else
    if [ -s "$gitignore" ]; then
        # Keep the appended block separated from whatever the last line was.
        [ -z "$(tail -c 1 -- "$gitignore")" ] || printf '\n' >> "$gitignore"
        printf '%s' "$GITIGNORE_BLOCK" >> "$gitignore"
        written+=(".gitignore (appended)")
    else
        # A new (or empty) .gitignore should not start with a blank line.
        printf '%s' "${GITIGNORE_BLOCK#$'\n'}" > "$gitignore"
        written+=(".gitignore")
    fi
fi

for f in ${written[@]+"${written[@]}"}; do printf '  + %s\n' "$f"; done
for f in ${skipped[@]+"${skipped[@]}"}; do printf '  = %s (kept)\n' "$f"; done

cat <<EOF

Installed into $target. Next:
  1. Run it locally once, from your coding agent (Claude Code, Codex, OpenCode, ...): the
     security-audit skill with \`$scope --sarif\` (\`/security-audit $scope --sarif\` in Claude Code). The skill derives
     THREAT_MODEL.md at the repo root if it finds none; review it, then commit it with $AUDIT_DIR/baseline.sarif.
  2. For a codebase too large for one session: the scan skill with \`$scope --sarif\` splits the audit by module or by
     endpoint group, one git worktree per group, and aggregates one report.
EOF
