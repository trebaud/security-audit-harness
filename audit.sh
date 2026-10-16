#!/usr/bin/env bash
# Runs the security-audit skill, loaded from this repo as a plugin, once per target, each in its own
# mori worktree (sec-audit-<id>-<target>), then merges every report into one summary in a separate
# worktree (sec-audit-<id>-summary), with a live dashboard of state, subagents, tokens, cost and
# findings. See README.md.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)

usage() {
  cat <<EOF
Usage: $(basename "$0") [-t <target,target,...>] [-f <file>] [-r <repo>] [-j <jobs>] [-i <id>]
       [-m <model>] [-e <effort>]

  -t, --targets       comma-separated targets to audit, e.g. carts,refunds,b2b-api
  -f, --targets-file  file with one target per line; blank lines and # comments are skipped
  -r, --repo          git repo to audit (default: the repo of the current directory)
  -j, --jobs          audits run in parallel (default: 4)
  -i, --id            run id (default: today, YYYYMMDD); reuse an id to resume that run
  -m, --model         model for every claude session: an alias (opus, sonnet) or a full name
  -e, --effort        effort for every claude session: low, medium, high, xhigh or max
  -h, --help          show this help

-t and -f can be combined. Without either, each entry point of the threat model is a target, named
after its id and name, e.g. e2-authenticated-api.

Env: NO_COLOR=1 turns colors off, REFRESH=<seconds> sets the dashboard refresh.
EOF
}

die() {
  echo "error: $*" >&2
  echo "run $(basename "$0") -h for usage" >&2
  exit 1
}

# ---- Options --------------------------------------------------------------------------------------

target_list="" targets_file="" repo="" jobs=4 id=$(date +%Y%m%d) model="" effort=""
targets=()

require_value() { [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"; }

parse_args() {
  while [ $# -gt 0 ]; do
    case $1 in
      -h | --help) usage; exit 0 ;;
      -t | --targets)      require_value "$@"; target_list=$2;  shift 2 ;;
      -f | --targets-file) require_value "$@"; targets_file=$2; shift 2 ;;
      -r | --repo)         require_value "$@"; repo=$2;         shift 2 ;;
      -j | --jobs)         require_value "$@"; jobs=$2;         shift 2 ;;
      -i | --id)           require_value "$@"; id=$2;           shift 2 ;;
      -m | --model)        require_value "$@"; model=$2;        shift 2 ;;
      -e | --effort)       require_value "$@"; effort=$2;       shift 2 ;;
      *) die "unknown argument: $1" ;;
    esac
  done
}

# Fills targets from -t and -f: split on commas and lines, trimmed, without blanks, # comments
# or duplicates. Leaves targets empty when neither is given.
read_targets() {
  local target
  if [ -n "$targets_file" ]; then
    [ -f "$targets_file" ] || die "targets file $targets_file not found"
  fi
  while IFS= read -r target; do
    targets+=("$target")
  done < <({ echo "$target_list"; [ -z "$targets_file" ] || grep -v '^[[:space:]]*#' "$targets_file"; } \
    | tr ',' '\n' | tr -d ' \t' | grep -v '^$' | awk '!seen[$0]++')
  [ ${#targets[@]} -gt 0 ] || [ -z "$target_list$targets_file" ] || die "no targets in -t or -f"
}

validate_options() {
  local target
  for target in ${targets[@]+"${targets[@]}"}; do
    # The skill names its report after the target, so keep targets already in slug form.
    [[ $target =~ ^[a-z0-9][a-z0-9-]*$ ]] \
      || die "invalid target '$target': use names like auth or b2b-api (lowercase letters, digits, -), not paths"
    [ "$target" != summary ] || die "'summary' is reserved for the merge step"
  done
  [[ $jobs =~ ^[1-9][0-9]*$ ]] || die "--jobs must be a positive integer, got '$jobs'"
  [[ -z $effort || $effort =~ ^(low|medium|high|xhigh|max)$ ]] \
    || die "--effort must be low, medium, high, xhigh or max, got '$effort'"
  [[ $id =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
    || die "--id must be a slug (letters, digits, . _ -) starting alphanumeric, got '$id'"
}

# Sets repo to the top level of -r <repo>, or of the current directory's repo.
resolve_repo() {
  local root
  if [ -z "$repo" ]; then
    repo=$(git rev-parse --show-toplevel 2>/dev/null) || die "not inside a git repo: pass -r <repo>"
    return
  fi
  [ -d "$repo" ] || die "repo $repo does not exist"
  root=$(git -C "$repo" rev-parse --show-toplevel 2>/dev/null) || die "$repo is not a git repo"
  repo=$root
}

# ---- Preflight ------------------------------------------------------------------------------------

# The skill as a plugin namespaces it: <plugin name>:<skill name>.
SKILL=/security-audit-harness:security-audit

# Prints the branch mori cuts worktrees from: origin/HEAD, else main or master.
base_branch() {
  local ref name
  if ref=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null); then
    echo "${ref##*/}"
    return
  fi
  for name in main master; do
    if git rev-parse --verify --quiet "$name" >/dev/null; then
      echo "$name"
      return
    fi
  done
  echo main
}

# True when the threat model on stdin is still the skill's template: the skill deletes the template
# note once it fills the model in. Reads all of stdin, so a pipe into it never fails on SIGPIPE.
is_template() { grep '^> \*\*Template\.\*\*' >/dev/null; }

# Prints the first filled-in THREAT_MODEL.md committed on branch $1, outside node_modules, as the
# skill looks for one anywhere in the repo.
committed_threat_model() {
  local path
  while IFS= read -r path; do
    git show "$1:$path" | is_template || { echo "$path"; return; }
  done < <(git ls-tree -r --name-only "$1" | grep -E '(^|/)THREAT_MODEL\.md$' | grep -Ev '(^|/)node_modules/')
}

# Stops the run unless a filled-in threat model is committed on the base branch:
# every audit runs in a worktree cut from it, so files only in the working tree never reach one.
# Prints the commands for the steps that are not plain git.
preflight() {
  local base problems=() fixes=()
  base=$(base_branch)
  git rev-parse --verify --quiet "$base^{commit}" >/dev/null \
    || die "branch $base not found: mori cuts the audit worktrees from it"

  if [ -z "$(committed_threat_model "$base")" ]; then
    if [ -f THREAT_MODEL.md ] && ! is_template <THREAT_MODEL.md; then
      problems+=("THREAT_MODEL.md not committed on $base")
    else
      if [ -f THREAT_MODEL.md ]; then
        problems+=("THREAT_MODEL.md is still the template")
      else
        problems+=("no THREAT_MODEL.md")
      fi
      fixes+=("${D}threat model${X}   claude --plugin-dir $(short "$HERE") \"$SKILL threat model only\"")
    fi
  fi

  [ ${#problems[@]} -gt 0 ] || return 0
  {
    echo "${B}${R}Preflight failed${X} for $(short "$repo")"
    printf "  ${R}✗${X} %s\n" "${problems[@]}"
    echo
    [ ${#fixes[@]} -eq 0 ] || printf '  %s\n' "${fixes[@]}" ""
    echo "Commit to $base, which every audit worktree is cut from, then rerun."
  } >&2
  exit 1
}

# Fills targets with one per entry point (E1, E2, …) in the trust boundaries of the threat model
# committed on the base branch, named after its id and the first words of its name, e.g.
# e2-authenticated-api: the skill audits the entry point whose id starts the target.
read_entry_point_targets() {
  local base target
  base=$(base_branch)
  while IFS= read -r target; do
    targets+=("$target")
  done < <(git show "$base:$(committed_threat_model "$base")" | awk -F'|' '
    /^## / { in_boundaries = ($0 ~ /^## Trust boundaries/) }
    in_boundaries && $2 ~ /^ *E[0-9]+ *$/ {
      id = tolower($2); gsub(/ /, "", id)
      name = tolower($3); sub(/ —.*/, "", name); gsub(/[^a-z0-9]+/, "-", name); gsub(/^-|-$/, "", name)
      n = split(name, words, "-"); name = ""
      for (i = 1; i <= n && i <= 3; i++) name = name "-" words[i]
      print id name
    }')
  [ ${#targets[@]} -gt 0 ] || die "no entry points (E1, E2, …) in the threat model's trust boundaries: pass -t or -f"
}

# Claims the run folder for this process and records its targets.
start_run() {
  mkdir -p "$OUT"
  if [ -f "$OUT/run.pid" ] && kill -0 "$(cat "$OUT/run.pid")" 2>/dev/null; then
    die "run $RUN is already in progress (pid $(cat "$OUT/run.pid")); watch it with $HERE/status.sh $RUN"
  fi
  echo $$ >"$OUT/run.pid"
  rm -f "$OUT"/summary.* "$OUT"/summary-2???-??-??.md "$OUT/run.end"
  date +%s >"$OUT/run.start"
  # A resumed run with fewer targets keeps the earlier ones on the dashboard and in the summary.
  { cat "$OUT/targets" 2>/dev/null || true; printf '%s\n' "${targets[@]}"; } | awk '!seen[$0]++' >"$OUT/targets.tmp"
  mv "$OUT/targets.tmp" "$OUT/targets"
}

# ---- Audits ---------------------------------------------------------------------------------------

log() { echo "$(date +%T) $*" >>"$OUT/events.log"; }
set_state() { echo "$2" >"$OUT/$1.state"; }
has_report() { ls "$OUT/$1"-2???-??-??.md >/dev/null 2>&1; }

# Prints the worktree of sec-audit-<ID>-<name>, creating it first if needed.
worktree_path() {
  local name=$1 branch="sec-audit-$ID-$1"
  if ! mori path "$branch" >/dev/null 2>&1; then
    set_state "$name" setup
    log "  $name creating worktree"
    if ! mori new "$branch" >"$OUT/$name.setup.log" 2>&1; then
      set_state "$name" failed
      log "! $name worktree creation failed, see $name.setup.log"
      return 1
    fi
  fi
  mori path "$branch"
}

# Creates worktrees one at a time (concurrent `git worktree add` races on .git locks) and prints
# each target as soon as its worktree is ready, so the audit pool can start it.
queue_targets() {
  local target
  for target in "$@"; do
    if has_report "$target"; then
      set_state "$target" done
      log "= $target already has a report"
      continue
    fi
    worktree_path "$target" >/dev/null || continue
    set_state "$target" queued
    echo "$target"
  done
}

# Runs claude headless in a worktree, tracks it under $OUT/<name>.* and copies back the report it
# writes to .security-audit/<name>-<date>.md.
run_claude() {
  local name=$1 dir=$2 prompt=$3 sid code=0 cost
  sid=$(uuidgen | tr '[:upper:]' '[:lower:]')
  echo "$sid" >"$OUT/$name.session"
  date +%s >"$OUT/$name.start"
  rm -f "$OUT/$name.end"
  set_state "$name" running
  log "> $name started (session $sid)"

  (cd "$dir" && claude -p "$prompt" --plugin-dir "$HERE" \
    ${MODEL:+--model "$MODEL"} ${EFFORT:+--effort "$EFFORT"} \
    --session-id "$sid" --permission-mode auto --output-format stream-json --verbose </dev/null) \
    >"$OUT/$name.jsonl" 2>"$OUT/$name.err" || code=$?

  date +%s >"$OUT/$name.end"
  cost=$(grep '"type":"result"' "$OUT/$name.jsonl" | tail -1 | jq -r '.total_cost_usd | "$\(. * 100 | round / 100)"') || true
  cost=${cost:-cost unknown}
  if cp "$dir/.security-audit/$name"-2???-??-??.md "$OUT/" 2>/dev/null; then
    set_state "$name" done
    log "+ $name done, $cost"
  else
    set_state "$name" failed
    log "! $name no report (claude exit $code), $cost, see $name.err"
  fi
}

audit() {
  local target=$1 dir
  if ! dir=$(mori path "sec-audit-$ID-$target"); then
    set_state "$target" failed
    log "! $target worktree missing"
    return
  fi
  run_claude "$target" "$dir" "$SKILL $target"
}
# xargs starts each audit in a new bash, which only sees exported functions and variables.
export -f log set_state has_report run_claude audit

# Merges every report into one summary, written by claude in its own worktree.
summarize() {
  local dir missing="" target prompt
  if ! ls "$OUT"/*-2???-??-??.md >/dev/null 2>&1; then
    log "! no reports, no summary"
    return
  fi
  dir=$(worktree_path summary) || return
  rm -rf "$dir/.security-audit/$ID"
  mkdir -p "$dir/.security-audit/$ID"
  cp "$OUT"/*-2???-??-??.md "$dir/.security-audit/$ID/"
  for target in $(cat "$OUT/targets"); do
    has_report "$target" || missing="$missing $target"
  done
  prompt="$(cat "$HERE/summary-prompt.md")

Reports: .security-audit/$ID/
Targets without a report:${missing:- none}
Write the summary to .security-audit/summary-$(date +%F).md"
  run_claude summary "$dir" "$prompt"
}

# ---- Dashboard ------------------------------------------------------------------------------------

color="" B="" D="" G="" R="" Y="" X=""
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  color=1 B=$'\033[1m' D=$'\033[2m' G=$'\033[32m' R=$'\033[31m' Y=$'\033[33m' X=$'\033[0m'
fi

short() { local tilde='~'; echo "${1/#$HOME/$tilde}"; }
dashboard() { FORCE_COLOR=$color "$HERE/status.sh" "$RUN"; }

# Shows the dashboard until process $1 exits. On a terminal, redraws in place (home, overwrite,
# clear the rest) instead of clearing first, which avoids flicker; otherwise prints a snapshot
# every REFRESH.
watch_until() {
  local pid=$1 screen
  local hint="${D}Ctrl-C stops every audit · watch from elsewhere: $(short "$HERE")/status.sh $RUN · logs: $(short "$OUT")/$X"
  while kill -0 "$pid" 2>/dev/null; do
    screen=$(dashboard) || true
    if [ -t 1 ]; then
      printf '\033[H%s\033[K\n\n%s\033[K\033[J' "${screen//$'\n'/$'\033[K\n'}" "$hint"
    else
      printf '%s\n\n' "$screen"
    fi
    sleep "${REFRESH:-10}" & wait $! || true
  done
  wait "$pid" || true
}

# Kills the whole process group: xargs, every audit and its claude session.
stop() {
  trap - INT TERM EXIT
  [ -t 1 ] && tput cnorm
  rm -f "$OUT/run.pid"
  kill 0
}

# ---- Result ---------------------------------------------------------------------------------------

# Appends the dashboard, without its event log, to the summary.
append_run_stats() {
  { printf '\n## Run stats\n\n```\n'; "$HERE/status.sh" "$RUN" | awk 'NF == 0 { n++ } n < 2'; printf '```\n'; } >>"$1"
}

failed_targets() {
  grep -lx failed "$OUT"/*.state 2>/dev/null | xargs -n1 basename | sed 's/\.state$//' | grep -vx summary | paste -sd, -
}

print_result() {
  local summary=$1 failed=$2
  if [ -t 1 ]; then
    printf '\033[H\033[2J'
    tput cnorm
  fi
  dashboard
  echo
  if [ -n "$summary" ]; then
    echo "${B}${G}Summary${X}       $(short "$summary")"
  else
    echo "${B}${R}No summary${X}    see $(short "$OUT")/events.log"
  fi
  if [ -n "$failed" ]; then
    echo "${B}${Y}Retry failed${X}  $(short "$HERE")/$(basename "$0") -r $(short "$repo") -i $ID${MODEL:+ -m $MODEL}${EFFORT:+ -e $EFFORT} -t $failed"
  fi
  echo "${D}Clean up      worktrees keep the tests the audits wrote; remove them with:"
  echo "              cd $(short "$repo") && mori list --json | jq -r '.[].branch | select(startswith(\"sec-audit-$ID-\"))' | xargs -I{} mori rm {} -f$X"
}

# ---- Main -----------------------------------------------------------------------------------------

main() {
  local cmd summary failed
  parse_args "$@"
  read_targets
  validate_options
  for cmd in git mori claude jq uuidgen; do
    command -v "$cmd" >/dev/null || die "$cmd not found on PATH"
  done
  resolve_repo
  cd "$repo"
  preflight
  [ ${#targets[@]} -gt 0 ] || read_entry_point_targets

  export ID=$id HERE SKILL MODEL=$model EFFORT=$effort
  export OUT="$HERE/runs/$(basename "$repo")-$ID"
  RUN=$(basename "$OUT")
  start_run

  trap stop INT TERM
  # Exiting on an error must not leave audits running unattended: they would later write into a new run.
  trap '[ $? -eq 0 ] && rm -f "$OUT/run.pid" || stop' EXIT
  if [ -t 1 ]; then
    tput civis
    printf '\033[2J'
  else
    REFRESH=${REFRESH:-120}
  fi
  log "run $RUN: ${#targets[@]} targets, $jobs parallel, repo $repo${MODEL:+, model $MODEL}${EFFORT:+, effort $EFFORT}"

  queue_targets "${targets[@]}" | xargs -P "$jobs" -I{} bash -c 'audit "$1"' _ {} &
  watch_until $!
  summarize &
  watch_until $!
  date +%s >"$OUT/run.end"
  log "run $RUN finished"

  summary=$(ls "$OUT"/summary-2???-??-??.md 2>/dev/null || true)
  [ -z "$summary" ] || append_run_stats "$summary"
  failed=$(failed_targets) || true
  print_result "$summary" "$failed"
}

main "$@"
