#!/usr/bin/env bash
# Runs the bundled security-audit skill (skills/, loaded as a plugin) once per target, each in its
# own mori worktree (sec-audit-<day>-<target>),
# then merges every report into one summary in a separate worktree (sec-audit-<day>-summary),
# with a live dashboard of state, subagents, tokens, cost and findings. See README.md.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)

usage() {
  cat <<EOF
Usage: $(basename "$0") (-t <target,target,...> | -f <file>) [-r <repo>] [-j <jobs>] [-d <day>]

  -t, --targets       comma-separated targets to audit, e.g. carts,refunds,b2b-api
  -f, --targets-file  file with one target per line; blank lines and # comments are skipped
  -r, --repo          git repo to audit (default: the repo of the current directory)
  -j, --jobs          audits run in parallel (default: 4)
  -d, --day           run day, YYYYMMDD (default: today); pass an earlier one to resume that run
  -h, --help          show this help

-t and -f can be combined; at least one target is required.

Env: NO_COLOR=1 turns colors off, REFRESH=<seconds> sets the dashboard refresh.
EOF
}
die() { echo "error: $*" >&2; echo "run $(basename "$0") -h for usage" >&2; exit 1; }

targets="" targets_file="" repo="" jobs=4 day=$(date +%Y%m%d)
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help) usage; exit 0 ;;
    -t | --targets | -f | --targets-file | -r | --repo | -j | --jobs | -d | --day)
      [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"
      case $1 in
        -t | --targets) targets=$2 ;;
        -f | --targets-file) targets_file=$2 ;;
        -r | --repo) repo=$2 ;;
        -j | --jobs) jobs=$2 ;;
        -d | --day) day=$2 ;;
      esac
      shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [ -n "$targets_file" ]; then
  [ -f "$targets_file" ] || die "targets file $targets_file not found"
  targets="$targets,$(grep -v '^[[:space:]]*#' "$targets_file" | paste -sd, -)"
fi
# Split on commas, trim spaces, drop empty items and duplicates.
targets=$(echo "$targets" | tr ',' '\n' | tr -d ' \t' | grep -v '^$' | awk '!seen[$0]++' || true)
[ -n "$targets" ] || die "no targets: pass -t target1,target2 or -f <file>"
for t in $targets; do
  # The skill names its report after the target, so keep targets already in slug form.
  [[ $t =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "invalid target '$t': use names like auth or b2b-api (lowercase letters, digits, -), not paths"
  [ "$t" != summary ] || die "'summary' is reserved for the merge step"
done
[[ $jobs =~ ^[1-9][0-9]*$ ]] || die "--jobs must be a positive integer, got '$jobs'"
[[ $day =~ ^[0-9]{8}$ ]] || die "--day must be YYYYMMDD, got '$day'"

for cmd in git mori claude jq uuidgen; do
  command -v "$cmd" >/dev/null || die "$cmd not found on PATH"
done
if [ -n "$repo" ]; then
  [ -d "$repo" ] || die "repo $repo does not exist"
  root=$(git -C "$repo" rev-parse --show-toplevel 2>/dev/null) || die "$repo is not a git repo"
  repo=$root
else
  repo=$(git rev-parse --show-toplevel 2>/dev/null) || die "not inside a git repo: pass -r <repo>"
fi
cd "$repo"

export DAY=$day HERE
export OUT="$HERE/runs/$(basename "$repo")-$DAY"
RUN=$(basename "$OUT")
mkdir -p "$OUT"
if [ -f "$OUT/run.pid" ] && kill -0 "$(cat "$OUT/run.pid")" 2>/dev/null; then
  die "run $RUN is already in progress (pid $(cat "$OUT/run.pid")); watch it with $HERE/status.sh $RUN"
fi
echo $$ >"$OUT/run.pid"
rm -f "$OUT"/summary.* "$OUT"/summary-2???-??-??.md "$OUT/run.end"
date +%s >"$OUT/run.start"

set -- $targets
# A resumed run with fewer targets keeps the earlier ones on the dashboard and in the summary.
{ cat "$OUT/targets" 2>/dev/null || true; printf '%s\n' "$@"; } | awk '!seen[$0]++' >"$OUT/targets.tmp"
mv "$OUT/targets.tmp" "$OUT/targets"

log() { echo "$(date +%T) $*" >>"$OUT/events.log"; }
has_report() { ls "$OUT/$1"-2???-??-??.md >/dev/null 2>&1; }

# Prints the worktree of sec-audit-<DAY>-<name>, creating it first if needed.
worktree() {
  local b="sec-audit-$DAY-$1"
  if ! mori path "$b" >/dev/null 2>&1; then
    echo setup >"$OUT/$1.state"
    log "  $1 creating worktree"
    if ! mori new "$b" >"$OUT/$1.setup.log" 2>&1; then
      echo failed >"$OUT/$1.state"; log "! $1 worktree creation failed, see $1.setup.log"; return 1
    fi
  fi
  mori path "$b"
}

# Worktrees are created one at a time (concurrent `git worktree add` races on .git locks);
# each target goes to the audit pool as soon as its worktree is ready.
setup() {
  for t in "$@"; do
    if has_report "$t"; then echo done >"$OUT/$t.state"; log "= $t already has a report"; continue; fi
    worktree "$t" >/dev/null || continue
    echo queued >"$OUT/$t.state"
    echo "$t"
  done
}

# Runs claude headless in a worktree with the bundled skill, tracks it under $OUT/<name>.* and
# copies back the report it writes to .security-audit/<name>-<date>.md.
run_claude() {
  local name=$1 dir=$2 prompt=$3 sid code=0 cost
  sid=$(uuidgen | tr '[:upper:]' '[:lower:]')
  echo "$sid" >"$OUT/$name.session"
  date +%s >"$OUT/$name.start"; rm -f "$OUT/$name.end"
  echo running >"$OUT/$name.state"
  log "> $name started (session $sid)"

  (cd "$dir" && claude -p "$prompt" --plugin-dir "$HERE" --session-id "$sid" --permission-mode auto \
    --output-format stream-json --verbose </dev/null) >"$OUT/$name.jsonl" 2>"$OUT/$name.err" || code=$?

  date +%s >"$OUT/$name.end"
  cost=$(grep '"type":"result"' "$OUT/$name.jsonl" | tail -1 | jq -r '.total_cost_usd | "$\(. * 100 | round / 100)"') || true
  if cp "$dir/.security-audit/$name"-2???-??-??.md "$OUT/" 2>/dev/null; then
    echo done >"$OUT/$name.state"; log "+ $name done, ${cost:-cost unknown}"
  else
    echo failed >"$OUT/$name.state"; log "! $name no report (claude exit $code), ${cost:-cost unknown}, see $name.err"
  fi
}

audit() {
  local dir
  dir=$(mori path "sec-audit-$DAY-$1") || { echo failed >"$OUT/$1.state"; log "! $1 worktree missing"; return; }
  run_claude "$1" "$dir" "/security-audit-runner:security-audit $1"
}
export -f log has_report run_claude audit

summarize() {
  local dir missing="" t
  ls "$OUT"/*-2???-??-??.md >/dev/null 2>&1 || { log "! no reports, no summary"; return; }
  dir=$(worktree summary) || return
  rm -rf "$dir/.security-audit/$DAY"; mkdir -p "$dir/.security-audit/$DAY"
  cp "$OUT"/*-2???-??-??.md "$dir/.security-audit/$DAY/"
  for t in $(cat "$OUT/targets"); do has_report "$t" || missing="$missing $t"; done
  run_claude summary "$dir" "$(cat "$HERE/summary-prompt.md")

Reports: .security-audit/$DAY/
Targets without a report:${missing:- none}
Write the summary to .security-audit/summary-$(date +%F).md"
}

color="" B="" D="" G="" R="" Y="" X=""
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  color=1 B=$'\033[1m' D=$'\033[2m' G=$'\033[32m' R=$'\033[31m' Y=$'\033[33m' X=$'\033[0m'
fi
short() { local tilde='~'; echo "${1/#$HOME/$tilde}"; }
hint="${D}Ctrl-C stops every audit · watch from elsewhere: $(short "$HERE")/status.sh $RUN · logs: $(short "$OUT")/$X"

# On a terminal, redraws in place (home, overwrite, clear the rest) instead of clearing first,
# which avoids flicker; otherwise prints a snapshot every REFRESH.
watch_until() {
  local screen
  while kill -0 "$1" 2>/dev/null; do
    screen=$(FORCE_COLOR=$color "$HERE/status.sh" "$RUN") || true
    if [ -t 1 ]; then
      printf '\033[H%s\033[K\n\n%s\033[K\033[J' "${screen//$'\n'/$'\033[K\n'}" "$hint"
    else
      printf '%s\n\n' "$screen"
    fi
    sleep "${REFRESH:-10}" & wait $! || true
  done
  wait "$1" || true
}

stop() { trap - INT TERM EXIT; [ -t 1 ] && tput cnorm; rm -f "$OUT/run.pid"; kill 0; }
trap stop INT TERM
# Exiting on an error must not leave audits running unattended: they would later write into a new run.
trap '[ $? -eq 0 ] && rm -f "$OUT/run.pid" || stop' EXIT
if [ -t 1 ]; then tput civis; printf '\033[2J'; else REFRESH=${REFRESH:-120}; fi
log "run $RUN: $# targets, $jobs parallel, repo $repo"
[ -n "$(git ls-files -- '*THREAT_MODEL.md')" ] \
  || log "! no committed THREAT_MODEL.md: each audit drafts its own (see README)"

setup "$@" | xargs -P "$jobs" -I{} bash -c 'audit "$1"' _ {} &
watch_until $!
summarize &
watch_until $!
date +%s >"$OUT/run.end"
log "run $RUN finished"

summary=$(ls "$OUT"/summary-2???-??-??.md 2>/dev/null || true)
if [ -n "$summary" ]; then
  { printf '\n## Run stats\n\n```\n'; "$HERE/status.sh" "$RUN" | awk 'NF == 0 { n++ } n < 2'; printf '```\n'; } >>"$summary"
fi
failed=$(grep -lx failed "$OUT"/*.state 2>/dev/null | xargs -n1 basename | sed 's/\.state$//' | grep -vx summary | paste -sd, -) || true

[ -t 1 ] && { printf '\033[H\033[2J'; tput cnorm; }
FORCE_COLOR=$color "$HERE/status.sh" "$RUN"
echo
if [ -n "$summary" ]; then
  echo "${B}${G}Summary${X}       $(short "$summary")"
else
  echo "${B}${R}No summary${X}    see $(short "$OUT")/events.log"
fi
[ -n "$failed" ] && echo "${B}${Y}Retry failed${X}  $(short "$HERE")/run.sh -r $(short "$repo") -d $DAY -t $failed"
echo "${D}Clean up      worktrees keep the tests the audits wrote; remove them with:"
echo "              cd $(short "$repo") && mori list --json | jq -r '.[].branch | select(startswith(\"sec-audit-$DAY-\"))' | xargs -I{} mori rm {} -f$X"
