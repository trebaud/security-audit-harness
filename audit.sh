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
    die "run $RUN is already in progress (pid $(cat "$OUT/run.pid"))"
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

# Deletes branch $1 when it has no worktree and no commits past the base branch. An interrupted
# `mori new` leaves such a branch behind, and `mori new` then refuses to reuse its name.
drop_orphan_branch() {
  git rev-parse --verify --quiet "refs/heads/$1" >/dev/null || return 0
  git merge-base --is-ancestor "$1" "$(base_branch)" || return 0
  git branch -D "$1" >/dev/null 2>&1 || true
}

# Prints the worktree of sec-audit-<ID>-<name>, creating it first if needed.
worktree_path() {
  local name=$1 branch="sec-audit-$ID-$1"
  if ! mori path "$branch" >/dev/null 2>&1; then
    set_state "$name" setup
    log "  $name creating worktree"
    drop_orphan_branch "$branch"
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

summary_prompt() {
  cat <<'EOF'
Merge the per-target security audit reports below into one report. Do not re-audit, and do not
change code or tests. The only file you write is the summary.

Each report was written by /security-audit: every finding was traced input to sink, rated by an
adversarial critic, and Critical/High ones carry a confirming test.

1. Read every report.
2. Merge duplicates. Findings with the same root cause (same sink, same missing check) reported by
   more than one target are one finding: keep the highest severity, list every target that found it.
3. Look for chains across targets: a finding in one target gives the attacker a value or a state
   that a finding in another target needs. Confirm it by reading the cited code in this worktree.
   Most findings do not chain; do not invent one. A confirmed chain may rank above its parts.
4. Keep each finding's severity unless step 2 or 3 changes it, and say what changed it.

Report format:

- First line: the verdict, counts per severity after merging, e.g.
  `🔴 1 Critical · 🟠 3 High · 🟡 5 Medium · ⚪ 4 Low`, or `No findings.`
- `## Findings`: one table, most severe first, columns severity, claim, `file:line`, targets,
  confirming test (Critical/High only).
- `## Critical and High`: per finding, impact, source -> sink and fix in at most 5 lines, then a
  link to the per-target report for the full write-up and repro. Link by bare file name
  (`[carts](carts-2026-10-16.md)`); the summary will sit next to the reports.
- `## Chains`: confirmed chains only.
- `## Not covered`: the targets without a report, listed below.

Never print an empty section. No methodology narration.
EOF
}

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
  prompt="$(summary_prompt)

Reports: .security-audit/$ID/
Targets without a report:${missing:- none}
Write the summary to .security-audit/summary-$(date +%F).md"
  run_claude summary "$dir" "$prompt"
}

# ---- Dashboard ------------------------------------------------------------------------------------

color="" B="" C="" D="" G="" R="" Y="" X=""
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  color=1 B=$'\033[1m' C=$'\033[36m' D=$'\033[2m' G=$'\033[32m' R=$'\033[31m' Y=$'\033[33m' X=$'\033[0m'
fi

short() { local tilde='~'; echo "${1/#$HOME/$tilde}"; }

# $/MTok input, output, cache read; cache writes bill 1.25x input (5m TTL) or 2x (1h TTL).
# A message is logged once per content block, so keep the last copy per message id.
TOKEN_USAGE='
  def price: if test("fable") then [10, 50, 0.25] elif test("sonnet") then [2, 10, 0.20]
    elif test("haiku") then [0.10, 0.50, 0.01] else [4, 20, 0.20] end;
  reduce (inputs | .message) as $m ({}; .[$m.id] = $m)
  | [.[] | (.model | price) as [$i, $o, $r] | .usage as $u
     | [ ($u.input_tokens // 0) + ($u.cache_read_input_tokens // 0) + ($u.cache_creation_input_tokens // 0),
         ($u.output_tokens // 0),
         ( ($u.input_tokens // 0) * $i + ($u.output_tokens // 0) * $o + ($u.cache_read_input_tokens // 0) * $r
         + ($u.cache_creation.ephemeral_5m_input_tokens // 0) * $i * 1.25
         + ($u.cache_creation.ephemeral_1h_input_tokens // $u.cache_creation_input_tokens // 0) * $i * 2 ) / 1e6 ]]
  | (if length == 0 then [[0, 0, 0]] else . end) | transpose | map(add) | "\(.[0]) \(.[1]) \(.[2])"'

LAST_TOOL='.message.content[]? | select(.type == "tool_use")
  | "\(.name) › \(.input.description // .input.pattern // .input.file_path // .input.command // ""
    | tostring | gsub("\n"; " ") | sub("^.*/sec-audit-[^/]+/"; ""))"'

human() { awk -v n="$1" 'BEGIN { if (n >= 1e6) printf "%.1fM", n / 1e6; else if (n >= 1e3) printf "%.0fk", n / 1e3; else if (n > 0) printf "%d", n }'; }
clock() { printf '%d:%02d' $(($1 / 60)) $(($1 % 60)); }
since() { echo $(( $(cat "$2" 2>/dev/null || date +%s) - $(cat "$1") )); }

# Sets icon and colors for a state, and counts it. Running targets stand out, waiting ones fade.
classify_state() {
  name_color=""
  case $1 in
    done) icon="✓" state_color=$G n_done=$((n_done + 1)) ;;
    failed) icon="✗" state_color=$R n_failed=$((n_failed + 1)) ;;
    running) icon="●" state_color=$Y name_color=$B n_running=$((n_running + 1)) ;;
    *) icon="○" state_color=$D name_color=$D n_waiting=$((n_waiting + 1)) ;;
  esac
}

# Prints how long a target ran. A start with no end and no running session is an interrupted
# one: don't keep its clock going.
run_time() {
  local target=$1 state=$2
  [ -f "$OUT/$target.start" ] || return
  [ -f "$OUT/$target.end" ] || [ "$state" = running ] || return
  clock "$(since "$OUT/$target.start" "$OUT/$target.end")"
}

# Sets subagents, tokens and cost from a target's claude session, and adds the cost to the total.
read_session() {
  local target=$1 sid est final subagents
  sid=$(cat "$OUT/$target.session")
  subagents=(~/.claude/projects/*/"$sid"/subagents/*.jsonl)
  agents=${#subagents[@]}
  read -r tin tout est < <(cat ~/.claude/projects/*/"$sid".jsonl "${subagents[@]}" /dev/null \
    | grep -h '"type":"assistant"' | jq -rn "$TOKEN_USAGE")
  # A session can emit a result before its background subagents finish; only the last one, once
  # the session has ended, is the total.
  if [ -f "$OUT/$target.end" ]; then
    final=$(grep '"type":"result"' "$OUT/$target.jsonl" 2>/dev/null | tail -1 | jq -r '.total_cost_usd // empty')
  fi
  if [ -n "$final" ]; then
    cost=$(printf '$%.2f' "$final")
  else
    final=$est approx="~" cost_color=$D cost=$(printf '~$%.2f' "$est")
  fi
  total=$(awk -v a="$total" -v b="$final" 'BEGIN { print a + b }')
}

# Sets info to what a target is up to: its failure, its top finding once it has a report, else
# its last tool call; and info_width to the characters that fit in its column.
describe() {
  local target=$1 state=$2 reports tool
  info="" info_color=$D info_width=$width
  if [ "$state" = failed ]; then
    info="see $target.err, $target.jsonl" info_color=$R
    return
  fi
  if [ "$state" = setup ]; then
    info="creating worktree"
    return
  fi
  reports=("$OUT/$target"-2???-??-??.md)
  if [ ${#reports[@]} -gt 0 ]; then
    info=$(grep -m1 -E '🔴|🟠|🟡|⚪|No .*findings' "${reports[${#reports[@]} - 1]}" | sed 's/\*\*//g')
    info=${info:-report written} info_color=""
    # Severity glyphs take two columns each.
    info_width=$((width - $(grep -o -E '🔴|🟠|🟡|⚪' <<<"$info" | wc -l)))
    return
  fi
  [ -f "$OUT/$target.session" ] || return
  info=$(tail -n 200 "$OUT/$target.jsonl" | grep '"type":"assistant"' | jq -r "$LAST_TOOL" 2>/dev/null | tail -1)
  # A tool call is cut from the left, keeping the tool name and the end of its path or pattern.
  if [ "$state" = running ] && [ ${#info} -gt "$width" ]; then
    tool=${info%% *}
    info="$tool › …${info: -$((width - ${#tool} - 4))}"
  fi
}

# Prints the model the sessions run on, as claude resolved it once one has started, else as asked for.
run_model() {
  local transcripts=("$OUT"/*.jsonl) resolved
  [ ${#transcripts[@]} -gt 0 ] && resolved=$(grep -m1 '"subtype":"init"' "${transcripts[0]}" | jq -r '.model // empty')
  echo "${resolved:-${MODEL:-default model}}"
}

# Prints the run's name, elapsed time, total cost, model and effort, and a progress bar that
# fills with done and failed targets only, so it never shows progress before a target finishes.
print_header() {
  local finished=$((n_done + n_failed)) bar counts
  bar=$(awk -v n="$n" -v d="$n_done" -v f="$n_failed" -v G="$G" -v R="$R" -v D="$D" -v X="$X" '
    function seg(k, c, ch,   s, i) { for (i = 0; i < k; i++) s = s ch; return k > 0 ? c s X : "" }
    BEGIN { w = 30; d = n ? int(w * d / n) : 0; f = n ? int(w * f / n) : 0
      printf "%s%s%s", seg(d, G, "━"), seg(f, R, "━"), seg(w - d - f, D, "─") }')
  counts="${G}✓ $n_done done$X"
  [ "$n_running" -gt 0 ] && counts="$counts  ${Y}● $n_running running$X"
  [ "$n_failed" -gt 0 ] && counts="$counts  ${R}✗ $n_failed failed$X"
  [ "$n_waiting" -gt 0 ] && counts="$counts  ${D}○ $n_waiting waiting$X"
  printf "🔐 ${B}Security audit$X  ${C}%s$X   ⏳ %s   💰 ${B}%s\$%.2f$X\n" \
    "$RUN" "$(clock "$(since "$OUT/run.start" "$OUT/run.end" 2>/dev/null || echo 0)")" "$approx" "$total"
  printf "   $D%s · %s effort · %s$X\n" "$(run_model)" "${EFFORT:-default}" "$(date +%T)"
  printf "   %s  ${B}%d/%d$X   %s\n\n" "$bar" "$finished" "$n" "$counts"
}

# Prints the last events, tagged by kind: + done, ! failed, > started, = skipped.
print_events() {
  local line text glyph c
  tail -n 8 "$OUT/events.log" 2>/dev/null | while IFS= read -r line; do
    text=${line:11}
    case ${line:9:1} in
      "+") glyph="✓" c=$G ;;
      "!") glyph="✗" c=$R ;;
      ">") glyph="▸" c=$C ;;
      "=") glyph="✓" c=$D ;;
      " ") glyph="·" c=$D ;;
      *) glyph="·" c=$D text=${line:9} ;;
    esac
    printf "   $D%s$X  $c%s %s$X\n" "${line:0:8}" "$glyph" "$text"
  done
}

# Prints one snapshot of the run: state, time, subagents, tokens, cost and activity per target.
# Cost is exact (claude's own total) once a target ends. While it runs, it is an estimate (~)
# from the session transcripts at list price, which misses side calls like the auto-mode classifier.
# A subshell, so the helpers above can set its variables and rely on nullglob, without errexit
# or nounset.
dashboard() (
  set +eu
  shopt -s nullglob
  names=$(cat "$OUT/targets"; [ -f "$OUT/summary.state" ] && echo summary)
  # The target column fits the longest name.
  name_width=6
  for target in $names; do [ ${#target} -gt "$name_width" ] && name_width=${#target}; done
  # On a terminal, the last column gets the width left after the columns before it, and the rule
  # under the column names spans the screen.
  width=1000 rule_width=$((name_width + 57))
  if [ -n "$color" ]; then
    width=$(( ${COLUMNS:-$(tput cols 2>/dev/null || echo 160)} - name_width - 52 ))
    [ "$width" -lt 20 ] && width=20
    rule_width=$((name_width + 49 + width))
  else
    B="" C="" D="" G="" R="" Y="" X=""
  fi

  rows="" total=0 approx="" n=0 n_done=0 n_failed=0 n_running=0 n_waiting=0
  for target in $names; do
    state=$(cat "$OUT/$target.state" 2>/dev/null || echo pending)
    agents="" tin=0 tout=0 cost="" cost_color=""
    n=$((n + 1))
    classify_state "$state"
    time=$(run_time "$target" "$state")
    [ -f "$OUT/$target.session" ] && read_session "$target"
    describe "$target" "$state"
    [ ${#info} -gt "$info_width" ] && info="${info:0:$((info_width - 1))}…"
    rows+=$(printf " $state_color%s$X $name_color%-*s$X  $state_color%-8s$X %6s %6s %6s %6s $cost_color%8s$X  $info_color%s$X" \
      "$icon" "$name_width" "$target" "$state" "$time" "$agents" "$(human "$tin")" "$(human "$tout")" "$cost" "$info")$'\n'
  done

  print_header
  printf "   $D%-*s  %-8s %6s %6s %6s %6s %8s  %s$X\n" "$name_width" TARGET STATE TIME AGENTS IN OUT COST ACTIVITY
  printf "   $D%s$X\n" "$(printf '%*s' "$rule_width" '' | sed 's/ /─/g')"
  printf '%s' "$rows"
  echo
  print_events
)

# Shows the dashboard until process $1 exits. On a terminal, redraws in place (home, overwrite,
# clear the rest) instead of clearing first, which avoids flicker; otherwise prints a snapshot
# every REFRESH.
watch_until() {
  local pid=$1 screen
  local hint="   ${D}Ctrl-C stops every audit · logs: $(short "$OUT")/$X"
  while kill -0 "$pid" 2>/dev/null; do
    screen=$(dashboard) || true
    if [ -t 1 ]; then
      printf '\033[H%s\033[K\n\n%s\033[K\033[J' "${screen//$'\n'/$'\033[K\n'}" "$hint"
    else
      printf '%s\n\n' "$screen"
    fi
    sleep "${REFRESH:-2}" & wait $! || true
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
  { printf '\n## Run stats\n\n```\n'; color="" dashboard | awk 'NF == 0 { n++ } n < 2'; printf '```\n'; } >>"$1"
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
    echo "📄 ${B}${G}Summary${X}       $(short "$summary")"
  else
    echo "❌ ${B}${R}No summary${X}    see $(short "$OUT")/events.log"
  fi
  if [ -n "$failed" ]; then
    echo "🔁 ${B}${Y}Retry failed${X}  $(short "$HERE")/$(basename "$0") -r $(short "$repo") -i $ID${MODEL:+ -m $MODEL}${EFFORT:+ -e $EFFORT} -t $failed"
  fi
  echo "🧹 ${D}Clean up      worktrees keep the tests the audits wrote; remove them with:"
  echo "                 cd $(short "$repo") && mori list --json | jq -r '.[].branch | select(startswith(\"sec-audit-$ID-\"))' | xargs -I{} mori rm {} -f$X"
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
