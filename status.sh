#!/usr/bin/env bash
# One snapshot of a harness run: state, time, subagents, tokens, cost and activity per target.
#   status.sh [RUN]   (RUN is a folder under runs/, default: the latest)
# Cost is exact (claude's own total) once a target ends. While it runs, it is an estimate (~)
# from the session transcripts at list price, which misses side calls like the auto-mode classifier.
# Colors when stdout is a terminal or FORCE_COLOR is set; NO_COLOR turns them off.
set -o pipefail
shopt -s nullglob

HERE=$(cd "$(dirname "$0")" && pwd)
RUN=${1:-$(ls -t "$HERE/runs" 2>/dev/null | head -1)}
[ -n "$RUN" ] || { echo "no runs yet in $HERE/runs" >&2; exit 1; }
OUT="$HERE/runs/$RUN"
[ -f "$OUT/targets" ] || { echo "no run at $OUT" >&2; exit 1; }

# On a terminal, the last column gets the width left after the 82 columns before it.
if [ -n "${FORCE_COLOR:-}" ] || { [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; }; then
  B=$'\033[1m' D=$'\033[2m' R=$'\033[31m' G=$'\033[32m' Y=$'\033[33m' C=$'\033[36m' X=$'\033[0m'
  width=$(( ${COLUMNS:-$(tput cols 2>/dev/null || echo 160)} - 82 ))
  [ "$width" -lt 20 ] && width=20
else
  B="" D="" R="" G="" Y="" C="" X="" width=1000
fi

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
  | "\(.name) \(.input.description // .input.pattern // .input.file_path // .input.command // ""
    | tostring | gsub("\n"; " ") | sub("^.*/sec-audit-[^/]+/"; ""))"'

human() { awk -v n="$1" 'BEGIN { if (n >= 1e6) printf "%.1fM", n / 1e6; else if (n >= 1e3) printf "%.0fk", n / 1e3; else if (n > 0) printf "%d", n }'; }
clock() { printf '%d:%02d' $(($1 / 60)) $(($1 % 60)); }
since() { echo $(( $(cat "$2" 2>/dev/null || date +%s) - $(cat "$1") )); }

# Sets icon and color for a state, and counts it.
classify_state() {
  case $1 in
    done) icon="✓" color=$G n_done=$((n_done + 1)) ;;
    failed) icon="✗" color=$R n_failed=$((n_failed + 1)) ;;
    running) icon="●" color=$Y n_running=$((n_running + 1)) ;;
    *) icon="○" color=$D n_waiting=$((n_waiting + 1)) ;;
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
# its last tool call.
describe() {
  local target=$1 state=$2 reports tool
  info="" info_color=$D
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
    return
  fi
  [ -f "$OUT/$target.session" ] || return
  info=$(tail -n 200 "$OUT/$target.jsonl" | grep '"type":"assistant"' | jq -r "$LAST_TOOL" 2>/dev/null | tail -1)
  # A tool call is cut from the left, keeping the tool name and the end of its path or pattern.
  if [ "$state" = running ] && [ ${#info} -gt "$width" ]; then
    tool=${info%% *}
    info="$tool …${info: -$((width - ${#tool} - 2))}"
  fi
}

# Prints the run's elapsed time, total cost, and a progress bar with counts per state.
print_header() {
  local finished=$((n_done + n_failed)) bar counts
  bar=$(awk -v f="$finished" -v n="$n" 'BEGIN { w = 24; k = n ? int(w * f / n) : 0
    for (i = 0; i < w; i++) printf (i < k ? "█" : "░") }')
  counts="${G}✓ $n_done done$X"
  [ "$n_running" -gt 0 ] && counts="$counts  ${Y}● $n_running running$X"
  [ "$n_failed" -gt 0 ] && counts="$counts  ${R}✗ $n_failed failed$X"
  [ "$n_waiting" -gt 0 ] && counts="$counts  ${D}○ $n_waiting waiting$X"
  printf "${B}Security audit %s$X  ${D}%s elapsed · %s$X  ${B}total %s\$%.2f$X\n" \
    "$RUN" "$(clock "$(since "$OUT/run.start" "$OUT/run.end" 2>/dev/null || echo 0)")" "$(date +%T)" "$approx" "$total"
  printf "$G%s$X %d/%d  %s\n\n" "$bar" "$finished" "$n" "$counts"
}

# Prints the last events, colored by kind: + done, ! failed, > started.
print_events() {
  tail -n 8 "$OUT/events.log" 2>/dev/null | while IFS= read -r line; do
    case ${line:9:1} in "+") c=$G ;; "!") c=$R ;; ">") c=$C ;; *) c=$D ;; esac
    printf "$D%s$X $c%s$X\n" "${line:0:8}" "${line:9}"
  done
}

rows="" total=0 approx="" n=0 n_done=0 n_failed=0 n_running=0 n_waiting=0
for target in $(cat "$OUT/targets") $([ -f "$OUT/summary.state" ] && echo summary); do
  state=$(cat "$OUT/$target.state" 2>/dev/null || echo pending)
  agents="" tin=0 tout=0 cost="" cost_color=""
  n=$((n + 1))
  classify_state "$state"
  time=$(run_time "$target" "$state")
  [ -f "$OUT/$target.session" ] && read_session "$target"
  describe "$target" "$state"
  rows+=$(printf "%-28s $color%s %-8s$X %7s %6s %7s %6s $cost_color%9s$X  $info_color%s$X" \
    "$target" "$icon" "$state" "$time" "$agents" "$(human "$tin")" "$(human "$tout")" "$cost" "${info:0:$width}")$'\n'
done

print_header
printf "$D%-28s   %-8s %7s %6s %7s %6s %9s  %s$X\n" TARGET STATE TIME AGENTS IN OUT COST 'FINDINGS / LAST TOOL'
printf '%s' "$rows"
echo
print_events
