#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SECONDS_TO_RUN="${1:-10}"
"$ROOT/scripts/build_fuzzer.sh"

FUZZ_DIR="$ROOT/artifacts/fuzz"
rm -f "$FUZZ_DIR"/crash-* "$FUZZ_DIR"/timeout-* "$FUZZ_DIR"/oom-* "$FUZZ_DIR"/leak-*
rm -f "$FUZZ_DIR/failure-input.bin" "$FUZZ_DIR/failure.json" "$FUZZ_DIR/failure.db"

COMMAND=(
  "$FUZZ_DIR/pathalias_fuzzer"
  "-max_total_time=$SECONDS_TO_RUN"
  "-timeout=5"
  "-rss_limit_mb=2048"
  "-max_len=64"
  "-print_final_stats=1"
  "-artifact_prefix=$FUZZ_DIR/"
  "$FUZZ_DIR/corpus"
)
printf '%q ' "${COMMAND[@]}" > "$FUZZ_DIR/command.txt"
printf '\n' >> "$FUZZ_DIR/command.txt"

set +e
"${COMMAND[@]}" > "$FUZZ_DIR/fuzz.log" 2>&1
EXIT_CODE=$?
set -e

if [[ "$EXIT_CODE" -eq 0 ]] && ! compgen -G "$FUZZ_DIR/crash-*" >/dev/null &&
   ! compgen -G "$FUZZ_DIR/timeout-*" >/dev/null &&
   ! compgen -G "$FUZZ_DIR/oom-*" >/dev/null &&
   ! compgen -G "$FUZZ_DIR/leak-*" >/dev/null; then
  STATUS=passed
else
  STATUS=failed
fi

{
  echo "$STATUS"
  echo "exit_code=$EXIT_CODE"
  date -u +"finished_at_utc=%Y-%m-%dT%H:%M:%SZ"
  echo "max_total_time_seconds=$SECONDS_TO_RUN"
} > "$FUZZ_DIR/status.txt"

tail -20 "$FUZZ_DIR/fuzz.log"
echo "libFuzzer status=$STATUS exit=$EXIT_CODE"
[[ "$STATUS" == "passed" ]]
