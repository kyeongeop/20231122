#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

./build/auditfix demo --dir "$tmp/demo" --force \
  --harness build/auditfix_harness >"$tmp/demo.log"

grep -q 'run=demo-run status=paused new_attempts=2' "$tmp/demo.log"
grep -q 'run=demo-run status=complete new_attempts=6' "$tmp/demo.log"
grep -q '04-clock-skew-missing.sample.*STABLE' "$tmp/demo.log"
grep -q 'restored run=demo-run case=clock-desync-demo status=complete attempts=9' "$tmp/demo.log"

./build/auditfix verify --bundle "$tmp/demo/bundle" >/dev/null
./build/auditfix verify --bundle "$tmp/demo/bundle" \
  --rerun --harness build/auditfix_harness >/dev/null

./build/auditfix run \
  --db "$tmp/demo/auditfix.sqlite" --case-id clock-desync-demo \
  --run-id demo-run-2 --harness build/auditfix_harness >/dev/null
./build/auditfix compare \
  --db "$tmp/demo/auditfix.sqlite" --left demo-run --right demo-run-2 \
  --json >"$tmp/compare.json"
grep -q '"changed": false' "$tmp/compare.json"

# Real SIGINT: the first child invocation sleeps, the resumed one completes instantly.
signal="$tmp/signal"
mkdir -p "$signal/corpus"
cp "$tmp/demo/corpus/04-clock-skew-missing.sample" "$signal/corpus/"
./build/auditfix case import \
  --db "$signal/state.sqlite" --case-id signal-case \
  --a "$tmp/demo/device-a.jsonl" --b "$tmp/demo/device-b.jsonl" >/dev/null
./build/auditfix sample import \
  --db "$signal/state.sqlite" --case-id signal-case \
  --dir "$signal/corpus" >/dev/null
cat >"$signal/harness" <<'EOF'
#!/usr/bin/env bash
if [[ ! -e "$AUDITFIX_SLEEP_MARKER" ]]; then
  : >"$AUDITFIX_SLEEP_MARKER"
  sleep 30
fi
printf '%s\n' 'AUDITFIX_RESULT {"schema":"auditfix.harness.v1","verdict":"FINDINGS","classification":"MISSING_SEGMENT","chain_ok":true,"anchor_pairs":2,"clock_offset_ns":10000000000,"findings":["MISSING_SEGMENT","CLOCK_SKEW"],"missing_segments":[{"device":"device-a","seq_from":3,"seq_to":4,"count":2}]}'
EOF
chmod +x "$signal/harness"
export AUDITFIX_SLEEP_MARKER="$signal/slept"

set +e
./build/auditfix run \
  --db "$signal/state.sqlite" --case-id signal-case \
  --run-id signal-run --harness "$signal/harness" \
  >"$signal/run.log" 2>"$signal/run.err" &
signal_pid=$!
sleep 1
kill -INT "$signal_pid"
wait "$signal_pid"
signal_status=$?
set -e

if [[ "$signal_status" -ne 130 ]]; then
  echo "expected SIGINT exit 130, got $signal_status" >&2
  cat "$signal/run.err" >&2
  exit 1
fi
grep -q 'status=paused reason=interrupted' "$signal/run.log"

./build/auditfix resume \
  --db "$signal/state.sqlite" --run-id signal-run >"$signal/resume.log"
grep -q 'status=complete' "$signal/resume.log"
./build/auditfix export \
  --db "$signal/state.sqlite" --run-id signal-run \
  --out "$signal/bundle" >/dev/null
grep -q '"status":"interrupted"' "$signal/bundle/attempts.jsonl"
grep -q '"status":"complete"' "$signal/bundle/attempts.jsonl"
./build/auditfix verify --bundle "$signal/bundle" >/dev/null

printf '%s\n' "integration: ok"
