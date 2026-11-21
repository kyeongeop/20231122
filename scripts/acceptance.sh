#!/usr/bin/env bash
# End-to-end acceptance: pause/resume, deterministic comparison, degradation,
# SQLite evidence, libFuzzer bridge, and independent export verification.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v go >/dev/null 2>&1; then
  for candidate in "$HOME/.local/go/bin" "$HOME/sdk/go/bin" "$HOME/go/bin"; do
    if [ -x "$candidate/go" ]; then
      export PATH="$candidate:$PATH"
      break
    fi
  done
fi
command -v go >/dev/null 2>&1 || {
  echo "Go toolchain not found; set GO or add go to PATH" >&2
  exit 1
}

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK=${WORK:-artifacts/acceptance-$STAMP}
DB=$WORK/state.db
BIN=$WORK/corpusctl
CORPUS=testdata/corpus
mkdir -p "$WORK"

echo "== build and unit tests =="
go test ./...
go build -o "$BIN" ./cmd/corpusctl

echo "== baseline =="
"$BIN" run --db "$DB" --corpus "$CORPUS" --run-id baseline

echo "== paused/resumed run =="
while true; do
  code=0
  "$BIN" run --db "$DB" --corpus "$CORPUS" --run-id resumed \
    --pause-after 2 >"$WORK/resume.json" || code=$?
  if [ "$code" -eq 3 ]; then
    echo "  paused after two records"
    continue
  fi
  [ "$code" -eq 0 ] || exit "$code"
  break
done
cat "$WORK/resume.json"

echo "== compare uninterrupted and resumed results =="
"$BIN" compare --db "$DB" --a baseline --b resumed

echo "== low-resource degradation =="
"$BIN" run --db "$DB" --corpus "$CORPUS" --run-id degraded \
  --mem-budget 1 --export "$WORK/export-degraded"

echo "== export resumed evidence =="
"$BIN" export --db "$DB" --run-id resumed --out "$WORK/export-resumed" >/dev/null

echo "== independent export verification (no SQLite) =="
"$BIN" verify-export --dir "$WORK/export-resumed"
"$BIN" verify-export --dir "$WORK/export-degraded"

echo "== SQLite key evidence =="
python3 - "$DB" <<'PY'
import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
for run in ("resumed", "degraded"):
    status, cursor = db.execute(
        "select status, cursor from runs where run_id=?", (run,)).fetchone()
    records = db.execute(
        "select count(*) from results where run_id=?", (run,)).fetchone()[0]
    comps = [json.loads(row[0]) for row in db.execute(
        "select comparison_json from comparisons where run_id=? order by seq", (run,))]
    events = [json.loads(row[0])["kind"] for row in db.execute(
        "select event_json from events where run_id=? order by seq", (run,))]
    print(f"{run}: status={status} cursor={cursor} records={records}")
    print(f"  comparisons={[(c['phase'], c['match']) for c in comps]}")
    print(f"  events={events}")
    assert status in ("completed", "completed_degraded")
    assert records == cursor
    assert comps and all(c["match"] for c in comps)
    if run == "resumed":
        assert "resume" in events
    if run == "degraded":
        assert "resource_degraded" in events
PY

echo "== libFuzzer bridge =="
if [ "${SKIP_FUZZ:-0}" != "1" ]; then
  (cd fuzz && mkdir -p build && go build -buildmode=c-archive \
    -o build/libcorpusprobe.a ./bridge)
  if command -v clang++ >/dev/null 2>&1; then
    (cd fuzz && ./build.sh)
    echo "  c-archive/libFuzzer target linked"
  else
    echo "  Go c-archive verified; clang++ unavailable, skipped libFuzzer link"
  fi
else
  echo "  skipped"
fi

echo "ACCEPTANCE_OK work=$WORK ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
