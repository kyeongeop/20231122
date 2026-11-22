#!/usr/bin/env bash
# End-to-end demonstration:
#   1. generate the two-device clock-skew fixture
#   2. run a paused/resumed pipeline (budget-limited segments)
#   3. run an uninterrupted baseline
#   4. exercise the deterministic fault-injection and memory-pressure paths
#   5. export review bundles and prove before/after equivalence
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${OUT:-artifacts/review}"
mkdir -p "$OUT"

echo "== 1. fixture (two devices, clock skew, missing fragment)"
go run ./cmd/replayctl gen-fixture --out "$OUT/fixture.json"

echo "== 2. paused processing: three budget-limited segments"
for _ in 1 2 3; do
  go run ./cmd/replayctl run \
    --input "$OUT/fixture.json" \
    --db "$OUT/paused/evidence.sqlite" \
    --max-events 3
done

echo "== 3. uninterrupted baseline"
go run ./cmd/replayctl run \
  --input "$OUT/fixture.json" \
  --db "$OUT/baseline/evidence.sqlite"

echo "== 4a. deterministic fault injection (pause before segment 2)"
go run ./cmd/replayctl run \
  --input "$OUT/fixture.json" \
  --db "$OUT/fault/evidence.sqlite" --max-events 4
go run ./cmd/replayctl run \
  --input "$OUT/fixture.json" \
  --db "$OUT/fault/evidence.sqlite" --max-events 4 --pause-segment 2
go run ./cmd/replayctl run \
  --input "$OUT/fixture.json" \
  --db "$OUT/fault/evidence.sqlite" --max-events 4
go run ./cmd/replayctl run \
  --input "$OUT/fixture.json" \
  --db "$OUT/fault/evidence.sqlite" --max-events 4

echo "== 4b. memory-pressure degradation path"
go run ./cmd/replayctl run \
  --input "$OUT/fixture.json" \
  --db "$OUT/degraded/evidence.sqlite" --max-issues 1

echo "== 5. export bundles"
for run in paused baseline fault degraded; do
  go run ./cmd/replayctl export \
    --db "$OUT/$run/evidence.sqlite" \
    --out "$OUT/$run/bundle"
done

echo "== 6. independent verification and before/after comparison"
for run in paused baseline fault degraded; do
  go run ./cmd/replayctl verify --bundle "$OUT/$run/bundle"
done
go run ./cmd/replayctl compare \
  --before "$OUT/baseline/bundle" --after "$OUT/paused/bundle"
go run ./cmd/replayctl compare \
  --before "$OUT/baseline/bundle" --after "$OUT/fault/bundle"
go run ./cmd/replayctl compare \
  --before "$OUT/baseline/bundle" --after "$OUT/degraded/bundle"

echo
echo "Demo artifacts written to $OUT"
