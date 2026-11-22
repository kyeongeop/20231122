#!/usr/bin/env bash
# End-to-end, re-runnable demonstration of the auditable review pipeline.
# Produces a fresh evidence DB each run under build/demo/ and prints the
# mapping: attack input -> trigger site -> permission -> log evidence,
# including a truncated record, its recovery, and a deterministic replay.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
source ./env.sh

# Fresh, timestamped work dir so repeated runs never reuse a stale DB with an
# older schema; every run is independently reproducible.
WORK="build/demo-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$WORK"
DB="$WORK/evidence.db"
BATCH="BATCH-2026-1122"

echo "############ 1. build CLI ############"
go build -o "$WORK/riskflow" ./cmd/riskflow

echo "############ 2. generate v1/v2 + truncated batches ############"
"$WORK/riskflow" generate --out "$WORK/data"

echo "############ 3. ingest the TRUNCATED v2 batch (truncation = evidence) ############"
"$WORK/riskflow" ingest --db "$DB" --batch "$BATCH" \
  --file "$WORK/data/batch_v2_truncated.frames"

echo "############ 4. recover the cut-off final record ############"
"$WORK/riskflow" recover --db "$DB" --batch "$BATCH" \
  --file "$WORK/data/recovered_fragment.frames"

echo "############ 5. replay from SQLite and diff every transition ############"
"$WORK/riskflow" replay --db "$DB" --batch "$BATCH"

echo "############ 6. evidence mapping for the recovered record ############"
"$WORK/riskflow" evidence --db "$DB" --batch "$BATCH" --record R-1004

echo "############ 7. legacy v1 batch for backward-compat check ############"
"$WORK/riskflow" ingest --db "$DB" --batch "BATCH-V1" \
  --file "$WORK/data/batch_v1.jsonl"
"$WORK/riskflow" replay --db "$DB" --batch "BATCH-V1"

echo
echo "DEMO OK. Evidence database: $DB"
echo "Inspect directly:  sqlite3 '$DB' '.tables'   (or any SQLite client)"
