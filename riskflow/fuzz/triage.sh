#!/usr/bin/env bash
# Replay a libFuzzer crash artifact through the Go pipeline and correlate the
# attack input with trigger site / permission / log evidence.
#
# Usage: ./fuzz/triage.sh <path-to-crash-artifact>
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <crash-artifact>" >&2
  exit 2
fi

ARTIFACT="$1"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source ./env.sh

if [[ ! -f "$ARTIFACT" ]]; then
  echo "artifact not found: $ARTIFACT" >&2
  exit 1
fi

WORK="build/triage"
mkdir -p "$WORK"
DB="$WORK/triage.db"
BATCH="TRIAGE-$(sha256sum "$ARTIFACT" | cut -c1-12)"

echo "artifact      : $ARTIFACT"
echo "sha256(input) : $(sha256sum "$ARTIFACT" | cut -d' ' -f1)"
echo "raw bytes     : $(od -An -tx1 "$ARTIFACT" | tr -s ' ' | sed 's/^ //')"
echo

go build -o "$WORK/riskflow" ./cmd/riskflow

# A poison/sentinel input crashes the fuzzer before parsing; classify it here
# explicitly so reviewers see why it is a harness-level invariant crash.
if grep -q "POISON_RISKFLOW_INVARIANT" "$ARTIFACT"; then
  echo "classification: HARNESS INVARIANT CRASH (sentinel), not a parser finding"
  echo "the fuzzer captured the exact attack input; no SQLite state was written."
  exit 0
fi

# Otherwise treat the artifact as an ordinary (possibly truncated) batch and
# run it through the same ingest -> evidence pipeline used in production.
"$WORK/riskflow" ingest --db "$DB" --batch "$BATCH" --file "$ARTIFACT" || true
"$WORK/riskflow" replay --db "$DB" --batch "$BATCH" || true
"$WORK/riskflow" evidence --db "$DB" --batch "$BATCH" || true
