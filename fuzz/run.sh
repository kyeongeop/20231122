#!/usr/bin/env bash
# Runs the hardened libFuzzer target against a seed corpus copied from the
# preserved audit inputs, then writes any findings into evidence/crashers.
set -euo pipefail

cd "$(dirname "$0")"
SECONDS_TO_RUN="${FUZZ_SECONDS:-60}"
SEED_DIR="seed_corpus"

mkdir -p "$SEED_DIR" ../evidence/crashers
cp -f ../evidence/corpus/CASE-*.bin "$SEED_DIR"/ 2>/dev/null || true

./parser_fuzz_hardened "$SEED_DIR" \
	-max_total_time="$SECONDS_TO_RUN" \
	-artifact_prefix=../evidence/crashers/ \
	-print_final_stats=1
