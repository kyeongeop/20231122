#!/usr/bin/env bash
# Run libFuzzer against the checked-in corpus for a bounded time.
set -euo pipefail
cd "$(dirname "$0")"

SECONDS_TO_RUN=${SECONDS_TO_RUN:-30}
./build.sh
mkdir -p build/corpus
./build/corpus_fuzz \
  -max_total_time="$SECONDS_TO_RUN" \
  -artifact_prefix=build/ \
  -print_final_stats=1 \
  build/corpus ../testdata/corpus
