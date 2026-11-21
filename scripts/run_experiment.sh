#!/usr/bin/env bash
# End-to-end replayable protocol state-machine fuzz experiment.
# Stack: Go (state machines + orchestrator) + libFuzzer (clang) + SQLite.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/sdk/go/bin:$PATH"
CLANG="$HOME/sdk/llvm/usr/lib/llvm-21/bin/clang"
ART="$ROOT/artifacts"
CORPUS="$ROOT/exp/corpus"
BUILD="$ROOT/exp/build"

mkdir -p "$ART/crashes" "$CORPUS" "$BUILD"

echo "== seed corpus =="
# valid session
printf '\x01\x00\x02\x03key\x03\x00\x04\x02hi\x05\x00' > "$CORPUS/seed-valid"
# truncated record (control)
printf '\x01\x00\x02\x01k\x04\x05A' > "$CORPUS/seed-truncated"
# send before open
printf '\x04\x01x' > "$CORPUS/seed-send-first"

echo "== build go c-archive =="
cd "$ROOT/exp"
go build -buildmode=c-archive -o "$BUILD/fuzzlib.a" ./fuzzlib

echo "== build libFuzzer harness =="
"$CLANG" -fsanitize=fuzzer -g -O1 \
    "$ROOT/exp/harness/fuzz.c" "$BUILD/fuzzlib.a" \
    -o "$BUILD/fuzzer" -lpthread

echo "== fuzz (libFuzzer, differential v1 vs v2) =="
FUZZ_ARTIFACT_DIR="$ART/crashes" "$BUILD/fuzzer" "$CORPUS" \
    -max_total_time="${FUZZ_SECONDS:-45}" \
    -artifact_prefix="$ART/crashes/" \
    -print_final_stats=1 || true

echo "== record + verify + report =="
go run ./cmd/fuzzexp -artifacts "$ART"

echo "== done; evidence in $ART =="
