#!/usr/bin/env bash
# Build the libFuzzer target that drives the Go pipeline.
# Requires: source ./env.sh first (Go 1.24 + clang-18 with libclang_rt.fuzzer).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/fuzz/build"
mkdir -p "$OUT"

echo ">> building Go c-archive (CGO, pure-Go SQLite, no system libsqlite3 needed)"
(
  cd "$ROOT"
  CGO_ENABLED=1 go build -buildmode=c-archive -o "$OUT/libbridge.a" ./internal/fuzz
)

# go build emits the C header next to the archive; expose it as bridge.h.
cp "$OUT/libbridge.h" "$OUT/bridge.h"

echo ">> compiling + linking libFuzzer harness"
CLANG="${CLANG:-clang}"
"$CLANG" \
  -fsanitize=fuzzer \
  -g -O1 \
  -I"$OUT" \
  "$ROOT/fuzz/harness/fuzz_harness.c" \
  "$OUT/libbridge.a" \
  -lpthread -ldl -lm \
  -o "$OUT/riskflow_fuzz"

echo ">> built $OUT/riskflow_fuzz"
