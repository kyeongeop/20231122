#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_BIN="${GO:-go}"
CLANG_BIN="${CLANG:-clang++}"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"

mkdir -p "$BUILD_DIR"
mkdir -p "$BUILD_DIR/fuzz-corpus"
cd "$ROOT"

CGO_ENABLED=1 \
CC="${CC:-${CLANG_BIN%++}}" \
"$GO_BIN" build -buildmode=c-shared -o "$BUILD_DIR/libpolicy_bridge.so" ./cmd/fuzzbridge

"$CLANG_BIN" \
  -std=c++17 -g -O1 \
  -fsanitize=fuzzer,address,undefined \
  -I"$BUILD_DIR" \
  fuzz/policy_fuzzer.cpp \
  -L"$BUILD_DIR" -lpolicy_bridge \
  -Wl,-rpath,'$ORIGIN' \
  -o "$BUILD_DIR/policy_fuzzer"

exec "$BUILD_DIR/policy_fuzzer" "$BUILD_DIR/fuzz-corpus" "$ROOT/fuzz/corpus" "$@"
