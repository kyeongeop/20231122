#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLANG="${CLANG:-clang++}"
BUILD_DIR="$ROOT/fuzz/build"
ARTIFACT_DIR="$ROOT/fuzz/artifacts"

mkdir -p "$BUILD_DIR" "$ARTIFACT_DIR"
mkdir -p "$BUILD_DIR/corpus"
cp -n "$ROOT"/fuzz/corpus/* "$BUILD_DIR/corpus/"

"$CLANG" \
  -std=c++17 \
  -g -O1 \
  -fsanitize=fuzzer,address \
  -fno-omit-frame-pointer \
  "$ROOT/fuzz/log_injection_fuzz.cc" \
  -o "$BUILD_DIR/log_injection_fuzzer"

"$BUILD_DIR/log_injection_fuzzer" \
  -max_len=4096 \
  -timeout=2 \
  -max_total_time="${FUZZ_SECONDS:-30}" \
  -dict="$ROOT/fuzz/log_injection.dict" \
  -artifact_prefix="$ARTIFACT_DIR/" \
  "$@" \
  "$BUILD_DIR/corpus"
