#!/usr/bin/env bash
# Builds the libFuzzer binary for the idorfix detection engine.
#
# Pipeline:
#   1. cgo compiles the Go package (including harness.c) into a C archive.
#   2. clang links that archive against the libFuzzer runtime, which supplies
#      main() and the corpus/sanitizer machinery.
#
# Usage:
#   internal/fuzz/build.sh [output_dir]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$ROOT/build/fuzz}"
ARCHIVE="$OUT_DIR/libidorfuzz.a"
HEADER="$OUT_DIR/libidorfuzz.h"
BINARY="$OUT_DIR/idorfix_fuzzer"

mkdir -p "$OUT_DIR"

echo ">> building c-archive with cgo"
(
	cd "$ROOT"
	CGO_ENABLED=1 \
	CC="${CC:-clang-21}" \
	go build -buildmode=c-archive \
		-o "$ARCHIVE" \
		./internal/fuzz/libfuzzer
)

echo ">> linking libFuzzer binary"
"${CC:-clang-21}" \
	-fsanitize=fuzzer,address \
	-I"$OUT_DIR" \
	"$ROOT/internal/fuzz/libfuzzer/harness.c" \
	"$ARCHIVE" \
	-o "$BINARY"

echo ">> built $BINARY"
echo "   run:   $BINARY internal/fuzz/corpus"
echo "   repro: $BINARY <crash-file>"
