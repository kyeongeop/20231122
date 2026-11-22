#!/usr/bin/env bash
# Build the libFuzzer-driven harness against the production Go parser.
#
# Output: fuzz/bin/truncstream_fuzz (a standard libFuzzer binary).
# Requires: Go (cgo, gcc) and clang with libclang_rt.fuzzer available.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLANG_ROOT="${CLANG_ROOT:-$HOME/local/clang-root}"
LLVM_VER="${LLVM_VER:-21}"
RT_DIR="$CLANG_ROOT/usr/lib/llvm-$LLVM_VER/lib/clang/$LLVM_VER/lib/linux"
CLANG="$CLANG_ROOT/usr/lib/llvm-$LLVM_VER/bin/clang"

if [[ ! -x "$CLANG" ]]; then
	echo "clang not found at $CLANG" >&2
	echo "set CLANG_ROOT to a toolchain prefix containing usr/lib/llvm-$LLVM_VER" >&2
	exit 1
fi
if [[ ! -f "$RT_DIR/libclang_rt.fuzzer-x86_64.a" ]]; then
	echo "libFuzzer runtime missing under $RT_DIR" >&2
	echo "install the clang runtime package (e.g. libclang-rt-$LLVM_VER-dev)" >&2
	exit 1
fi

cd "$ROOT"
mkdir -p fuzz/bin fuzz/corpus_libfuzzer

echo ">> building c-archive from fuzz/bridge"
CGO_ENABLED=1 CC=gcc go build -buildmode=c-archive -o fuzz/bin/libbridge.a ./fuzz/cmd/bridge

echo ">> linking libFuzzer harness with $CLANG"
"$CLANG" \
	-fsanitize=fuzzer \
	-I fuzz/bin \
	fuzz/libfuzzer_harness.c \
	fuzz/bin/libbridge.a \
	"$RT_DIR/libclang_rt.fuzzer-x86_64.a" \
	-lpthread -ldl -lm \
	-o fuzz/bin/truncstream_fuzz

echo ">> built fuzz/bin/truncstream_fuzz"
echo ">> run: fuzz/bin/truncstream_fuzz fuzz/corpus_libfuzzer -max_total_time=60"
