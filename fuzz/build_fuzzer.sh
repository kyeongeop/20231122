#!/bin/sh
# Build the libFuzzer binary for the BMB1 decompressor.
# Go compiles the target with libFuzzer coverage instrumentation
# (-gcflags=all=-d=libfuzzer); clang links the libFuzzer runtime.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GO="$HOME/go/bin/go"
CLANG="$HOME/toolchain/LLVM-19.1.1-Linux-X64/bin/clang"

cd "$ROOT"
CGO_ENABLED=1 GOPATH="${GOPATH:-$HOME/gopath}" "$GO" build \
	-buildmode=c-archive \
	-tags libfuzzer \
	-gcflags=all=-d=libfuzzer \
	-o fuzz/libfuzzbomb.a ./fuzz

"$CLANG" -fsanitize=fuzzer -O1 -o fuzz/fuzzbomb \
	fuzz/libfuzzbomb.a -lpthread -ldl -lresolv -lm

echo "built fuzz/fuzzbomb"
