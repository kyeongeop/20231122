#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"
cd "$ROOT"

mkdir -p .build
"$GO" build -buildmode=c-archive \
	-tags=libfuzzer \
	-gcflags=all=-d=libfuzzer \
	-o .build/depth-fuzzer.a \
	./fuzz/libfuzzer

"$CLANG" -fsanitize=fuzzer \
	-o .build/depth-fuzzer \
	.build/depth-fuzzer.a \
	-lpthread -ldl -lm

echo "built $ROOT/.build/depth-fuzzer"
