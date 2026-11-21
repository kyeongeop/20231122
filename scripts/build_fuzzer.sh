#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -x "$ROOT/.tools/go/bin/go" ]]; then
  GO="$ROOT/.tools/go/bin/go"
else
  GO="${GO:-go}"
fi
if [[ -x "$ROOT/.tools/llvm/usr/bin/clang-19" ]]; then
  CLANG="$ROOT/.tools/llvm/usr/bin/clang-19"
else
  CLANG="${CLANG:-clang}"
fi
LLVM_LIB="$ROOT/.tools/llvm/usr/lib/x86_64-linux-gnu"
if [[ -d "$LLVM_LIB" ]]; then
  export LD_LIBRARY_PATH="$LLVM_LIB:${LD_LIBRARY_PATH:-}"
fi

mkdir -p .build artifacts/fuzz/corpus
if [[ -d fuzz/corpus ]]; then
  cp -f fuzz/corpus/* artifacts/fuzz/corpus/ 2>/dev/null || true
fi

CGO_ENABLED=1 "$GO" build -tags=libfuzzer \
  -gcflags=all=-d=libfuzzer \
  -buildmode=c-archive -o .build/libpathalias.a ./fuzzbridge
"$CLANG" -fsanitize=fuzzer -O1 -g -fno-omit-frame-pointer \
  fuzz/harness.c .build/libpathalias.a \
  -o artifacts/fuzz/pathalias_fuzzer -lpthread -ldl -lm

"$GO" version > artifacts/fuzz/toolchain.txt
"$CLANG" --version | head -1 >> artifacts/fuzz/toolchain.txt
echo "built artifacts/fuzz/pathalias_fuzzer"
