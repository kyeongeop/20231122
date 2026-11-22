#!/usr/bin/env bash
# 构建 Go + libFuzzer 混合 fuzz 目标。
# 产物：fuzz/out/fuzz_audit（libFuzzer 可执行文件）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/fuzz/out"
mkdir -p "$OUT"

export GOTOOLCHAIN=local
export CGO_ENABLED=1

echo ">> 1) go build -buildmode=c-archive"
(
  cd "$ROOT"
  go build -tags cgofuzz -buildmode=c-archive \
    -o "$OUT/libfuzzaudit.a" ./fuzz/libfuzzer
)

echo ">> 2) clang link with libFuzzer"
# 空 C 单元：LLVMFuzzerTestOneInput 已在 Go 侧通过 cgo 定义。
	printf '#include <stddef.h>\n#include <stdint.h>\n' > "$OUT/stub.c"

clang -fsanitize=fuzzer,address \
  "$OUT/stub.c" \
  "$OUT/libfuzzaudit.a" \
  -o "$OUT/fuzz_audit" \
  -lpthread -ldl -lm

echo ">> built $OUT/fuzz_audit"
