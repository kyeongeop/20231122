#!/usr/bin/env bash
# 构建并运行 Go + libFuzzer 模糊测试。
# 用法: scripts/fuzz.sh [runs]   (默认 200000 次)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="${1:-200000}"

# 允许通过环境变量覆盖工具链路径；默认使用仓库约定的本地安装位置。
GO_BIN="${GO_BIN:-$HOME/local/go/bin/go}"
CLANG_BIN="${CLANG_BIN:-$HOME/local/clang-root/usr/bin/clang}"
CLANG_LIB="${CLANG_LIB:-$HOME/local/clang-root/usr/lib/llvm-21/lib}"
RT_DIR="$CLANG_LIB/clang/21/lib/linux"

export CGO_ENABLED=1 CC="$CLANG_BIN"
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
export GOSUMDB="${GOSUMDB:-sum.golang.google.cn}"
export LD_LIBRARY_PATH="$CLANG_LIB:$CLANG_LIB/../x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"

cd "$ROOT"
mkdir -p fuzz/build fuzz/crashers reports

echo "[1/3] go build -buildmode=c-archive"
(cd fuzz && "$GO_BIN" build -buildmode=c-archive -o build/libfuzz.a .)

echo "[2/3] link libFuzzer harness"
"$CLANG_BIN" -fsanitize=fuzzer \
  fuzz/fuzzentry.c \
  fuzz/build/libfuzz.a \
  "$RT_DIR/libclang_rt.fuzzer-x86_64.a" \
  "$RT_DIR/libclang_rt.fuzzer_interceptors-x86_64.a" \
  -lpthread -ldl \
  -o fuzz/build/fuzz.bin

echo "[3/3] run libFuzzer (runs=$RUNS)"
set +e
fuzz/build/fuzz.bin \
  -runs="$RUNS" \
  -max_len=8192 \
  -artifact_prefix=fuzz/crashers/ \
  -print_final_stats=1 \
  fuzz/runtime-corpus fuzz/seed 2>&1 | tee reports/fuzz-summary.txt
STATUS=${PIPESTATUS[0]}
set -e

echo "libFuzzer exit status: $STATUS"
if [ "$STATUS" -ne 0 ]; then
  echo "发现崩溃，崩溃样本已写入 fuzz/crashers/。后续动作:"
  echo "  1) 用 xxd 查看崩溃输入并转成 Envelope 加入 fuzz/seed 回归"
  echo "  2) 修复后重跑本脚本，直到退出码为 0"
  exit "$STATUS"
fi
echo "FUZZ_CLEAN: $RUNS 次执行未发现崩溃"
