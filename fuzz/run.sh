#!/usr/bin/env bash
# 运行已构建的 libFuzzer 目标。默认 20000 轮，可用 RUNS 覆盖。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="${RUNS:-20000}"

export LD_LIBRARY_PATH="${LLVM_LIB:-$HOME/toolchains/root/usr/lib/llvm-21/lib}:${LD_LIBRARY_PATH:-}"

mkdir -p "$ROOT/fuzz/corpus"
"$ROOT/fuzz/out/fuzz_audit" "$ROOT/fuzz/corpus" \
  -max_len=256 -runs="$RUNS" -print_final_stats=1 \
  -artifact_prefix="$ROOT/fuzz/out/"
