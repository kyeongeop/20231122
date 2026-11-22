#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

clangxx="${CLANGXX:-}"
if [[ -z "$clangxx" ]]; then
  for candidate in clang++ clang++-22 clang++-21 clang++-20 clang++-19 clang++-18; do
    if command -v "$candidate" >/dev/null 2>&1; then
      clangxx="$candidate"
      break
    fi
  done
fi
if [[ -z "$clangxx" ]]; then
  echo "clang++ with libFuzzer support is required" >&2
  exit 1
fi
out="${1:-build/apiskew_fuzz}"
mkdir -p "$(dirname "$out")"

"$clangxx" \
  -std=c++17 \
  -O2 \
  -g \
  -fno-omit-frame-pointer \
  -fsanitize=fuzzer,address \
  -o "$out" \
  fuzz/api_diff_fuzzer.cc

echo "$out"
