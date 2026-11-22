#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compiler="${CACHELEAK_CLANGXX:-clang++}"
output="${1:-$here/cache_key_fuzzer}"

"$compiler" -std=c++17 -O1 -g -fsanitize=fuzzer,address \
  -fno-omit-frame-pointer "$here/cache_key_fuzzer.cpp" -o "$output"
echo "$output"
