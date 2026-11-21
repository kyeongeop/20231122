#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
if [[ -z "${CC:-}" ]]; then
  if command -v clang >/dev/null 2>&1; then
    CC=clang
  else
    CC=cc
  fi
fi

if "$CC" -fsanitize=fuzzer -x c -c /dev/null -o /tmp/kz3-fuzzer-probe.o >/dev/null 2>&1; then
  "$CC" -g -O1 -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
    -o kz3_fuzz kz3_fuzz.c
  echo "built kz3_fuzz"
else
  echo "libFuzzer unavailable with $CC; install clang to build kz3_fuzz" >&2
fi

"$CC" -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
  -DSTANDALONE_REPLAY -o kz3_replay kz3_fuzz.c

echo "built kz3_replay"
