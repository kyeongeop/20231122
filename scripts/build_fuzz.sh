#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cc="${CC:-clang}"
out="${1:-$root/artifacts/bin/pathnorm_fuzz}"
corpus="$root/artifacts/corpus/recovered/minimized-01"

mkdir -p "$(dirname "$out")"
mkdir -p "$(dirname "$corpus")"
base64 --decode "$root/fuzz/corpus/minimized-01.b64" >"$corpus"

expected="fda6c1cc604aef43a126b18a7751ec7c041ba16861ab04a164aefc4e5726e5ac"
actual="$(sha256sum "$corpus" | awk '{print $1}')"
if [[ "$actual" != "$expected" ]]; then
  printf 'corpus hash mismatch: %s\n' "$actual" >&2
  exit 1
fi

"$cc" \
  -O1 \
  -g \
  -fno-omit-frame-pointer \
  -fsanitize=fuzzer,address,undefined \
  -o "$out" \
  "$root/fuzz/pathnorm_fuzz.c"

printf 'built %s\nmaterialized %s\n' "$out" "$corpus"
