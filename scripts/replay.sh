#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="${FUZZ_BIN:-$root/artifacts/bin/pathnorm_fuzz}"
artifact="${1:-$root/artifacts/corpus/recovered/minimized-01}"
prefix="$root/artifacts/replays"

if [[ ! -x "$bin" ]]; then
  printf 'missing libFuzzer binary: %s\nrun scripts/build_fuzz.sh first\n' "$bin" >&2
  exit 2
fi

mkdir -p "$prefix"
set +e
"$bin" -runs=1 -artifact_prefix="$prefix/" "$artifact" >"$prefix/replay.stdout" 2>"$prefix/replay.stderr"
code=$?
set -e

if grep -q 'PATH_CANON_DIVERGENCE' "$prefix/replay.stderr"; then
  printf 'canonicalization divergence reproduced from %s (libFuzzer exit %d)\n' "$artifact" "$code"
  sed -n '1,20p' "$prefix/replay.stderr"
  exit 0
fi

printf 'replay finished without the expected differential (exit %d)\n' "$code" >&2
exit "$code"
