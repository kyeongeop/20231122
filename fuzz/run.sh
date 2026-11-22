#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="${1:-$here/.run}"
mkdir -p "$work/corpus" "$work/artifacts"
printf 'Bq7x\000' >"$work/corpus/seed-q7x.bin"
"$here/build.sh" "$work/cache_key_fuzzer"
set +e
"$work/cache_key_fuzzer" -runs="${FUZZ_RUNS:-2000}" -timeout=10 \
  -rss_limit_mb=512 -detect_leaks=0 \
  -artifact_prefix="$work/artifacts/" "$work/corpus" \
  >"$work/libfuzzer.log" 2>&1
status=$?
set -e
echo "libFuzzer exit status: $status"
find "$work/artifacts" -maxdepth 1 -type f -printf '%f\n' | sort
exit 0
