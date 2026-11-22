#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/build/fuzz/taintlab_fuzz"
if [[ ! -x "${BIN}" ]]; then
  "${ROOT}/fuzz/build.sh"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/taintlab-fuzz-corpus.XXXXXX")"
ARTIFACTS="${ROOT}/build/fuzz/artifacts"
mkdir -p "${ARTIFACTS}"
cp -a "${ROOT}/fuzz/corpus/." "${WORK}/"

"${BIN}" \
  -max_len=131072 \
  -timeout=10 \
  -rss_limit_mb=2048 \
  -artifact_prefix="${ARTIFACTS}/" \
  "${WORK}" "$@"
STATUS=$?

find "${WORK}" -type f -delete
rmdir "${WORK}"
exit "${STATUS}"

