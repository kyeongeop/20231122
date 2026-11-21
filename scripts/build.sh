#!/usr/bin/env bash
# Builds the libFuzzer harness in four flavors from one source:
#
#   kr_fuzz_vuln   coverage-guided fuzzer, vulnerable parser
#   kr_fuzz_fixed  coverage-guided fuzzer, localized correction
#   kr_replay_vuln single-file replay (exit 133 = trap / 77 verdict)
#   kr_replay_fixed single-file replay (exit 78 = stale rejected)
#
# Honors CLANG and OUT override; no network, no root required.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${HERE}/../target/harness/fuzz_kr.c"
OUT="${OUT:-${HERE}/../.krfix/build}"
CLANG="${CLANG:-clang}"

mkdir -p "${OUT}"

echo "[build] compiler: $("${CLANG}" --version | head -1)"

"${CLANG}" -g -O1 -fsanitize=fuzzer,address \
  "${SRC}" -o "${OUT}/kr_fuzz_vuln"

"${CLANG}" -g -O1 -fsanitize=fuzzer,address -DKR_FIXED \
  "${SRC}" -o "${OUT}/kr_fuzz_fixed"

"${CLANG}" -g -O1 -fsanitize=address -DKR_REPLAY_EXIT \
  "${SRC}" -o "${OUT}/kr_replay_vuln"

"${CLANG}" -g -O1 -fsanitize=address -DKR_REPLAY_EXIT -DKR_FIXED \
  "${SRC}" -o "${OUT}/kr_replay_fixed"

cat > "${OUT}/BUILD_MANIFEST.txt" <<EOF
built_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
clang=$(${CLANG} --version | head -1)
source=${SRC}
flavors=kr_fuzz_vuln,kr_fuzz_fixed,kr_replay_vuln,kr_replay_fixed
EOF

echo "[build] artifacts in ${OUT}"
ls -l "${OUT}"
