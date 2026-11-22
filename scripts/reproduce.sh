#!/usr/bin/env bash
# End-to-end reproduction: unit tests -> libFuzzer build + campaign ->
# SQLite evidence load -> acceptance report + integrity verification.
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
source scripts/env.sh

echo "== 1/5 go unit tests =="
go test ./...

echo "== 2/5 build libFuzzer harness =="
scripts/build_fuzz.sh

echo "== 3/5 run libFuzzer campaign (30s) =="
mkdir -p artifacts/fuzz-smoke
mkdir -p corpus-work
./fuzz/dnsfuzz -max_total_time=30 -max_len=8192 \
  -artifact_prefix=artifacts/fuzz-smoke/ corpus corpus-work > artifacts/fuzz_run_repro.log 2>&1
grep -E "ERROR|AddressSanitizer|panic" artifacts/fuzz_run_repro.log && {
  echo "fuzz campaign found a failure"; exit 1; } || true
tail -1 artifacts/fuzz_run_repro.log

echo "== 4/5 verify preserved raw materials =="
sha256sum -c evidence/raw/SHA256SUMS

echo "== 5/5 load SQLite store and render report =="
go run ./cmd/seed -fuzzlog artifacts/fuzz_run_repro.log
go run ./cmd/report
go run ./cmd/inspect | head -20

echo "reproduction complete; see artifacts/report.md and artifacts/dnscheck.db"
