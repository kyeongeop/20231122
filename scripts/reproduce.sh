#!/usr/bin/env bash
# End-to-end reproduction of the parser integer-overflow audit.
# Assumes Go and clang (with libFuzzer/ASan/UBSan) are on PATH or supplied via
# the environment variables below.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PATH="${GO_DIR:-$HOME/.local/opt/go/bin}:${CLANG_DIR:-$HOME/.local/opt/clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04/bin}:$PATH"
export LD_LIBRARY_PATH="${LOCAL_LIB:-$HOME/.local/lib}:${LD_LIBRARY_PATH:-}"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"

echo "== 1. build & unit tests =="
go build ./...
go test ./... -count=1

echo "== 2. run audit, persist SQLite evidence =="
rm -f evidence/audit.db evidence/audit.db-wal evidence/audit.db-shm
go run ./cmd/audit -base .

echo "== 3. hash manifest & acceptance report =="
go run ./cmd/manifest -base .
go run ./cmd/report -base .

echo "== 4. libFuzzer targets =="
(cd fuzz && ./build.sh)
(cd fuzz && ./parser_fuzz_hardened seed_corpus \
	-max_total_time="${FUZZ_SECONDS:-60}" \
	-artifact_prefix=../evidence/crashers/ -print_final_stats=1 \
	> ../evidence/crashers/hardened-fuzz.log 2>&1)

echo "== 5. verify evidence chain =="
go run ./cmd/query -base .

echo "reproduction complete; see evidence/reports/ACCEPTANCE.md"
