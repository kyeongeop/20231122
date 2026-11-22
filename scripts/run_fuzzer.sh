#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"
cd "$ROOT"

BIN="$ROOT/.build/depth-fuzzer"
if [[ ! -x "$BIN" ]]; then
	"$SCRIPT_DIR/build_fuzzer.sh"
fi

mkdir -p artifacts/fuzzer .build/fuzz-corpus
rm -rf .build/fuzz-corpus
mkdir -p .build/fuzz-corpus
cp artifacts/fuzzer/seed.graphql .build/fuzz-corpus/seed
rm -f artifacts/fuzzer/crash.graphql

set +e
timeout 30s "$BIN" \
	.build/fuzz-corpus \
	-runs=1000 \
	-seed=20231122 \
	-artifact_prefix="$ROOT/artifacts/fuzzer/" \
	-exact_artifact_path="$ROOT/artifacts/fuzzer/crash.graphql" \
	-print_final_stats=1 \
	> artifacts/fuzzer/libfuzzer.log 2>&1
status=$?
set -e

printf '\n[fuzzwrapper] exit=%d artifact=%s\n' "$status" "$ROOT/artifacts/fuzzer/crash.graphql" \
	>> artifacts/fuzzer/libfuzzer.log
if [[ ! -s artifacts/fuzzer/crash.graphql ]]; then
	echo "libFuzzer did not preserve the crash artifact; see artifacts/fuzzer/libfuzzer.log" >&2
	exit 1
fi

echo "libFuzzer crash preserved at artifacts/fuzzer/crash.graphql"
