#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"
cd "$ROOT"

"$SCRIPT_DIR/build_fuzzer.sh"
"$SCRIPT_DIR/run_fuzzer.sh"

"$GO" build -o .build/depthlab ./cmd/depthlab
"$ROOT/.build/depthlab" run \
	--out artifacts \
	--fuzz-record artifacts/fuzzer/crash.graphql \
	--limit 4
"$ROOT/.build/depthlab" verify \
	--db artifacts/evidence.sqlite \
	--report artifacts/report.json \
	--manifest artifacts/manifest.sha256
