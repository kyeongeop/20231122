#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x "$ROOT/.toolchain/root/usr/local/go/bin/go" ]]; then
	"$ROOT/scripts/bootstrap.sh"
fi
source "$ROOT/scripts/env.sh"

FUZZ_SECONDS="${FUZZ_SECONDS:-10}"
if [[ -d artifacts/evidence ]] && [[ -n "$(find artifacts/evidence -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
	STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
	mkdir -p artifacts/archive
	mv artifacts/evidence "artifacts/archive/evidence-$STAMP"
fi
mkdir -p artifacts/evidence

make build >artifacts/evidence/build.log 2>&1

record_stage() {
	local id="$1"
	local rc="$2"
	local evidence="$3"
	if [[ "$rc" -eq 0 ]]; then
		./build/dfexp record-check --db artifacts/evidence/experiment.db \
			--id "$id" --category pipeline --passed \
			--expected "command exits 0" --observed "exit=0" --evidence "$evidence"
	else
		./build/dfexp record-check --db artifacts/evidence/experiment.db \
			--id "$id" --category pipeline --passed=false \
			--expected "command exits 0" --observed "exit=$rc" --evidence "$evidence"
	fi
}

{
	go version
	clang --version | head -2
	go list -m github.com/mattn/go-sqlite3
} >artifacts/evidence/toolchain.txt

set +e
go test -v ./... >artifacts/evidence/unit-tests.log 2>&1
TEST_RC=$?
set -e
if [[ "$TEST_RC" -eq 0 ]]; then
	./build/dfexp record-check --db artifacts/evidence/experiment.db \
		--id boundary_unit_tests --category build --passed \
		--expected "go test ./... passes" --observed "exit=0" \
		--evidence "artifacts/evidence/unit-tests.log"
else
	./build/dfexp record-check --db artifacts/evidence/experiment.db \
		--id boundary_unit_tests --category build --passed=false \
		--expected "go test ./... passes" --observed "exit=$TEST_RC" \
		--evidence "artifacts/evidence/unit-tests.log"
fi

set +e
./build/dfexp run --db artifacts/evidence/experiment.db --out artifacts/evidence \
	>artifacts/evidence/core-run.json 2>artifacts/evidence/core-run.err
CORE_RC=$?
set -e
record_stage core_run_command "$CORE_RC" artifacts/evidence/core-run.err
./build/dfexp query --db artifacts/evidence/experiment.db \
	--sql "SELECT 'sqlite_version=' || sqlite_version();" | tail -1 >>artifacts/evidence/toolchain.txt

mkdir -p artifacts/evidence/fuzz
make fuzz FUZZ_SECONDS="$FUZZ_SECONDS" >artifacts/evidence/fuzz/make.log 2>&1
FUZZ_RC="$(cat artifacts/evidence/fuzz/exit_code)"
if [[ "$FUZZ_RC" -eq 0 ]]; then
	./build/dfexp record-check --db artifacts/evidence/experiment.db \
		--id libfuzzer_process_exit_zero --category fuzzing --passed \
		--expected "libFuzzer process exits 0" --observed "exit=0" \
		--evidence "artifacts/evidence/fuzz/fuzzer.log"
else
	./build/dfexp record-check --db artifacts/evidence/experiment.db \
		--id libfuzzer_process_exit_zero --category fuzzing --passed=false \
		--expected "libFuzzer process exits 0" --observed "exit=$FUZZ_RC" \
		--evidence "artifacts/evidence/fuzz/fuzzer.log"
fi

set +e
./build/dfexp ingest-fuzz --db artifacts/evidence/experiment.db \
	--corpus artifacts/evidence/fuzz/corpus --out artifacts/evidence \
	>artifacts/evidence/fuzz/ingest.json 2>artifacts/evidence/fuzz/ingest.err
INGEST_RC=$?
set -e
record_stage fuzz_corpus_ingest_command "$INGEST_RC" artifacts/evidence/fuzz/ingest.err

set +e
./build/dfexp fuzz-stats --db artifacts/evidence/experiment.db \
	--log artifacts/evidence/fuzz/fuzzer.log \
	--artifacts artifacts/evidence/fuzz \
	--corpus artifacts/evidence/fuzz/corpus \
	>artifacts/evidence/fuzz/stats.json 2>artifacts/evidence/fuzz/stats.err
STATS_RC=$?
set -e
record_stage fuzz_stats_command "$STATS_RC" artifacts/evidence/fuzz/stats.err

set +e
./build/dfexp replay --source artifacts/evidence/experiment.db \
	--dest artifacts/evidence/replay.db --out artifacts/evidence \
	>artifacts/evidence/replay-command.json 2>artifacts/evidence/replay-command.err
REPLAY_RC=$?
set -e
record_stage replay_command "$REPLAY_RC" artifacts/evidence/replay-command.err

./build/dfexp manifest --dir artifacts/evidence >artifacts/manifest-run.log
set +e
./build/dfexp report --db artifacts/evidence/experiment.db \
	--evidence artifacts/evidence --out artifacts \
	>artifacts/report-run.log 2>&1
REPORT_RC=$?
set -e
cat artifacts/report-run.log
./build/dfexp verify-manifest --dir artifacts/evidence
exit "$REPORT_RC"
