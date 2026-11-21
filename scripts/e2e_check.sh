#!/usr/bin/env bash
# End-to-end acceptance check for krfix. Uses only the built krfix binary and
# the libFuzzer harnesses; creates all state under a throwaway temp directory.
#
# Required env:
#   KRFIX_BIN   path to the krfix binary
#   BUILD_DIR   directory containing kr_replay_vuln / kr_replay_fixed /
#               kr_fuzz_vuln / kr_fuzz_fixed
set -euo pipefail

: "${KRFIX_BIN:?set KRFIX_BIN}"
: "${BUILD_DIR:?set BUILD_DIR}"

WORK="$(mktemp -d)"
trap 'echo "e2e workspace left at: $WORK"' EXIT
cd "$WORK"

echo "[1/8] init + immutable original"
"$KRFIX_BIN" init
test -f .krfix/original/original_kr_blob.bin
stat -c '%a' .krfix/original/original_kr_blob.bin | grep -q '^444$'
"$KRFIX_BIN" verify

echo "[2/8] import corpus (three anchors, raw offsets)"
"$KRFIX_BIN" import
mkdir -p .krfix/build
	cp "$BUILD_DIR"/kr_replay_vuln "$BUILD_DIR"/kr_replay_fixed .krfix/build/

echo "[3/8] independent replay of every sample, both phases"
"$KRFIX_BIN" run

echo "[4/8] re-entry skips completed jobs"
"$KRFIX_BIN" run | grep -q 'processed=0 skipped=18'

echo "[5/8] stop/resume: interrupted job is recovered and finished"
setsid bash -c "cd '$WORK' && exec env KRFIX_REPLAY_DELAY_MS=1500 \
	'$KRFIX_BIN' run --redo --sample atk_epoch_lag2 --phase vuln" \
	> /tmp/krfix_e2e_run.log 2>&1 < /dev/null &
PID=$!
for _ in $(seq 1 50); do
	grep -q '^run ' /tmp/krfix_e2e_run.log 2>/dev/null && break
	sleep 0.05
done
kill -TERM "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
RESUME_LOG="$WORK/resume.log"
"$KRFIX_BIN" run --sample atk_epoch_lag2 --phase vuln > "$RESUME_LOG" 2>&1
grep -q 'recovered' "$RESUME_LOG"
grep -q 'processed=1' "$RESUME_LOG"

echo "[6/8] verdicts: vuln reproduces (77), fix rejects (78), benign accepted"
"$KRFIX_BIN" report --sample atk_epoch_lag2 | grep -q ROTATION_FAILURE_REPRODUCED
"$KRFIX_BIN" report --sample atk_epoch_lag2 | grep -q STALE_KEY_REJECTED
"$KRFIX_BIN" report --sample benign_current | grep -q FRAME_ACCEPTED

echo "[7/8] per-sample export bundle with report + evidence"
"$KRFIX_BIN" export --sample atk_epoch_lag2
	tar tzf .krfix/export/atk_epoch_lag2/atk_epoch_lag2_evidence.tar.gz \
		| grep -q atk_epoch_lag2_report.json

echo "[8/8] tampering the original is detected"
chmod +w .krfix/original/original_kr_blob.bin
printf 'Z' | dd of=.krfix/original/original_kr_blob.bin bs=1 count=1 \
	conv=notrunc status=none
if "$KRFIX_BIN" verify >/dev/null 2>&1; then
	echo "FAIL: tamper not detected" >&2
	exit 1
fi

echo "E2E OK"
