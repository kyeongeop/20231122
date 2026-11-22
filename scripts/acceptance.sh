#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORIGINAL="$ROOT/testdata/original/container-mount-capture.v1.txt"
BIN="$ROOT/build/mountaudit"
STAMP="$(date -u +%Y%m%dT%H%M%S.%NZ)"
OUT="${1:-$ROOT/artifacts/acceptance/$STAMP}"
GO_BIN="${GO:-}"

NEEDS_BUILD=false
if [[ ! -x "$BIN" ]]; then
  NEEDS_BUILD=true
elif [[ -n "$(find "$ROOT/cmd" "$ROOT/internal" "$ROOT/go.mod" -newer "$BIN" -print -quit)" ]]; then
  NEEDS_BUILD=true
fi

if [[ "$NEEDS_BUILD" == true ]]; then
  if [[ -n "$GO_BIN" ]]; then
    (cd "$ROOT" && CGO_ENABLED=1 "$GO_BIN" build -o "$BIN" ./cmd/mountaudit)
  else
    (cd "$ROOT" && make build)
  fi
fi

mkdir -p "$OUT"
SHA_BEFORE="$(sha256sum "$ORIGINAL" | awk '{print $1}')"
MODE_BEFORE="$(stat -c '%a' "$ORIGINAL")"

"$BIN" init --db "$OUT/audit.db" --input "$ORIGINAL" \
  --artifacts "$OUT/artifacts" >"$OUT/init.json"
RUN_ID="$(jq -r '.run_id' "$OUT/init.json")"

"$BIN" run --db "$OUT/audit.db" --run "$RUN_ID" --pause-after 1 >"$OUT/pause-1.json"
"$BIN" resume --db "$OUT/audit.db" --run "$RUN_ID" --pause-after 2 >"$OUT/pause-2.json"
"$BIN" resume --db "$OUT/audit.db" --run "$RUN_ID" >"$OUT/complete.json"
"$BIN" verify --db "$OUT/audit.db" --run "$RUN_ID" >"$OUT/verify.json"
"$BIN" report --db "$OUT/audit.db" --run "$RUN_ID" \
  --format json --out "$OUT/report.json"
"$BIN" status --db "$OUT/audit.db" --run "$RUN_ID" >"$OUT/status.txt"

SHA_AFTER="$(sha256sum "$ORIGINAL" | awk '{print $1}')"
MODE_AFTER="$(stat -c '%a' "$ORIGINAL")"

jq -e --arg sha "$SHA_BEFORE" '
  .run.status == "completed" and
  .original.unmodified == true and
  .original.sha256 == $sha and
  .original.artifact_mode == "0444" and
  (.anchors | length) == 3 and
  .anchors[0].offset == 83 and .anchors[0].line == 3 and
  .anchors[1].offset == 385 and .anchors[1].line == 7 and
  .anchors[2].offset == 787 and .anchors[2].line == 13 and
  (.checkpoints | length) == 3 and
  all(.checkpoints[]; (.started_at | length) > 0 and (.finished_at | length) > 0) and
  (.findings | length) > 0 and
  all(.findings[]; (.observed_at | length) > 0 and .start_offset >= 0 and .end_offset > .start_offset) and
  any(.findings[]; .code == "container_socket_mount" and .severity == "critical") and
  any(.comparisons[]; .scope == "resume-replay:stage:1" and .equal == true) and
  any(.comparisons[]; .scope == "resume-replay:final" and .equal == true)
' "$OUT/report.json" >/dev/null

if [[ "$SHA_BEFORE" != "$SHA_AFTER" || "$MODE_BEFORE" != "$MODE_AFTER" ]]; then
  echo "original material changed during acceptance" >&2
  exit 1
fi

jq -e '
  .status == "completed" and
  .next_stage == 4 and
  .degraded == false
' "$OUT/complete.json" >/dev/null
jq -e '.equal == true and .stages_compared == 3' "$OUT/verify.json" >/dev/null

jq -r '.checkpoints[] |
  "checkpoint \(.stage): [\(.start_offset),\(.end_offset)) " +
  "started_at=\(.started_at) finished_at=\(.finished_at) " +
  "anchor_offset=\(.anchor_offset) result_sha256=\(.result_sha256)"
' "$OUT/report.json"
jq -r '.findings[] |
  "finding \(.ordinal): \(.severity)/\(.code) " +
  "raw=[\(.start_offset),\(.end_offset)) line=\(.line) observed_at=\(.observed_at)"
' "$OUT/report.json"

DEGRADED_OUT="$OUT/degraded"
mkdir -p "$DEGRADED_OUT"
"$BIN" init --db "$DEGRADED_OUT/audit.db" --input "$ORIGINAL" \
  --artifacts "$DEGRADED_OUT/artifacts" \
  --max-scan-bytes 420 --max-records 2 >"$DEGRADED_OUT/init.json"
DEGRADED_RUN="$(jq -r '.run_id' "$DEGRADED_OUT/init.json")"
"$BIN" run --db "$DEGRADED_OUT/audit.db" --run "$DEGRADED_RUN" >"$DEGRADED_OUT/run.json"
"$BIN" report --db "$DEGRADED_OUT/audit.db" --run "$DEGRADED_RUN" \
  --format json --out "$DEGRADED_OUT/report.json"

jq -e '
  .run.status == "degraded" and
  .summary.degraded == true and
  .summary.pipeline_complete == true and
  .summary.analysis_complete == false and
  any(.evidence[]; .kind == "resource_scan_budget") and
  any(.evidence[]; .kind == "resource_record_quota") and
  all(.checkpoints[]; .end_offset <= 420)
' "$DEGRADED_OUT/report.json" >/dev/null

echo "acceptance_dir=$OUT"
echo "original_sha256=$SHA_BEFORE original_mode=$MODE_AFTER unchanged=true"
echo "degraded_report=$DEGRADED_OUT/report.json"
