#!/usr/bin/env bash
# 一键复核流水线：单元测试 -> 语料回放 -> 模糊测试 -> 生成报告。
# 证据库已存在时不会覆盖原始证据（用例级去重）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_BIN="${GO_BIN:-$HOME/local/go/bin/go}"
RUNS="${FUZZ_RUNS:-300000}"

cd "$ROOT"
mkdir -p bin reports

echo "==> [1/4] go test"
"$GO_BIN" test ./...

echo "==> [2/4] build CLI"
"$GO_BIN" build -o bin/oauthreview ./cmd/oauthreview

echo "==> [3/4] replay curated corpus into SQLite"
./bin/oauthreview replay --corpus fuzz/seed --db reports/evidence.db

echo "==> [4/4] libFuzzer + report"
./scripts/fuzz.sh "$RUNS"
./bin/oauthreview report --corpus fuzz/seed --db reports/evidence.db \
  --fuzz-log reports/fuzz-summary.txt --out reports/review-report.md

echo "PIPELINE_OK -> reports/evidence.db, reports/review-report.md"
