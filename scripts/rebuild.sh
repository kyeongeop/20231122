#!/usr/bin/env bash
# 重建“资源配额绕过”处理过程：六个标准场景 -> SQLite -> 证据导出。
set -euo pipefail

cd "$(dirname "$0")/.."

export GOFLAGS="${GOFLAGS:-}"
DB="${DB:-artifacts/evidence.sqlite}"
OUT="${OUT:-artifacts}"

go build -o artifacts/quotabypass ./cmd/quotabypass
./artifacts/quotabypass rebuild -db "$DB" -out "$OUT"
./artifacts/quotabypass verify -db "$DB"
