#!/usr/bin/env bash
# 模拟同事独立复核：从 JSONL 重载到全新 SQLite 库，
# 逐记录校验 SHA-256 指纹与字段顺序。
set -euo pipefail

cd "$(dirname "$0")/.."

go build -o artifacts/quotabypass ./cmd/quotabypass
FRESH="${FRESH_DB:-artifacts/reload.sqlite}"
find "$FRESH" -delete 2>/dev/null || true

./artifacts/quotabypass import -db "$FRESH" -in artifacts/evidence.jsonl
./artifacts/quotabypass verify -db "$FRESH"

# 独立 sha256sum 复核：规范化 evidence.json 与清单哈希。
echo "--- file digests ---"
sha256sum artifacts/evidence.json artifacts/evidence.jsonl
