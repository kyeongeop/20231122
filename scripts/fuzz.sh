#!/usr/bin/env bash
# 覆盖率引导 fuzzing。Go 原生 fuzzing 引擎是 libFuzzer 的 Go 移植版，
# 使用相同的覆盖率插桩、能量调度与语料最小化机制。
set -euo pipefail

cd "$(dirname "$0")/.."

DURATION="${FUZZ_TIME:-30s}"
go test -run='^$' -fuzz=FuzzParseAndReplay -fuzztime="$DURATION" ./internal/quota

# 人工语料（含空输入/超大输入种子）的离线回归。
go test -run TestCorpusSeeds -v ./internal/quota
