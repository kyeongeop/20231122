#!/usr/bin/env bash
# Reproducible entry point for the protocol timeout state machine experiment.
set -euo pipefail

export PATH="${GO_BIN:-/tmp/go/bin}:${PATH}"
export GOPATH="${GOPATH:-/home/hj/.gopath}"
# The sandbox proxy on 7897 is often down; use a working direct module mirror.
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY || true
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
export GOSUMDB=off

echo "==> unit tests"
go test ./...

echo "==> experiment (record + single post-recovery replay)"
go run ./cmd/experiment

echo "==> SQLite evidence"
go run ./cmd/dbquery

echo
echo "Done. See evidence/report.md (automated verdict + manual checklist)."
echo "Run 'make fuzz' for coverage-guided fuzzing (Go/libFuzzer-style engine)."
