#!/bin/sh
# End-to-end reproduction: scenarios -> evidence db -> export -> reload+verify.
set -eu
cd "$(dirname "$0")"
export PATH="$HOME/go/bin:$PATH" GOPATH="${GOPATH:-$HOME/gopath}"

go build -o bin/bombverify ./cmd/bombverify

./bin/bombverify scenario all
./bin/bombverify scenario --subject intern --deny missing_fragment
./bin/bombverify export
./bin/bombverify reload --source-db artifacts/evidence.db

go test ./...
