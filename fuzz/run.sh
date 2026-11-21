#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p ../tmp
./build.sh

set +e
./kz3_replay corpus/seed.kz3 > ../tmp/replay.stdout 2> ../tmp/replay.stderr
status=$?
set -e

cat ../tmp/replay.stderr
if [[ "$status" -eq 0 ]]; then
  echo "expected ASan reproduction, got exit 0" >&2
  exit 1
fi
echo "reproduced boundary: exit=$status"
