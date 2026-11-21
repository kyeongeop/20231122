#!/usr/bin/env bash
# End-to-end acceptance for the pausable container-image permission audit.
# Acceptance lands on concrete UTC timestamps and raw tar offsets.
set -uo pipefail
cd "$(dirname "$0")/.."

export PATH="$HOME/sdk/go/bin:$PATH"
BIN=artifacts/permaudit
DB=artifacts/audit.db
IMG=artifacts/image.tar

rm -rf artifacts
mkdir -p artifacts

echo "== build =="
go build -o "$BIN" ./cmd/permaudit || exit 1
go build -o artifacts/genimage ./cmd/genimage || exit 1

echo "== fixture + pristine original =="
artifacts/genimage -out "$IMG"
"$BIN" snapshot -image "$IMG" -dir artifacts/original

echo "== baseline run (single pass) =="
"$BIN" run -db "$DB" -image "$IMG" -run-id base || exit 1

echo "== paused/resumed run (pause every 5 entries, checkpoint every entry) =="
while true; do
  "$BIN" run -db "$DB" -image "$IMG" -run-id paused \
    -checkpoint-every 1 -pause-after 5
  code=$?
  if [ "$code" -eq 3 ]; then
    echo "  paused; resuming..."
    continue
  fi
  [ "$code" -eq 0 ] || exit 1
  break
done

echo "== degraded run (mem-budget 700000 < 1MiB blobs) =="
"$BIN" run -db "$DB" -image "$IMG" -run-id degraded \
  -checkpoint-every 1 -mem-budget 700000 || exit 1

echo "== repeated object under extreme params (3 rounds) =="
for r in round1 round2 round3; do
  "$BIN" run -db "$DB" -image "$IMG" -run-id "$r" \
    -checkpoint-every 1 -mem-budget 1 || exit 1
done

echo "== compare before/after (baseline vs paused/resumed) =="
"$BIN" compare -db "$DB" -a base -b paused || exit 1

echo "== compare rounds for determinism =="
"$BIN" compare -db "$DB" -a round1 -b round2 || exit 1
"$BIN" compare -db "$DB" -a round1 -b round3 || exit 1

echo "== verify raw offsets against image =="
for r in base paused degraded round1; do
  "$BIN" verify -db "$DB" -image "$IMG" -run-id "$r" || exit 1
done

echo "== original material untouched =="
"$BIN" check-original -dir artifacts/original || exit 1

echo "== key evidence (timestamps + raw offsets) =="
"$BIN" report -db "$DB" -run-id base
"$BIN" report -db "$DB" -run-id degraded

echo "ACCEPTANCE_OK ts=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
