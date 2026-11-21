GO ?= go

.PHONY: run test fuzz

run:
	$(GO) run . -addr :8080 -db evidence/forensics.db

test:
	$(GO) test ./...

fuzz:
	cd fuzz && CC=clang ./build.sh
	cd fuzz && ./kz3_fuzz corpus/
