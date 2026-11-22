.PHONY: run test fuzz

run:
	go run ./cmd/server

test:
	go test ./...

fuzz:
	CLANG="$${CLANG:-clang++}" CC="$${CC:-clang}" scripts/fuzz.sh -max_total_time=30
