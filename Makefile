.PHONY: run test vet fuzz

run:
	go run ./cmd/server

test:
	go test ./...

vet:
	go vet ./...

fuzz:
	./scripts/fuzz.sh
