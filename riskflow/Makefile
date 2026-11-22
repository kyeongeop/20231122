# Auditable dependency-risk pipeline. Remember to `source ./env.sh` first.

.PHONY: all test fmt vet cli fuzz demo clean

all: cli fuzz

test:
	go test ./...

fmt:
	gofmt -w cmd internal

vet:
	go vet ./...

cli:
	go build -o bin/riskflow ./cmd/riskflow

fuzz:
	./fuzz/build.sh

demo:
	./run_demo.sh

clean:
	rm -rf bin build fuzz/build fuzz/artifacts fuzz/poison_in fuzz/clean_corpus
