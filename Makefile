GO ?= go
CLANGXX ?=

.PHONY: build fuzzer test e2e clean

build:
	$(GO) build -o build/apiskew ./cmd/apiskew

fuzzer:
	CLANGXX="$(CLANGXX)" scripts/build-fuzzer.sh build/apiskew_fuzz

test:
	$(GO) test ./...

e2e: build fuzzer
	APISKEW_FUZZER="$$PWD/build/apiskew_fuzz" $(GO) test ./...

clean:
	$(GO) clean ./...
	find build -type f -delete 2>/dev/null || true
