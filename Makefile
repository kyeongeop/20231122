GO ?= go
CLANGXX ?= clang++
WORKSPACE ?= .serrfix
ORIGINAL ?= testdata/original/incident-errors.txt

.PHONY: build test demo accept fuzz fuzz-build clean

build:
	$(GO) build -trimpath -o dist/serrfix ./cmd/serrfix

test:
	$(GO) test ./...

demo: build
	@test ! -e "$(WORKSPACE)" || (echo "refusing to overwrite existing workspace: $(WORKSPACE)"; exit 1)
	./dist/serrfix init --workspace $(WORKSPACE) --original $(ORIGINAL)
	./dist/serrfix run --workspace $(WORKSPACE) --resume --stop-after 2
	./dist/serrfix run --workspace $(WORKSPACE) --resume
	./dist/serrfix verify --workspace $(WORKSPACE)
	./dist/serrfix report --workspace $(WORKSPACE)

accept: build
	./dist/serrfix accept --workspace $(WORKSPACE) --json

fuzz: build
	CLANGXX=$(CLANGXX) ./dist/serrfix fuzz --workspace $(WORKSPACE) --runs 500 --max-seconds 3

fuzz-build:
	mkdir -p dist
	$(CLANGXX) -std=c++17 -O1 -g -fsanitize=fuzzer,address \
		-fno-omit-frame-pointer -o dist/error_fuzzer fuzz/error_target.cpp

clean:
	rm -rf dist coverage
