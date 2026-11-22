GO ?= go
CLANG ?= clang++
BUILD_DIR ?= build

.PHONY: run test fuzz build fuzz-build clean

run:
	$(GO) run ./cmd/server

test:
	$(GO) test ./...

build:
	mkdir -p $(BUILD_DIR)
	$(GO) build -trimpath -o $(BUILD_DIR)/webhook-inspect ./cmd/server

fuzz-build:
	mkdir -p $(BUILD_DIR)/corpus
	CGO_ENABLED=1 $(GO) build -buildmode=c-archive -o $(BUILD_DIR)/libverify.a ./fuzz/export
	$(CLANG) -std=c++17 -O1 -g -fsanitize=fuzzer,address -I$(BUILD_DIR) \
		fuzz/verify_fuzz.cc $(BUILD_DIR)/libverify.a -lpthread -ldl -o $(BUILD_DIR)/verify_fuzzer
	cp fuzz/corpus/* $(BUILD_DIR)/corpus/

fuzz: fuzz-build
	$(BUILD_DIR)/verify_fuzzer $(BUILD_DIR)/corpus -max_total_time=20 -print_final_stats=1
