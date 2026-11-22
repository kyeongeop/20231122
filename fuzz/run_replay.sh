#!/bin/sh
# Build the libFuzzer-compatible target and replay the seed corpus.
# With clang installed, prefer a real libFuzzer run:
#   go build -buildmode=c-archive -o fuzz/tve_fuzz.a ./fuzz/fuzztarget
#   clang -fsanitize=fuzzer,address fuzz/tve_fuzz.a -o fuzz/tve-fuzz
#   ./fuzz/tve-fuzz fuzz/corpus -max_total_time=60
set -eu
cd "$(dirname "$0")/.."
go build -buildmode=c-archive -o fuzz/tve_fuzz.a ./fuzz/fuzztarget
cc fuzz/driver.c fuzz/tve_fuzz.a -o fuzz/replay -lpthread
./fuzz/replay fuzz/corpus/*
