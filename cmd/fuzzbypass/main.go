//go:build fuzzshim

// fuzzbypass is the libFuzzer harness for the unicode-bypass target.
// Build and link with a real libFuzzer engine (requires clang with
// -fsanitize=fuzzer for the __sanitizer_cov_* runtime):
//
//	go build -tags "fuzzshim libfuzzer" \
//	  -buildmode=c-shared -o fuzzbypass.so ./cmd/fuzzbypass
//	clang -fsanitize=fuzzer fuzzbypass.c ./fuzzbypass.so -o fuzzbypass
//
// The "libfuzzer" build tag is Go's official switch for libFuzzer
// coverage instrumentation; "fuzzshim" only exposes the entry point.
// The same logic is exercised by Go's native fuzzer via
// FuzzFilenameUnicodeBypass in internal/filter/fuzz_test.go.
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"unicodebypass/internal/filter"
)

//export LLVMFuzzerTestOneInput
func LLVMFuzzerTestOneInput(data *C.char, size C.size_t) C.int {
	if size <= 0 {
		return 0
	}
	name := C.GoStringN(data, C.int(size))
	v := filter.Classify(name)
	if v.Bypass() {
		// A bypass is a finding: abort so libFuzzer preserves the
		// crashing input as a corpus artifact.
		panic("unicode filter bypass: " + filter.Canonicalize(name))
	}
	return 0
}

func main() {}
