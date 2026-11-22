// Command smuggle-fuzz is the libFuzzer entry point. Build it with:
//
//	CGO_ENABLED=1 CC=clang \
//	CGO_CFLAGS_ALLOW='-fsanitize.*' CGO_LDFLAGS_ALLOW='-fsanitize.*' \
//	CGO_LDFLAGS='-fsanitize=fuzzer' \
//	go build -tags libfuzzer -gcflags=all=-d=libfuzzer \
//	  -o artifacts/fuzz/smuggle-fuzz ./fuzz/libfuzzer
//
// The resulting binary is a native libFuzzer executable:
//
//	./artifacts/fuzz/smuggle-fuzz artifacts/fuzz/corpus -max_total_time=60
package main

/*
#include <stddef.h>
#include <stdint.h>
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/kyeongeop/20231122/fuzz/harness"
)

//export LLVMFuzzerTestOneInput
func LLVMFuzzerTestOneInput(p unsafe.Pointer, sz C.size_t) C.int {
	data := C.GoBytes(p, C.int(sz))
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "panic on input %q: %v\n", data, r)
			panic(r)
		}
	}()
	for _, v := range harness.Check(data) {
		// Invariant violations are fatal to the fuzzer: abort so libFuzzer
		// captures the crashing input.
		fmt.Fprintf(os.Stderr, "invariant violation: %s\n", v)
		panic(v)
	}
	return 0
}

func main() {}
