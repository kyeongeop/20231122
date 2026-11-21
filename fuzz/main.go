// Package main exposes the decomp attack surface to libFuzzer. It is built
// as a c-archive with -gcflags=all=-d=libfuzzer and linked against
// libclang_rt.fuzzer (see fuzz/build_fuzzer.sh).
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"unsafe"

	"bombverify/internal/decomp"
)

//export LLVMFuzzerTestOneInput
func LLVMFuzzerTestOneInput(data *C.char, size C.size_t) C.int {
	if size == 0 {
		// Exercise the empty-input path as well.
		_, _ = decomp.Decompress(nil, decomp.DefaultQuota(), decomp.DiscardLogger{})
		return 0
	}
	buf := C.GoBytes(unsafe.Pointer(data), C.int(size))
	_, _ = decomp.Decompress(buf, decomp.DefaultQuota(), decomp.DiscardLogger{})
	return 0
}

func main() {}
