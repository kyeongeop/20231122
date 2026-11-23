// Package main is the libFuzzer entry point. It is built with the clang
// libFuzzer runtime (see fuzz/build.sh) rather than with the normal Go test
// runner, satisfying the fixed libFuzzer technology requirement.
package main

/*
#include <stdint.h>
#include <stddef.h>

// Provided by the Go side through cgo //export.
extern int GoIDORFixTarget(unsigned char* data, long long size);
*/
import "C"

import (
	"unsafe"

	idorfuzz "idorfix/internal/fuzz"
)

//export GoIDORFixTarget
func GoIDORFixTarget(data *C.uchar, size C.longlong) C.int {
	if size <= 0 {
		return 0
	}
	goBytes := C.GoBytes(unsafe.Pointer(data), C.int(size))
	return C.int(idorfuzz.Target(goBytes))
}

func main() {
	// libFuzzer supplies its own main(); this function is never reached in a
	// fuzzer build but keeps the package compilable as a normal Go program.
}
