//go:build linux && cgo

package main

/*
#include <stddef.h>
*/
import "C"

import (
	"unsafe"

	"taintlab/internal/invariants"
	"taintlab/internal/taint"
)

const maxFuzzInput = 2 * 1024 * 1024

//export LLVMFuzzerTestOneInput
func LLVMFuzzerTestOneInput(data unsafe.Pointer, size C.size_t) C.int {
	length := uint64(size)
	if length > maxFuzzInput {
		return 0
	}
	var input []byte
	if length > 0 {
		input = C.GoBytes(data, C.int(length))
	}
	result := taint.Execute(input)
	if err := invariants.Check(result); err != nil {
		panic("taintlab invariant: " + err.Error())
	}
	return 0
}

func main() {}
