package main

/*
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"unsafe"

	"mountaudit/internal/audit"
)

const maxFuzzInput = 1 << 20

//export MTAFuzz
func MTAFuzz(data *C.uint8_t, size C.size_t) C.int {
	if size == 0 || size > maxFuzzInput {
		return 0
	}
	payload := C.GoBytes(unsafe.Pointer(data), C.int(size))
	limits := audit.DefaultLimits()
	limits.MaxScanBytes = maxFuzzInput
	limits.MaxRecords = 2048
	audit.Analyze(payload, limits, nil)
	return 0
}

func main() {}
