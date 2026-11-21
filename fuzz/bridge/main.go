//go:build cgo

// Command fuzzbridge exports the deterministic corpus probe to libFuzzer.
package main

/*
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"unsafe"

	"corpusd/internal/model"
	"corpusd/internal/probe"
)

//export CorpusProbe
func CorpusProbe(data *C.uint8_t, size C.size_t) C.int {
	if size > 1<<24 {
		return 0
	}
	input := C.GoBytes(unsafe.Pointer(data), C.int(size))
	result := probe.Analyze(input, "", model.ModeFull)
	if result.ResultSHA256 == "" || result.CoverageBytes != len(input) {
		return 1
	}
	return 0
}

func main() {}
