// Command bridge exports the Go truncated-stream parser over the C ABI so an
// external libFuzzer driver (clang -fsanitize=fuzzer) can feed raw capture
// bytes directly into the production parser. The bridge deliberately contains
// no test-only logic: it calls the exact stream.Parse used by the pipeline.
package main

/*
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"unsafe"

	"truncstream/internal/stream"
)

func main() {}

// Error classes mirrored to C so the libFuzzer harness can assert on them
// without depending on Go string memory.
const (
	ClassNone        = 0
	ClassMagic       = 1
	ClassHeader      = 2
	ClassLength      = 3
	ClassChecksum    = 4
	ClassCompression = 5
	ClassEncoding    = 6
	ClassUnknownType = 7
)

var classToCode = map[string]C.int{
	stream.ErrClassMagic:       ClassMagic,
	stream.ErrClassHeader:      ClassHeader,
	stream.ErrClassLength:      ClassLength,
	stream.ErrClassChecksum:    ClassChecksum,
	stream.ErrClassCompression: ClassCompression,
	stream.ErrClassEncoding:    ClassEncoding,
	stream.ErrClassUnknownType: ClassUnknownType,
}

//export TSTParse
func TSTParse(data *C.char, size C.size_t) C.int {
	var buf []byte
	if size > 0 && data != nil {
		buf = unsafe.Slice((*byte)(unsafe.Pointer(data)), int(size))
	}
	res := stream.Parse(buf)
	if res.Error == nil {
		return ClassNone
	}
	return classToCode[res.Error.Class]
}

//export TSTVersion
func TSTVersion() *C.char {
	return C.CString("truncstream-libfuzzer-bridge/1")
}
