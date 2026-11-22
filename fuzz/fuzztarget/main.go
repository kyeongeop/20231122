// Binary fuzztarget exposes the escaping engine through the canonical
// libFuzzer entrypoint LLVMFuzzerTestOneInput. Build it as a C archive
// and link with clang -fsanitize=fuzzer for real libFuzzer runs:
//
//	go build -buildmode=c-archive -o fuzz/tve_fuzz.a ./fuzz/fuzztarget
//	clang -fsanitize=fuzzer,address fuzz/tve_fuzz.a -o fuzz/tve-fuzz
//	./fuzz/tve-fuzz fuzz/corpus
//
// In containers without clang, the same archive links with the small
// replay driver in fuzz/driver.c (see fuzz/run_replay.sh).
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"encoding/binary"
	"unsafe"

	"tve/internal/escape"
)

//export LLVMFuzzerTestOneInput
func LLVMFuzzerTestOneInput(data *C.uint8_t, size C.size_t) C.int {
	b := C.GoBytes(unsafe.Pointer(data), C.int(size))
	fuzzOne(b)
	return 0
}

// fuzzOne maps raw fuzzer bytes onto (template, value, limits).
func fuzzOne(b []byte) {
	if len(b) < 6 {
		return
	}
	tlen := int(binary.LittleEndian.Uint16(b[0:2])) % (1 + len(b))
	maxVal := int(binary.LittleEndian.Uint16(b[2:4]))
	maxOut := int(binary.LittleEndian.Uint16(b[4:6]))
	tmpl := b[6 : 6+min(tlen, len(b)-6)]
	val := string(b[6+min(tlen, len(b)-6):])
	_, _ = escape.Render(tmpl, map[string]string{"a": val, "b": val},
		escape.Limits{MaxValueBytes: maxVal, MaxOutputBytes: maxOut})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {}
