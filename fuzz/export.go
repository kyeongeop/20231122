// Fuzz entrypoint: exposes the DNS name encoding validation pipeline to
// libFuzzer through a c-shared library. The invariant under test:
// Evaluate never panics on arbitrary bytes and always returns one of the
// three known permission verdicts.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"

	"dnscheck/internal/checker"
)

//export FuzzValidate
func FuzzValidate(data *C.char, size C.int) C.int {
	if size < 0 {
		return 0
	}
	buf := C.GoBytes(unsafe.Pointer(data), size)
	res := checker.Evaluate(string(buf))
	switch res.Verdict {
	case checker.VerdictDeny, checker.VerdictAllow, checker.VerdictUndetermined:
		return 0
	}
	panic("unknown verdict: " + string(res.Verdict))
}

func main() {}
