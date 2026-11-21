// Fuzz entrypoint: exposes the checker pipeline to libFuzzer through a
// c-shared library. The invariant under test: Evaluate never panics and
// always returns one of the three known verdicts, for arbitrary bytes.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"

	"wsauthz/internal/checker"
)

//export FuzzClassify
func FuzzClassify(data *C.char, size C.int) C.int {
	if size < 0 {
		return 0
	}
	buf := C.GoBytes(unsafe.Pointer(data), size)
	res := checker.Evaluate(checker.Input{
		Label:   "fuzz",
		Content: string(buf),
	})
	switch res.Verdict {
	case checker.VerdictBypassDetected, checker.VerdictNoBypass, checker.VerdictUndetermined:
		return 0
	}
	panic("unknown verdict: " + string(res.Verdict))
}

func main() {}
