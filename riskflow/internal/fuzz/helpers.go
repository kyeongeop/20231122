package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"os"
	"unsafe"
)

// unsafePointer adapts the C char pointer to the argument type of C.GoBytes.
func unsafePointer(p *C.char) unsafe.Pointer {
	return unsafe.Pointer(p)
}

// cTempDir creates an isolated working directory for one fuzz iteration.
func cTempDir() string {
	dir, err := os.MkdirTemp("", "riskflow-fuzz-")
	if err != nil {
		// Fall back to the process temp dir; SQLite will still open a file.
		return os.TempDir()
	}
	return dir
}
