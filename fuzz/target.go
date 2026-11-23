package main

/*
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"unsafe"

	"example.com/deserialize-boundary/internal/wire"
)

//export DFParse
func DFParse(data *C.uint8_t, size C.size_t) C.int {
	code := C.int(1)
	func() {
		defer func() {
			if recover() != nil {
				code = 2
			}
		}()
		input := C.GoBytes(unsafe.Pointer(data), C.int(size))
		if _, err := wire.Parse(input); err == nil {
			code = 0
		}
	}()
	return code
}

func main() {}
