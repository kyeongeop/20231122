//go:build libfuzzer

// libfuzzer build tag bridges C LLVMFuzzerTestOneInput to the Go parser.
// Build via the Makefile target, which supplies clang's libFuzzer runtime.
package main

/*
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Provided by shim.c, linked from the same package directory.
extern int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

// Go-exported entry point invoked by the C shim.
extern int fuzzEntryGo(unsigned char* data, long long length);

// Driver entry from libclang_rt.fuzzer_no_main.a: it runs the fuzz loop and
// calls LLVMFuzzerTestOneInput for every generated input.
int LLVMFuzzerRunDriver(int* argc, char*** argv,
	int (*user_cb)(const uint8_t*, size_t));

// Build a fresh argv from the Go side so corpus dirs / flags passed to the
// binary reach libFuzzer unchanged. Owned memory is freed after the driver
// returns (normally only on -runs=N or timeout shutdown).
static int run_driver(int go_argc, char** go_argv) {
	char** argv = (char**)calloc((size_t)go_argc + 1, sizeof(char*));
	for (int i = 0; i < go_argc; i++) {
		argv[i] = (char*)malloc(strlen(go_argv[i]) + 1);
		memcpy(argv[i], go_argv[i], strlen(go_argv[i]) + 1);
	}
	int argc = go_argc;
	int rc = LLVMFuzzerRunDriver(&argc, &argv, LLVMFuzzerTestOneInput);
	for (int i = 0; i < go_argc; i++) {
		free(argv[i]);
	}
	free(argv);
	return rc;
}

// The fuzzer_no_main archive is supplied through CGO_LDFLAGS so the build
// stays portable across clang installation layouts.
#cgo LDFLAGS: -lstdc++
*/
import "C"

import (
	"os"
	"unsafe"

	"lfireview/internal/fuzzshim"
)

//export fuzzEntryGo
func fuzzEntryGo(data *C.uchar, length C.longlong) C.int {
	var goData []byte
	if length > 0 {
		goData = unsafe.Slice((*byte)(unsafe.Pointer(data)), int(length))
	}
	return C.int(fuzzshim.Entry(goData))
}

// main hands process control to libFuzzer's driver. The fuzzer runtime used
// here is fuzzer_no_main (no own main), so the Go-generated main is the entry.
func main() {
	argv := make([]*C.char, 0, len(os.Args))
	for _, arg := range os.Args {
		argv = append(argv, C.CString(arg))
	}
	if rc := C.run_driver(C.int(len(argv)), (**C.char)(unsafe.Pointer(&argv[0]))); rc != 0 {
		panic("libFuzzer driver returned non-zero")
	}
}
