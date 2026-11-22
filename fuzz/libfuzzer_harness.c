// libFuzzer entry point for the truncstream parser. It is compiled with
// clang -fsanitize=fuzzer and linked against the cgo archive produced by
// `go build -buildmode=c-archive`; every mutation therefore executes the
// real Go stream.Parse code path.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libbridge.h"

// Documented error classes mirrored from fuzz/bridge/bridge.go.
enum {
	CLASS_NONE = 0,
	CLASS_MAGIC = 1,
	CLASS_HEADER = 2,
	CLASS_LENGTH = 3,
	CLASS_CHECKSUM = 4,
	CLASS_COMPRESSION = 5,
	CLASS_ENCODING = 6,
	CLASS_UNKNOWN_TYPE = 7
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	int cls = TSTParse((const char *)data, (size_t)size);

	// Invariant: the bridge may only return documented class codes. Any
	// other value indicates a broken contract and fails the fuzz run.
	if (cls < CLASS_NONE || cls > CLASS_UNKNOWN_TYPE) {
		__builtin_trap();
	}

	// The documented magic prefix must always classify as BAD_MAGIC rather
	// than drifting into an arbitrary class.
	if (size >= 4 && memcmp(data, "TST1", 4) == 0 && cls == CLASS_MAGIC) {
		__builtin_trap();
	}
	if (size >= 4 && memcmp(data, "XXXX", 4) == 0 && cls != CLASS_MAGIC) {
		__builtin_trap();
	}
	return 0;
}
