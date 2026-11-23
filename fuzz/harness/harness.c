#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "libdfcodec.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	int result = DFParse((uint8_t *)data, size);
	if (result == 2) {
		abort();
	}
	return 0;
}

