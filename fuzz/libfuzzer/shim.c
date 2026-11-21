//go:build libfuzzer

#include <stdint.h>
#include <stddef.h>

extern int fuzzEntryGo(unsigned char* data, long long length);

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	return fuzzEntryGo((unsigned char*)data, (long long)size);
}
