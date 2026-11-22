/*
 * libFuzzer harness: feeds arbitrary bytes into the Go DNS name encoding
 * validation pipeline. Inputs up to 64 KiB are exercised; larger inputs are
 * skipped because the Go guard stage rejects them before parsing anyway.
 */
#include <stdint.h>
#include <stddef.h>

extern int FuzzValidate(char *data, int size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > (1u << 16)) {
        return 0;
    }
    FuzzValidate((char *)data, (int)size);
    return 0;
}
