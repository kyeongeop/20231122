#include <stdint.h>
#include <stddef.h>

extern int FuzzOne(uint8_t *data, int n);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 4096) {
        return 0;
    }
    FuzzOne((uint8_t *)data, (int)size);
    return 0;
}
