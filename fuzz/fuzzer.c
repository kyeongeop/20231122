// libFuzzer harness: feeds arbitrary bytes into the Go checker pipeline.
#include <stdint.h>
#include <stddef.h>

extern int FuzzClassify(char *data, int size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 1 << 20) {
        return 0; // skip pathological inputs
    }
    FuzzClassify((char *)data, (int)size);
    return 0;
}
