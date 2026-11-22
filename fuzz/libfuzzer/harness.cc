// libFuzzer entry point. The Go core is built as a c-shared library; this
// harness only forwards each input byte string to the exported C function.
#include <stddef.h>
#include <stdint.h>

#include "librrfuzz.h"

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  RRFuzzInit();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  RRFuzzRun(reinterpret_cast<unsigned char *>(const_cast<uint8_t *>(data)),
            static_cast<size_t>(size));
  return 0;
}
