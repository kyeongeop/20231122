#include <cstddef>
#include <cstdint>

#include "libmtafuzz.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size > (1u << 20)) {
    return 0;
  }
  MTAFuzz(const_cast<uint8_t *>(data), size);
  return 0;
}
