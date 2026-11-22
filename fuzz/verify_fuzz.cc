#include <cstddef>
#include <cstdint>

#include "libverify.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 64 * 1024) {
    return 0;
  }
  GoVerifyWebhook(const_cast<uint8_t *>(data), size);
  return 0;
}
