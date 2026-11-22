#include <cstddef>
#include <cstdint>

#include "libpolicy_bridge.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (data == nullptr || size == 0 || size > (1U << 20)) {
    return 0;
  }
  const int state = CrossDomainAuditFuzz(const_cast<unsigned char *>(data), size);
  // Go does not expose its runtime coverage counters to the C++ harness.
  // Partition the analyzer result so libFuzzer can keep inputs that reach
  // new state combinations (pass/fail/undecided/first-error/boundary).
  static volatile int observation = 0;
  switch (state & 0x0f) {
    case 0: observation ^= 1; break;
    case 1: observation ^= 2; break;
    case 2: observation ^= 4; break;
    case 3: observation ^= 8; break;
    case 4: observation ^= 16; break;
    case 5: observation ^= 32; break;
    case 6: observation ^= 64; break;
    case 7: observation ^= 128; break;
    default: observation ^= 256; break;
  }
  if (state & (1 << 6)) observation += 1;
  if (state & (1 << 7)) observation += 2;
  if (state & (1 << 8)) observation += 4;
  if (state & (1 << 9)) observation += 8;
  if (state & (1 << 10)) observation += 16;
  if (state & (1 << 14)) observation += 32;
  if (state & (1 << 18)) observation += 64;
  return 0;
}
