#include <cstddef>
#include <cstdint>
#include <string_view>

#include "analyzer.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::string_view input(reinterpret_cast<const char*>(data), size);
  auditfix::emitResult(auditfix::analyze(input));
  return 0;
}
