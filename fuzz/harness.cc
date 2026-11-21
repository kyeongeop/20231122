#include <cstddef>
#include <cstdint>

extern "C" int CorpusProbe(uint8_t *data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return CorpusProbe(const_cast<uint8_t *>(data), size);
}
