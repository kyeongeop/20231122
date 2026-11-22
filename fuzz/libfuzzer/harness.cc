#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "libmigrationfuzz.h"

static volatile unsigned long semantic_sink = 0;

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  const char *path = std::getenv("MIGRATION_POLICY");
  if (path == nullptr) {
    path = "config/policy.json";
  }
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    std::fprintf(stderr, "cannot open policy: %s\n", path);
    std::abort();
  }
  std::vector<unsigned char> policy((std::istreambuf_iterator<char>(input)),
                                    std::istreambuf_iterator<char>());
  if (policy.empty() || MFLoadPolicy(policy.data(), policy.size()) != 0) {
    std::fprintf(stderr, "cannot load policy: %s\n", path);
    std::abort();
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int result = MFEvaluate(const_cast<unsigned char *>(data), size);
  if (result < 0) {
    std::fprintf(stderr, "Go invariant failure: %d (size=%zu)\n", result, size);
    std::abort();
  }
  std::uint32_t features = static_cast<std::uint32_t>(result);
  for (int bit = 0; bit < 31; ++bit) {
    if ((features & (1U << bit)) != 0) {
      semantic_sink += static_cast<unsigned long>(bit + 1);
    } else {
      semantic_sink ^= static_cast<unsigned long>(bit + 1);
    }
  }
  std::uint32_t mixed = features * 2654435761U;
  mixed ^= mixed >> 16;
  switch (mixed & 63U) {
#define FEATURE_BUCKET(n) case n: semantic_sink ^= (n + 1) * 131UL; break;
    FEATURE_BUCKET(0) FEATURE_BUCKET(1) FEATURE_BUCKET(2) FEATURE_BUCKET(3)
    FEATURE_BUCKET(4) FEATURE_BUCKET(5) FEATURE_BUCKET(6) FEATURE_BUCKET(7)
    FEATURE_BUCKET(8) FEATURE_BUCKET(9) FEATURE_BUCKET(10) FEATURE_BUCKET(11)
    FEATURE_BUCKET(12) FEATURE_BUCKET(13) FEATURE_BUCKET(14) FEATURE_BUCKET(15)
    FEATURE_BUCKET(16) FEATURE_BUCKET(17) FEATURE_BUCKET(18) FEATURE_BUCKET(19)
    FEATURE_BUCKET(20) FEATURE_BUCKET(21) FEATURE_BUCKET(22) FEATURE_BUCKET(23)
    FEATURE_BUCKET(24) FEATURE_BUCKET(25) FEATURE_BUCKET(26) FEATURE_BUCKET(27)
    FEATURE_BUCKET(28) FEATURE_BUCKET(29) FEATURE_BUCKET(30) FEATURE_BUCKET(31)
    FEATURE_BUCKET(32) FEATURE_BUCKET(33) FEATURE_BUCKET(34) FEATURE_BUCKET(35)
    FEATURE_BUCKET(36) FEATURE_BUCKET(37) FEATURE_BUCKET(38) FEATURE_BUCKET(39)
    FEATURE_BUCKET(40) FEATURE_BUCKET(41) FEATURE_BUCKET(42) FEATURE_BUCKET(43)
    FEATURE_BUCKET(44) FEATURE_BUCKET(45) FEATURE_BUCKET(46) FEATURE_BUCKET(47)
    FEATURE_BUCKET(48) FEATURE_BUCKET(49) FEATURE_BUCKET(50) FEATURE_BUCKET(51)
    FEATURE_BUCKET(52) FEATURE_BUCKET(53) FEATURE_BUCKET(54) FEATURE_BUCKET(55)
    FEATURE_BUCKET(56) FEATURE_BUCKET(57) FEATURE_BUCKET(58) FEATURE_BUCKET(59)
    FEATURE_BUCKET(60) FEATURE_BUCKET(61) FEATURE_BUCKET(62) FEATURE_BUCKET(63)
#undef FEATURE_BUCKET
  }
  return 0;
}
