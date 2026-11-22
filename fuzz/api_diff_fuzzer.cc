#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr size_t kSampleSize = 24;
constexpr char kMagic[] = "ASK1";

struct Scenario {
  uint32_t revision_a;
  uint32_t revision_b;
  int64_t updated_a;
  int64_t updated_b;
  uint8_t acl_a;
  uint8_t acl_b;
  bool deleted_a;
  bool deleted_b;
};

uint64_t env_u64(const char *name, uint64_t fallback) {
  const char *raw = std::getenv(name);
  if (raw == nullptr || *raw == '\0') {
    return fallback;
  }
  char *end = nullptr;
  errno = 0;
  unsigned long long value = std::strtoull(raw, &end, 10);
  if (errno != 0 || end == raw) {
    return fallback;
  }
  return static_cast<uint64_t>(value);
}

int64_t env_i64(const char *name, int64_t fallback) {
  const char *raw = std::getenv(name);
  if (raw == nullptr || *raw == '\0') {
    return fallback;
  }
  char *end = nullptr;
  errno = 0;
  long long value = std::strtoll(raw, &end, 10);
  if (errno != 0 || end == raw) {
    return fallback;
  }
  return static_cast<int64_t>(value);
}

const Scenario &scenario() {
  static const Scenario value = {
      static_cast<uint32_t>(env_u64("APISKEW_REV_A", 7)),
      static_cast<uint32_t>(env_u64("APISKEW_REV_B", 5)),
      env_i64("APISKEW_UPDATED_A", 1700000003000LL),
      env_i64("APISKEW_UPDATED_B", 1700000003000LL),
      static_cast<uint8_t>(env_u64("APISKEW_ACL_A", 7)),
      static_cast<uint8_t>(env_u64("APISKEW_ACL_B", 7)),
      env_u64("APISKEW_DELETED_A", 0) != 0,
      env_u64("APISKEW_DELETED_B", 1) != 0,
  };
  return value;
}

size_t max_findings() {
  static const size_t value =
      static_cast<size_t>(env_u64("APISKEW_MAX_FINDINGS", 5000));
  return value;
}

int32_t read_i32(const uint8_t *data) {
  return static_cast<int32_t>(
      static_cast<uint32_t>(data[0]) |
      (static_cast<uint32_t>(data[1]) << 8) |
      (static_cast<uint32_t>(data[2]) << 16) |
      (static_cast<uint32_t>(data[3]) << 24));
}

uint8_t effective_acl(uint8_t role, uint8_t acl) {
  switch (role) {
  case 0:
    return 7;
  case 1:
    return acl;
  case 2:
    return static_cast<uint8_t>(acl & 1);
  default:
    return 0;
  }
}

bool allowed(const Scenario &s, uint8_t role, uint8_t action, bool tenant_match,
             bool replica_b) {
  const bool deleted = replica_b ? s.deleted_b : s.deleted_a;
  const uint8_t acl = replica_b ? s.acl_b : s.acl_a;
  if (!tenant_match || role > 2 || deleted) {
    return false;
  }
  const uint8_t permission = static_cast<uint8_t>(1U << action);
  return (effective_acl(role, acl) & permission) != 0;
}

bool differs(const uint8_t *data, size_t size) {
  if (size != kSampleSize || std::memcmp(data, kMagic, 4) != 0 ||
      data[4] != 1 || data[5] > 3 || data[6] > 2) {
    return false;
  }
  const Scenario &s = scenario();
  const int32_t skew_a = read_i32(data + 8);
  const int32_t skew_b = read_i32(data + 12);
  const bool tenant_match = (data[7] & 1U) != 0;
  const uint8_t role = data[5];
  const uint8_t action = data[6];

  const int64_t local_a = s.updated_a + static_cast<int64_t>(skew_a);
  const int64_t local_b = s.updated_b + static_cast<int64_t>(skew_b);
  const bool v1_b = local_b > local_a;

  bool v2_b = false;
  if (s.revision_b > s.revision_a) {
    v2_b = true;
  } else if (s.revision_b == s.revision_a && s.updated_b > s.updated_a) {
    v2_b = true;
  }

  return allowed(s, role, action, tenant_match, v1_b) !=
         allowed(s, role, action, tenant_match, v2_b);
}

uint64_t fnv1a(const uint8_t *data, size_t size) {
  uint64_t hash = 1469598103934665603ULL;
  for (size_t i = 0; i < size; ++i) {
    hash ^= data[i];
    hash *= 1099511628211ULL;
  }
  return hash;
}

void persist(const uint8_t *data, size_t size) {
  static size_t persisted = 0;
  if (persisted >= max_findings()) {
    return;
  }
  const char *dir = std::getenv("APISKEW_FINDINGS");
  if (dir == nullptr || *dir == '\0') {
    return;
  }
  char name[64];
  std::snprintf(name, sizeof(name), "/finding-%016llx.bin",
                static_cast<unsigned long long>(fnv1a(data, size)));
  std::string path(dir);
  path += name;
  int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
  if (fd < 0) {
    return;
  }
  ++persisted;
  size_t written = 0;
  while (written < size) {
    ssize_t count = ::write(fd, data + written, size - written);
    if (count <= 0) {
      break;
    }
    written += static_cast<size_t>(count);
  }
  ::close(fd);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (differs(data, size)) {
    persist(data, size);
  }
  return 0;
}
