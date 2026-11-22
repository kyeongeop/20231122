#include <cstdint>
#include <cstdio>
#include <map>
#include <string>

namespace {

struct Entry {
  std::string snapshot;
  std::string body;
};

class StaticCache {
 public:
  Entry Fetch(const std::string& key, const std::string& snapshot,
              const std::string& body) {
    auto found = entries_.find(key);
    if (found != entries_.end()) {
      return found->second;
    }
    Entry entry{snapshot, body};
    entries_[key] = entry;
    return entry;
  }

 private:
  std::map<std::string, Entry> entries_;
};

std::string Route(const uint8_t* data, size_t size) {
  std::string route = "/static/";
  for (size_t index = 0; index < size && route.size() < 48; ++index) {
    const uint8_t byte = data[index];
    if ((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') ||
        byte == '-' || byte == '_') {
      route.push_back(static_cast<char>(byte));
    } else {
      route.push_back('x');
    }
  }
  if (route.size() == 8) {
    route += "probe";
  }
  route += ".q7x";
  return route;
}

std::string Body(const char* version, const uint8_t* data, size_t size) {
  std::string body(version);
  body += ":";
  for (size_t index = 0; index < size; ++index) {
    static const char kHex[] = "0123456789abcdef";
    body.push_back(kHex[data[index] >> 4]);
    body.push_back(kHex[data[index] & 0x0f]);
  }
  return body;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) {
    return 0;
  }
  const std::string key = Route(data, size);
  const std::string body_v1 = Body("snap-v1", data, size);
  const std::string body_v2 = Body("snap-v2", data, size);
  StaticCache cache;
  const Entry first = cache.Fetch(key, "snap-v1", body_v1);
  const Entry second = cache.Fetch(key, "snap-v2", body_v2);
  if (first.snapshot != "snap-v1" || first.body != body_v1 ||
      second.snapshot != "snap-v2" || second.body != body_v2) {
    std::fprintf(stderr,
                 "CACHELEAK_ASSERT: key=%s first=%s second=%s "
                 "version-omitted-from-cache-key\n",
                 key.c_str(), first.snapshot.c_str(), second.snapshot.c_str());
    __builtin_trap();
  }
  return 0;
}
