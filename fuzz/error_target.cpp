#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace {

bool contains(std::string_view haystack, std::string_view needle) {
  return haystack.find(needle) != std::string_view::npos;
}

int shape(std::string_view input) {
  if (input.empty() || input.size() > 65536) {
    return 0;
  }
  int score = 0;
  if (contains(input, "authorization") || contains(input, "Authorization")) {
    score += 1;
  }
  if (contains(input, "bearer ") || contains(input, "Bearer ")) {
    score += 2;
  }
  if (contains(input, "password") || contains(input, "passwd") ||
      contains(input, "pwd")) {
    score += 3;
  }
  if (contains(input, "token") || contains(input, "api_key") ||
      contains(input, "client_secret")) {
    score += 3;
  }
  if (contains(input, "://") && contains(input, "@")) {
    score += 4;
  }
  if (contains(input, "-----BEGIN ") && contains(input, "PRIVATE KEY-----")) {
    score += 5;
  }
  if (contains(input, "AKIA") || contains(input, "ghp_") ||
      contains(input, "eyJ")) {
    score += 5;
  }
  if (contains(input, "\n") || contains(input, "\r")) {
    score += 2;
  }
  if (input.find('\0') != std::string_view::npos) {
    score += 7;
  }
  if (score > 4) {
    std::size_t equals = input.find('=');
    std::size_t colon = input.find(':');
    std::size_t quote = input.find('"');
    std::size_t amp = input.find('&');
    if (equals != std::string_view::npos || colon != std::string_view::npos) {
      score += 1;
    }
    if (quote != std::string_view::npos) {
      score += 1;
    }
    if (amp != std::string_view::npos) {
      score += 1;
    }
  }
  if (score > 10) {
    for (char c : input) {
      if (static_cast<unsigned char>(c) >= 0x80) {
        score += 2;
        break;
      }
    }
  }
  return score;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (data == nullptr) {
    return 0;
  }
  std::string_view input(reinterpret_cast<const char *>(data), size);
  int score = shape(input);
  if (score >= 25) {
    volatile int sink = score;
    (void)sink;
  }
  return 0;
}
