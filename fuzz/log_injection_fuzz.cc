#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

namespace {

bool ascii_iequal(std::string_view value, std::string_view needle, size_t at) {
  if (at + needle.size() > value.size()) return false;
  for (size_t i = 0; i < needle.size(); ++i) {
    const auto a = static_cast<unsigned char>(value[at + i]);
    const auto b = static_cast<unsigned char>(needle[i]);
    if (std::tolower(a) != std::tolower(b)) return false;
  }
  return true;
}

size_t count_encoded_crlf(std::string_view input) {
  size_t count = 0;
  for (size_t i = 0; i + 6 <= input.size(); ++i) {
    if (ascii_iequal(input, "%0d%0a", i)) {
      ++count;
      i += 5;
    }
  }
  return count;
}

std::string normalize(std::string_view input) {
  std::string out;
  out.reserve(input.size());
  for (size_t i = 0; i < input.size();) {
    if (i + 6 <= input.size() && ascii_iequal(input, "%0d%0a", i)) {
      out.append("\r\n");
      i += 6;
    } else if (i + 3 <= input.size() && ascii_iequal(input, "%0a", i)) {
      out.push_back('\n');
      i += 3;
    } else if (i + 3 <= input.size() && ascii_iequal(input, "%0d", i)) {
      out.push_back('\r');
      i += 3;
    } else {
      out.push_back(input[i]);
      ++i;
    }
  }
  return out;
}

size_t line_count(std::string_view value) {
  size_t lines = 1;
  for (size_t i = 0; i < value.size(); ++i) {
    if (value[i] == '\n') ++lines;
    if (value[i] == '\r' && (i + 1 == value.size() || value[i + 1] != '\n')) {
      ++lines;
    }
  }
  return lines;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0 || size > 4096) return 0;
  const std::string_view input(reinterpret_cast<const char*>(data), size);

  const size_t encoded = count_encoded_crlf(input);
  if (encoded == 0) return 0;

  const std::string decoded = normalize(input);
  if (decoded.find('\n') == std::string::npos &&
      decoded.find('\r') == std::string::npos) {
    std::abort();
  }

  // Every decoded CRLF must introduce a new physical line. This catches
  // normalization implementations that collapse or overwrite boundary bytes.
  if (line_count(decoded) < encoded + 1) {
    std::abort();
  }
  return 0;
}
