#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

namespace auditfix {

class Sha256 {
 public:
  Sha256() { reset(); }

  void reset() {
    state_ = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
              0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
    bit_length_ = 0;
    buffer_length_ = 0;
  }

  void update(const void* data, size_t length) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    bit_length_ += static_cast<uint64_t>(length) * 8U;
    while (length > 0) {
      const size_t take = length < (64U - buffer_length_)
                              ? length
                              : (64U - buffer_length_);
      std::memcpy(buffer_ + buffer_length_, bytes, take);
      buffer_length_ += take;
      bytes += take;
      length -= take;
      if (buffer_length_ == 64U) {
        transform(buffer_);
        buffer_length_ = 0;
      }
    }
  }

  void update(const std::string& value) { update(value.data(), value.size()); }

  std::array<uint8_t, 32> finish() {
    const uint64_t original_bits = bit_length_;
    const uint8_t pad = 0x80;
    update(&pad, 1);
    const uint8_t zero = 0;
    while (buffer_length_ != 56U) {
      update(&zero, 1);
    }
    uint8_t length_bytes[8];
    for (int i = 0; i < 8; ++i) {
      length_bytes[7 - i] = static_cast<uint8_t>(original_bits >> (i * 8));
    }
    update(length_bytes, sizeof(length_bytes));
    std::array<uint8_t, 32> digest{};
    for (size_t i = 0; i < state_.size(); ++i) {
      digest[i * 4] = static_cast<uint8_t>(state_[i] >> 24);
      digest[i * 4 + 1] = static_cast<uint8_t>(state_[i] >> 16);
      digest[i * 4 + 2] = static_cast<uint8_t>(state_[i] >> 8);
      digest[i * 4 + 3] = static_cast<uint8_t>(state_[i]);
    }
    return digest;
  }

 private:
  static uint32_t rotr(uint32_t value, uint32_t bits) {
    return (value >> bits) | (value << (32U - bits));
  }

  void transform(const uint8_t* block) {
    static constexpr uint32_t k[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
        0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
        0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
        0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
      w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
             (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
             (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
             static_cast<uint32_t>(block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
      const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^
                          (w[i - 15] >> 3);
      const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^
                          (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (int i = 0; i < 64; ++i) {
      const uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const uint32_t ch = (e & f) ^ ((~e) & g);
      const uint32_t temp1 = h + s1 + ch + k[i] + w[i];
      const uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t temp2 = s0 + maj;
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

  std::array<uint32_t, 8> state_{};
  uint64_t bit_length_ = 0;
  uint8_t buffer_[64]{};
  size_t buffer_length_ = 0;
};

inline std::string hexDigest(const std::array<uint8_t, 32>& digest) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(64);
  for (size_t i = 0; i < digest.size(); ++i) {
    out[i * 2] = kHex[digest[i] >> 4];
    out[i * 2 + 1] = kHex[digest[i] & 0x0f];
  }
  return out;
}

inline std::string sha256Hex(const std::string& value) {
  Sha256 sha;
  sha.update(value);
  return hexDigest(sha.finish());
}

}  // namespace auditfix
