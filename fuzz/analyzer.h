#pragma once

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "sha256.h"

namespace auditfix {

struct Event {
  int device = 0;
  int64_t seq = 0;
  int64_t time_ns = 0;
  std::string kind;
  std::string anchor_id;
  std::string subject;
  std::string payload;
  std::string prev;
  std::string hash;
};

struct MissingSegment {
  int device = 0;
  int64_t seq_from = 0;
  int64_t seq_to = 0;
  int64_t count = 0;
};

struct Result {
  bool parsed = true;
  bool chain_ok = true;
  bool anchor_mismatch = false;
  int anchor_pairs = 0;
  int64_t clock_offset_ns = 0;
  std::vector<MissingSegment> missing;
  std::vector<std::string> findings;
};

inline std::string lower(std::string value) {
  for (char& c : value) {
    if (c >= 'A' && c <= 'F') {
      c = static_cast<char>(c - 'A' + 'a');
    }
  }
  return value;
}

inline bool validHex64(const std::string& value) {
  if (value.size() != 64) {
    return false;
  }
  for (char c : value) {
    const bool digit = c >= '0' && c <= '9';
    const bool lower_hex = c >= 'a' && c <= 'f';
    const bool upper_hex = c >= 'A' && c <= 'F';
    if (!digit && !lower_hex && !upper_hex) {
      return false;
    }
  }
  return true;
}

inline bool parsePositive(std::string_view value, int64_t& out) {
  uint64_t parsed = 0;
  const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
  if (result.ec != std::errc() || result.ptr != value.data() + value.size() ||
      parsed == 0 || parsed > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
    return false;
  }
  out = static_cast<int64_t>(parsed);
  return true;
}

inline std::vector<std::string_view> splitTabs(std::string_view line) {
  std::vector<std::string_view> fields;
  size_t start = 0;
  while (true) {
    const size_t tab = line.find('\t', start);
    if (tab == std::string_view::npos) {
      fields.push_back(line.substr(start));
      break;
    }
    fields.push_back(line.substr(start, tab - start));
    start = tab + 1;
  }
  return fields;
}

inline std::string eventDigest(const Event& event) {
  std::string canonical = "AFX-AUDIT-1\n";
  canonical += (event.device == 0 ? "device-a\n" : "device-b\n");
  canonical += std::to_string(event.seq) + "\n";
  canonical += std::to_string(event.time_ns) + "\n";
  canonical += event.kind + "\n";
  canonical += event.anchor_id + "\n";
  canonical += event.subject + "\n";
  canonical += event.payload + "\n";
  canonical += event.prev + "\n";
  return sha256Hex(canonical);
}

inline bool parseEvent(std::string_view line, Event& event) {
  const auto fields = splitTabs(line);
  if (fields.size() != 10 || fields[0] != "D") {
    return false;
  }
  if (fields[1] == "a") {
    event.device = 0;
  } else if (fields[1] == "b") {
    event.device = 1;
  } else {
    return false;
  }
  if (!parsePositive(fields[2], event.seq) || !parsePositive(fields[3], event.time_ns)) {
    return false;
  }
  event.kind = std::string(fields[4]);
  if (event.kind != "anchor" && event.kind != "operation" &&
      event.kind != "heartbeat") {
    return false;
  }
  event.anchor_id = std::string(fields[5]);
  event.subject = std::string(fields[6]);
  if (event.subject.empty() || (event.kind == "anchor" && event.anchor_id.empty())) {
    return false;
  }
  event.payload = lower(std::string(fields[7]));
  event.prev = lower(std::string(fields[8]));
  event.hash = lower(std::string(fields[9]));
  return validHex64(event.payload) && validHex64(event.prev) && validHex64(event.hash);
}

inline int64_t median(std::vector<int64_t> values) {
  if (values.empty()) {
    return 0;
  }
  std::sort(values.begin(), values.end());
  const size_t middle = values.size() / 2;
  if (values.size() % 2 == 1) {
    return values[middle];
  }
  const int64_t low = values[middle - 1];
  const int64_t high = values[middle];
  return static_cast<int64_t>((static_cast<__int128>(low) + high) / 2);
}

inline bool absBeyond(int64_t value, int64_t limit) {
  return value > limit || value < -limit;
}

inline Result analyze(std::string_view input) {
  Result result;
  if (input.size() > 1024U * 1024U || input.size() < 6U ||
      input.substr(0, 5) != "AFXS1") {
    result.parsed = false;
    return result;
  }
  size_t offset = 5;
  if (input[offset] == '\r') {
    ++offset;
  }
  if (offset >= input.size() || input[offset] != '\n') {
    result.parsed = false;
    return result;
  }
  ++offset;

  std::vector<Event> events;
  while (offset < input.size()) {
    const size_t newline = input.find('\n', offset);
    std::string_view line = input.substr(
        offset, newline == std::string_view::npos ? input.size() - offset
                                                  : newline - offset);
    offset = newline == std::string_view::npos ? input.size() : newline + 1;
    if (!line.empty() && line.back() == '\r') {
      line.remove_suffix(1);
    }
    if (line.empty()) {
      if (offset >= input.size()) {
        break;
      }
      result.parsed = false;
      return result;
    }
    if (line.size() > 16384U || events.size() >= 4096U) {
      result.parsed = false;
      return result;
    }
    Event event;
    if (!parseEvent(line, event)) {
      result.parsed = false;
      return result;
    }
    events.push_back(std::move(event));
  }
  if (events.empty()) {
    result.parsed = false;
    return result;
  }

  std::array<bool, 2> has_previous{false, false};
  std::array<Event, 2> previous{};
  for (const Event& event : events) {
    if (eventDigest(event) != event.hash) {
      result.chain_ok = false;
      continue;
    }
    const int device = event.device;
    if (!has_previous[device]) {
      has_previous[device] = true;
      previous[device] = event;
      continue;
    }
    const Event& prior = previous[device];
    if (event.seq <= prior.seq) {
      result.chain_ok = false;
    } else if (event.seq == prior.seq + 1) {
      if (event.prev != prior.hash) {
        result.chain_ok = false;
      }
    } else {
      if (event.prev != prior.hash) {
        result.chain_ok = false;
      }
      result.missing.push_back(MissingSegment{
          device, prior.seq + 1, event.seq - 1, event.seq - prior.seq - 1});
    }
    previous[device] = event;
  }

  std::unordered_map<std::string, std::vector<size_t>> anchors_a;
  std::unordered_map<std::string, std::vector<size_t>> anchors_b;
  for (size_t i = 0; i < events.size(); ++i) {
    if (events[i].kind != "anchor") {
      continue;
    }
    if (events[i].device == 0) {
      anchors_a[events[i].anchor_id].push_back(i);
    } else {
      anchors_b[events[i].anchor_id].push_back(i);
    }
  }
  std::vector<int64_t> offsets;
  for (const auto& [id, a_indices] : anchors_a) {
    const auto found = anchors_b.find(id);
    if (found == anchors_b.end()) {
      continue;
    }
    const auto& b_indices = found->second;
    const size_t count = std::min(a_indices.size(), b_indices.size());
    for (size_t i = 0; i < count; ++i) {
      const Event& a = events[a_indices[i]];
      const Event& b = events[b_indices[i]];
      if (a.subject != b.subject || a.payload != b.payload) {
        result.anchor_mismatch = true;
        continue;
      }
      ++result.anchor_pairs;
      offsets.push_back(b.time_ns - a.time_ns);
    }
  }
  result.clock_offset_ns = median(offsets);

  std::sort(result.missing.begin(), result.missing.end(),
            [](const MissingSegment& left, const MissingSegment& right) {
              if (left.device != right.device) {
                return left.device < right.device;
              }
              return left.seq_from < right.seq_from;
            });
  if (!result.chain_ok) {
    result.findings.push_back("CHAIN_BREAK");
  }
  if (result.anchor_mismatch) {
    result.findings.push_back("ANCHOR_MISMATCH");
  }
  if (!result.missing.empty()) {
    result.findings.push_back("MISSING_SEGMENT");
  }
  if (absBeyond(result.clock_offset_ns, 1000000)) {
    result.findings.push_back("CLOCK_SKEW");
  }
  return result;
}

inline void emitResult(const Result& result) {
  std::cout << "AUDITFIX_RESULT {\"schema\":\"auditfix.harness.v1\",\"verdict\":\"";
  if (!result.parsed) {
    std::cout << "MALFORMED\",\"classification\":\"MALFORMED\",\"chain_ok\":false,"
                 "\"anchor_pairs\":0,\"clock_offset_ns\":0,"
                 "\"findings\":[\"MALFORMED\"],\"missing_segments\":[]}\n";
    return;
  }
  const std::string classification =
      result.findings.empty() ? "OK" : result.findings.front();
  std::cout << (result.findings.empty() ? "PASS" : "FINDINGS") << "\",\"classification\":\""
            << classification << "\",\"chain_ok\":"
            << (result.chain_ok ? "true" : "false")
            << ",\"anchor_pairs\":" << result.anchor_pairs
            << ",\"clock_offset_ns\":" << result.clock_offset_ns
            << ",\"findings\":[";
  for (size_t i = 0; i < result.findings.size(); ++i) {
    if (i != 0) {
      std::cout << ',';
    }
    std::cout << '"' << result.findings[i] << '"';
  }
  std::cout << "],\"missing_segments\":[";
  for (size_t i = 0; i < result.missing.size(); ++i) {
    if (i != 0) {
      std::cout << ',';
    }
    const MissingSegment& segment = result.missing[i];
    std::cout << "{\"device\":\""
              << (segment.device == 0 ? "device-a" : "device-b")
              << "\",\"seq_from\":" << segment.seq_from
              << ",\"seq_to\":" << segment.seq_to
              << ",\"count\":" << segment.count << '}';
  }
  std::cout << "]}\n";
}

}  // namespace auditfix
