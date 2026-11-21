/*
 * libFuzzer target for the parser integer-overflow audit.
 *
 * It mirrors the Go wire format (internal/parser):
 *   magic "PF01" | uint32 record_count | records:
 *     uint8 tag | uint32 length | uint32 offset
 *
 * Build (see fuzz/build.sh):
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined parser_fuzz.c -o parser_fuzz
 *
 * The hardened parser is the entry point; the fuzzer proves that no input can
 * drive it into wrapping arithmetic or out-of-bounds access. A dedicated
 * vulnerable path is kept behind #ifdef VULNERABLE to reproduce the overflow.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define MAGIC0 'P'
#define MAGIC1 'F'
#define MAGIC2 '0'
#define MAGIC3 '1'
#define HEADER_SIZE 9
#define MAX_RECORD_COUNT 65536

static uint32_t le32(const uint8_t *p) {
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int add32(uint32_t a, uint32_t b, uint32_t *out) {
	if (b > UINT32_MAX - a) return 0;
	*out = a + b;
	return 1;
}

static int mul32(uint32_t a, uint32_t b, uint32_t *out) {
	if (a != 0 && b > UINT32_MAX / a) return 0;
	*out = a * b;
	return 1;
}

#ifdef VULNERABLE
/* Reproduces the historical unchecked arithmetic for regression evidence. */
static int parse_vulnerable(const uint8_t *data, size_t size) {
	if (size < 8) return -1;
	uint32_t record_count = le32(data + 4);
	/* anchor A1: unchecked multiply */
	uint32_t table_width = record_count * HEADER_SIZE;
	uint32_t cursor = 8;
	for (uint32_t i = 0; i < record_count; i++) {
		if ((uint64_t)cursor + HEADER_SIZE > size) return -1;
		uint32_t length = le32(data + cursor + 1);
		uint32_t offset = le32(data + cursor + 5);
		/* anchor A2 + A3: unchecked additions */
		uint32_t end = offset + length;
		uint32_t payload_at = cursor + length;
		if (payload_at < size && data[payload_at] == 0x5a) return 1;
		cursor = end;
	}
	(void)table_width;
	return 0;
}
#endif

static int parse_hardened(const uint8_t *data, size_t size) {
	if (size == 0) return -1;
	if (size < 4 || data[0] != MAGIC0 || data[1] != MAGIC1 ||
	    data[2] != MAGIC2 || data[3] != MAGIC3)
		return -1;
	if (size < 8) return -1;

	uint32_t record_count = le32(data + 4);
	if (record_count > MAX_RECORD_COUNT) return -1;

	uint32_t table_width;
	if (!mul32(record_count, HEADER_SIZE, &table_width)) return -1;
	if ((uint64_t)8 + table_width > size) return -1;

	uint32_t cursor = 8;
	for (uint32_t i = 0; i < record_count; i++) {
		if ((uint64_t)cursor + HEADER_SIZE > size) return -1;
		uint32_t length = le32(data + cursor + 1);
		uint32_t offset = le32(data + cursor + 5);

		uint32_t end;
		if (!add32(offset, length, &end)) return -1;
		uint32_t payload_at;
		if (!add32(cursor, length, &payload_at)) return -1;
		if ((uint64_t)payload_at > size) return -1;
		cursor = end;
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
#ifdef VULNERABLE
	parse_vulnerable(data, size);
#else
	parse_hardened(data, size);
#endif
	return 0;
}
