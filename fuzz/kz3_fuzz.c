#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t be16(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static uint32_t be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 29 || memcmp(data, "RZ31", 4) != 0) {
    return 0;
  }
  if (be32(data + 6) != (uint32_t)size || be16(data + 14) != 1) {
    return 0;
  }
  if (be32(data + 16) > size - 16) {
    return 0;
  }

  uint8_t extension = data[20];
  uint32_t extension_len = be32(data + 21);
  if (extension_len > size - 29) {
    return 0;
  }
  size_t payload = 29 + (size_t)extension_len;

  if (extension == 0x7e && extension_len == 12) {
    volatile uint8_t sink = data[payload];
    sink = data[size];
    (void)sink;
  }
  return 0;
}

#ifdef STANDALONE_REPLAY
int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <sample.kz3>\n", argv[0]);
    return 2;
  }
  FILE *file = fopen(argv[1], "rb");
  if (file == NULL) {
    perror("fopen");
    return 2;
  }
  if (fseek(file, 0, SEEK_END) != 0) {
    return 2;
  }
  long length = ftell(file);
  if (length < 0 || fseek(file, 0, SEEK_SET) != 0) {
    return 2;
  }
  uint8_t *data = malloc((size_t)length);
  if (data == NULL) {
    return 2;
  }
  if (fread(data, 1, (size_t)length, file) != (size_t)length) {
    return 2;
  }
  fclose(file);
  int result = LLVMFuzzerTestOneInput(data, (size_t)length);
  free(data);
  return result;
}
#endif
