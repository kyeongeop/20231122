#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH_CAP 512
#define SEG_CAP 96

struct segment {
  const char *at;
  size_t len;
};

static int decode_once(const char *raw, char *out, size_t cap) {
  size_t read = 0;
  size_t write = 0;
  while (raw[read] != '\0') {
    if (raw[read] == '%' && raw[read + 1] != '\0' && raw[read + 2] != '\0') {
      int hi = raw[read + 1];
      int lo = raw[read + 2];
      int dh = (hi >= '0' && hi <= '9') ? hi - '0'
               : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10
               : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
      int dl = (lo >= '0' && lo <= '9') ? lo - '0'
               : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10
               : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
      if (dh >= 0 && dl >= 0) {
        if (write + 1 >= cap) return -1;
        out[write++] = (char)((dh << 4) | dl);
        read += 3;
        continue;
      }
    }
    if (write + 1 >= cap) return -1;
    out[write++] = raw[read++];
  }
  out[write] = '\0';
  return 0;
}

static int split_path(const char *value, struct segment *segments, int capacity) {
  int count = 0;
  const char *start = value;
  for (const char *cursor = value;; cursor++) {
    if (*cursor == '/' || *cursor == '\0') {
      if (cursor > start) {
        if (count >= capacity) return -1;
        segments[count].at = start;
        segments[count].len = (size_t)(cursor - start);
        count++;
      }
      if (*cursor == '\0') break;
      start = cursor + 1;
    }
  }
  return count;
}

static int normalize(const char *input, const char *root, int clamp_root,
                     char *out, size_t cap) {
  struct segment input_segments[SEG_CAP];
  struct segment root_segments[SEG_CAP];
  int input_count = split_path(input, input_segments, SEG_CAP);
  int root_count = split_path(root, root_segments, SEG_CAP);
  if (input_count < 0 || root_count < 0) return -1;

  int start = 0;
  int stack = 0;
  char stack_data[SEG_CAP][128];
  if (clamp_root && root_count > 0) {
    if (input_count < root_count) return -1;
    for (int i = 0; i < root_count; i++) {
      if (input_segments[i].len != root_segments[i].len ||
          memcmp(input_segments[i].at, root_segments[i].at, input_segments[i].len) != 0) {
        return -1;
      }
      if (input_segments[i].len >= sizeof(stack_data[0])) return -1;
      memcpy(stack_data[stack], input_segments[i].at, input_segments[i].len);
      stack_data[stack][input_segments[i].len] = '\0';
      stack++;
    }
    start = root_count;
  }

  for (int i = start; i < input_count; i++) {
    struct segment segment = input_segments[i];
    if (segment.len == 1 && segment.at[0] == '.') continue;
    if (segment.len == 2 && segment.at[0] == '.' && segment.at[1] == '.') {
      if (stack > (clamp_root ? root_count : 0)) {
        stack--;
      } else if (!clamp_root && stack > 0) {
        stack--;
      }
      continue;
    }
    if (segment.len >= sizeof(stack_data[0])) return -1;
    memcpy(stack_data[stack], segment.at, segment.len);
    stack_data[stack][segment.len] = '\0';
    stack++;
  }

  size_t write = 0;
  for (int i = 0; i < stack; i++) {
    size_t size = strlen(stack_data[i]);
    if (write + size + 2 >= cap) return -1;
    out[write++] = '/';
    memcpy(out + write, stack_data[i], size);
    write += size;
  }
  if (write == 0) out[write++] = '/';
  out[write] = '\0';
  return 0;
}

static const char *extension_of(const char *path) {
  const char *slash = strrchr(path, '/');
  const char *dot = strrchr(path, '.');
  if (dot == NULL || (slash != NULL && dot < slash)) return "";
  return dot;
}

static int registered_extension(const char *extension) {
  static const char *known[] = {".png", ".jpg", ".jpeg", ".pdf", ".txt"};
  for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
    if (strcmp(extension, known[i]) == 0) return 1;
  }
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8 || size >= PATH_CAP) return 0;
  if (memchr(data, '\0', size) != NULL) return 0;

  char raw[PATH_CAP];
  memcpy(raw, data, size);
  while (size > 0 && (raw[size - 1] == '\n' || raw[size - 1] == '\r')) size--;
  raw[size] = '\0';

  char decoded[PATH_CAP];
  char legacy[PATH_CAP];
  char hardened[PATH_CAP];
  if (decode_once(raw, decoded, sizeof(decoded)) != 0) return 0;
  if (normalize(decoded, "/srv/www", 0, legacy, sizeof(legacy)) != 0) return 0;
  if (normalize(decoded, "/srv/www", 1, hardened, sizeof(hardened)) != 0) return 0;

  const char *extension = extension_of(legacy);
  if (strcmp(legacy, hardened) != 0 && !registered_extension(extension)) {
    fprintf(stderr,
            "PATH_CANON_DIVERGENCE\nraw=%s\ndecoded=%s\nlegacy=%s\n"
            "hardened=%s\nextension=%s registered=false\n",
            raw, decoded, legacy, hardened, extension);
    fflush(stderr);
    __builtin_trap();
  }
  return 0;
}

#ifdef PATHNORM_STANDALONE
int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <corpus-file>\n", argv[0]);
    return 2;
  }
  FILE *file = fopen(argv[1], "rb");
  if (file == NULL) {
    perror("open corpus");
    return 2;
  }
  uint8_t buffer[PATH_CAP];
  size_t size = fread(buffer, 1, sizeof(buffer), file);
  fclose(file);
  return LLVMFuzzerTestOneInput(buffer, size);
}
#endif
