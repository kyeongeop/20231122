typedef __SIZE_TYPE__ size_t;
typedef unsigned char uint8_t;

extern int PathAliasFuzzOneInput(const uint8_t *data, size_t size);
extern void abort(void);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (PathAliasFuzzOneInput(data, size) != 0) {
    abort();
  }
  return 0;
}
