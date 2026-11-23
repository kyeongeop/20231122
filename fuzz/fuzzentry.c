#include <stdint.h>
#include <stddef.h>

int Fuzz(char *data, int size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* 覆盖探测点：区分 JSON 封装 / form 编码 / 裸字节，
     引导 libFuzzer 在三种输入形态间变异。真正的解析与不变量检查在 Go 侧。 */
  if (size > 0) {
    int has_brace = 0, has_amp = 0, has_nul = 0;
    for (size_t i = 0; i < size && i < 4096; i++) {
      if (data[i] == '{') has_brace = 1;
      if (data[i] == '&') has_amp = 1;
      if (data[i] == 0) has_nul = 1;
    }
    if (has_brace && has_amp) {
      volatile int sink = has_brace + has_amp;
      (void)sink;
    } else if (has_brace) {
      volatile int sink = has_brace;
      (void)sink;
    } else if (has_amp) {
      volatile int sink = has_amp;
      (void)sink;
    } else if (has_nul) {
      volatile int sink = has_nul;
      (void)sink;
    }
  }
	return Fuzz((char *)data, (int)size);
}
