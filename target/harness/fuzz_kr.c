#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "kr_parser.h"

#ifdef KR_REPLAY_EXIT
#include <stdio.h>
#endif

/*
 * libFuzzer entry point. Two builds are produced from this single source:
 *
 *   kr_fuzz_vuln  - vulnerable parser (key-rotation failure present)
 *   kr_fuzz_fixed - localized correction (KR_FIXED defined)
 *
 * In file-replay mode the harness propagates the policy verdict via its
 * process exit code (77 = rotation failure reproduced, 78 = stale frame
 * rejected by the fix), which the Go runner records as evidence.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  kr_frame_t frame;
  if (kr_parse(data, size, &frame) != 0) {
    return 0; /* malformed inputs are uninteresting */
  }
  int verdict = kr_evaluate(&frame);
  if (verdict == 77) {
#ifdef KR_REPLAY_EXIT
    /* Single-file replay: surface the policy verdict as the exit code so the
     * Go runner can distinguish "rotation failure reproduced" (77) from a
     * generic harness crash. */
    exit(77);
#else
    /* Deterministic trap so libFuzzer keeps the corpus input as a crash. */
    __builtin_trap();
#endif
  }
  if (verdict == 78) {
#ifdef KR_REPLAY_EXIT
    exit(78);
#else
    return 0;
#endif
  }
  return 0;
}

#ifdef KR_REPLAY_EXIT
int main(int argc, char **argv) {
  const char *delay_ms = getenv("KRFIX_REPLAY_DELAY_MS");
  if (delay_ms && atoi(delay_ms) > 0) {
    struct timespec ts = {atoi(delay_ms) / 1000,
                          (long)(atoi(delay_ms) % 1000) * 1000000L};
    nanosleep(&ts, NULL);
  }
  if (argc < 2) {
    fprintf(stderr, "usage: %s <sample-file>\n", argv[0]);
    return 2;
  }
  FILE *fp = fopen(argv[1], "rb");
  if (!fp) return 2;
  fseek(fp, 0, SEEK_END);
  long n = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  uint8_t *buf = (uint8_t *)malloc((size_t)n);
  if (fread(buf, 1, (size_t)n, fp) != (size_t)n) return 2;
  fclose(fp);
  int rc = LLVMFuzzerTestOneInput(buf, (size_t)n);
  free(buf);
  return rc;
}
#endif
