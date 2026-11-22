/*
 * Replay driver for the libFuzzer-compatible target exported from Go
 * (LLVMFuzzerTestOneInput in fuzz/fuzztarget). With clang available,
 * link the c-archive with -fsanitize=fuzzer instead and get the real
 * libFuzzer engine; this driver only replays corpus files through the
 * same entrypoint, mirroring what libFuzzer does for file arguments.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <corpus-file>...\n", argv[0]);
        return 2;
    }
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) { perror(argv[i]); return 1; }
        fseek(f, 0, SEEK_END);
        long n = ftell(f);
        fseek(f, 0, SEEK_SET);
        uint8_t *buf = malloc(n > 0 ? (size_t)n : 1);
        if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
            perror("fread");
            return 1;
        }
        fclose(f);
        LLVMFuzzerTestOneInput(buf, (size_t)n);
        free(buf);
        printf("ok %s (%ld bytes)\n", argv[i], n);
    }
    return 0;
}
