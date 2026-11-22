/*
 * libFuzzer entry point for the dependency-risk pipeline.
 *
 * The Go core is built as a C archive (go build -buildmode=c-archive) and
 * exposes RiskflowFuzz(char*, int). This harness forwards every mutated input
 * to it. A Go panic / abort on an invariant violation surfaces here as a
 * libFuzzer crash artifact, preserving the exact attack input as evidence.
 */
#include <stddef.h>
#include <stdint.h>

#include "bridge.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }
    /* Go owns the bytes for the duration of the call; it copies what it needs. */
    RiskflowFuzz((char *)data, (int)size);
    return 0;
}
