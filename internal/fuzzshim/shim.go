// Package fuzzshim exposes the parser as a libFuzzer-style entry point.
//
// fuzz/libfuzzer/main.c declares extern int LLVMFuzzerTestOneInput(const
// uint8_t*, size_t) and forwards every fuzzed byte buffer here through cgo.
// The Go parser is pure, allocation-bounded and panic-safe, so arbitrary
// truncated or adversarial inputs cannot take the harness down.
package fuzzshim

import (
	"lfireview/internal/parse"
)

// Entry is the Go side of LLVMFuzzerTestOneInput. The first byte selects the
// snapshot format (0 -> legacy v1, anything else -> current v2); the remaining
// bytes are the evidence object under test. Returning 0 keeps libFuzzer happy
// while exercising both decode paths and tolerant truncation recovery.
func Entry(data []byte) int {
	version := parse.VersionV2
	payload := data
	if len(data) > 0 && data[0] == 0 {
		version = parse.VersionV1
		payload = data[1:]
	} else if len(data) > 0 {
		payload = data[1:]
	}

	rec, err := parse.Decode(version, "fuzz-object", payload)
	if err != nil {
		return 0
	}
	// Touch the recovered fields so the compiler keeps the whole decode path
	// reachable and any future panic there is surfaced to the fuzzer.
	_ = rec.CorrelationID
	_ = rec.AttackInput
	_ = rec.TriggerFile
	_ = rec.PermissionDecision
	_ = rec.LogSnippet
	_ = len(rec.Raw)
	return 0
}
