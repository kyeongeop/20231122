// Package harness exposes the smuggling pipeline to fuzzers. It is shared
// by Go's native fuzzing (go test -fuzz) and by the libFuzzer build
// (go test -c -tags libfuzzer).
package harness

import (
	"fmt"

	"github.com/kyeongeop/20231122/internal/httpwire"
	"github.com/kyeongeop/20231122/internal/smuggle"
)

// fuzzLimits mirrors the scenario limits but keeps bodies small enough that
// the fuzzer explores chunk parsing instead of bouncing off the cap.
var fuzzOptions = smuggle.Options{
	Limits: httpwire.Limits{
		MaxRequestBytes: 1 << 20,
		MaxBodyBytes:    4096,
		MaxChunks:       64,
		MaxHeaders:      32,
	},
	AdminToken:  "s3cr3t-adm1n",
	MaxRequests: 8,
}

var profiles = []httpwire.Profile{
	httpwire.Frontend,
	httpwire.Backend,
	httpwire.FrontendTE,
	httpwire.BackendCL,
}

// Check runs data through every front-end/back-end profile pair and returns
// a list of invariant violations. An empty slice means the pipeline held.
func Check(data []byte) (violations []string) {
	for _, fe := range profiles {
		for _, be := range profiles {
			violations = append(violations, checkPair(data, fe, be)...)
		}
	}
	return violations
}

func checkPair(data []byte, feProfile, beProfile httpwire.Profile) (violations []string) {
	tag := fmt.Sprintf("fe=%s be=%s", feProfile, beProfile)

	// Invariant 1: the front-end never consumes more bytes than exist.
	fe := httpwire.NewConn(feProfile, fuzzOptions.Limits, data)
	consumed := 0
	for i := 0; i < fuzzOptions.MaxRequests; i++ {
		req, err := fe.Next()
		if err != nil {
			break
		}
		consumed += len(req.Raw)
		if consumed > len(data) {
			violations = append(violations, fmt.Sprintf("%s: frontend consumed %d > input %d", tag, consumed, len(data)))
			break
		}
		_ = i
	}

	// Invariant 2: the full analysis terminates and stays within bounds.
	a := smuggle.Analyze("fuzz", data, fuzzOptions, feProfile, beProfile)
	if a.Reuse.FrontendServed > fuzzOptions.MaxRequests || a.Reuse.BackendServed > fuzzOptions.MaxRequests {
		violations = append(violations, fmt.Sprintf("%s: served beyond MaxRequests", tag))
	}
	for _, sm := range a.Smuggled {
		if len(sm.Raw) == 0 {
			violations = append(violations, fmt.Sprintf("%s: empty smuggled request", tag))
		}
	}
	return violations
}
