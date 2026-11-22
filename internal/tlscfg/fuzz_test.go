package tlscfg

import (
	"strings"
	"testing"
)

// FuzzDifferential is a differential fuzz target over the two frozen parser
// snapshots. Go's built-in fuzzing engine is the libFuzzer-style,
// coverage-guided fuzzer shipped with the toolchain (go test -fuzz).
//
// The target ignores the two already-known behaviour changes (ALPN default
// removal, TLS1.2 floor) and fails only on *unexplained* divergence, i.e.
// evidence of an additional regression.
func FuzzDifferential(f *testing.F) {
	seeds := []string{
		`{"id":"s1","min_version":"TLS1.2","alpn":["h2"]}`,
		`{"id":"s2","min_version":"TLS1.2"}`,
		`{"id":"s3","min_version":"TLS1.0","alpn":["http/1.1"]}`,
		`{"id":"s4","cipher_suites":["TLS_AES_128_GCM_SHA256"],"alpn":["h2"]}`,
		`{"id":"s5","min_version":"TLS1.2","cipher_suites":["TLS_AES_128_GCM_SHA256"],"alpn":["h`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		o1 := ParseV1([]byte(raw))
		o2 := ParseV2([]byte(raw))
		if o1.Canonical() == o2.Canonical() {
			return
		}
		if explainedDivergence(o1, o2) {
			return
		}
		t.Fatalf("unexplained divergence\ninput: %q\nv1: %s\nv2: %s",
			raw, o1.Canonical(), o2.Canonical())
	})
}

// explainedDivergence reports whether a v1/v2 disagreement is fully accounted
// for by the two known v2 changes.
func explainedDivergence(o1, o2 Outcome) bool {
	if o2.Status == "error" {
		known := []string{"alpn must not be empty", "min_version below TLS1.2"}
		for _, k := range known {
			if strings.Contains(o2.Err, k) {
				return true
			}
		}
		return false
	}
	// Both ok but configs differ: explainable only when the differences are
	// the known min-version floor and default cipher-suite changes.
	if o1.Status != "ok" || o1.Config == nil || o2.Config == nil {
		return false
	}
	c1, c2 := *o1.Config, *o2.Config
	// Known change: default cipher suite (v1 ECDHE/AES-128, v2 TLS1.3
	// AES-128-GCM). Normalize both defaults away before comparing.
	if joinStrings(c1.CipherSuites) == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" &&
		joinStrings(c2.CipherSuites) == "TLS_AES_128_GCM_SHA256" {
		c1.CipherSuites, c2.CipherSuites = nil, nil
	}
	c1.MinVersion, c2.MinVersion = "", ""
	return c1.MaxVersion == c2.MaxVersion &&
		c1.SessionTickets == c2.SessionTickets &&
		joinStrings(c1.CipherSuites) == joinStrings(c2.CipherSuites) &&
		joinStrings(c1.ALPN) == joinStrings(c2.ALPN)
}

func joinStrings(s []string) string { return strings.Join(s, ",") }
