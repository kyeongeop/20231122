package audit

import (
	"strings"
	"testing"
)

// FuzzParseToken exercises the parser with Go's built-in fuzzing engine
// (the libFuzzer-derived coverage-guided fuzzer in the Go toolchain).
// Invariants: never panics; a successful parse always yields a known
// snapshot; and any minted v2 token must round-trip.
func FuzzParseToken(f *testing.F) {
	f.Add("PRT1:0a1b2c3d:1798761600")
	f.Add(MintV2("user42", 1798761600))
	f.Add("PRTX:9f3a:legacy")
	f.Add("")
	f.Add("PRT2:!!!:zzzz")
	f.Fuzz(func(t *testing.T, raw string) {
		tok, err := ParseToken(raw)
		if err != nil {
			return
		}
		if tok.Snapshot != SnapshotV1 && tok.Snapshot != SnapshotV2 {
			t.Fatalf("unknown snapshot %q for input %q", tok.Snapshot, raw)
		}
		if tok.Snapshot == SnapshotV2 {
			again, err := ParseToken(MintV2(tok.ID, tok.Expiry))
			if err != nil {
				t.Fatalf("re-minted token failed to parse: %v", err)
			}
			if again.ID != tok.ID || again.Expiry != tok.Expiry {
				t.Fatalf("round-trip mismatch: %+v vs %+v", again, tok)
			}
		}
		if tok.Snapshot == SnapshotV1 && !strings.HasPrefix(raw, "PRT1:") {
			t.Fatalf("v1 token from non-v1 input %q", raw)
		}
	})
}
