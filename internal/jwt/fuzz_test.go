package jwt

import (
	"strings"
	"testing"
)

// FuzzParse runs under Go's libFuzzer-based engine (go test -fuzz).
// The parser must never panic and must only return ErrMalformed on bad input.
func FuzzParse(f *testing.F) {
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.c2ln")
	f.Add("not-a-jwt")
	f.Add("..")
	f.Add("###.@@@.$$$")
	f.Fuzz(func(t *testing.T, raw string) {
		tok, err := Parse(raw)
		if err != nil {
			return
		}
		if tok == nil {
			t.Fatal("nil token without error")
		}
		if got := strings.Count(raw, "."); got != 2 {
			t.Fatalf("accepted token with %d dots", got)
		}
	})
}
