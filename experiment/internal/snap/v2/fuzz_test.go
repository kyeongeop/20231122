package v2

import "testing"

// FuzzParse is the coverage-guided (libFuzzer-style) fuzz target for the
// hardened snapshot: Parse must never panic, only return errors.
func FuzzParse(f *testing.F) {
	seeds := [][]byte{
		[]byte("a: &x [1, 2, 3]\nb: [*x, *x]\n"),
		[]byte("a: &x [*x]\n"),
		[]byte("k: {a: 1, b: [2, 3]}\n"),
		[]byte("bad line without colon\n"),
		[]byte("l: &a [\"x\"]\nm: &b [*a]\nn: [*b]\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = Parse(data, DefaultLimits())
	})
}
