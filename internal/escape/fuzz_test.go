package escape

import (
	"bytes"
	"testing"
)

// FuzzRender is the native Go fuzz entrypoint. The same engine is also
// exercised through the libFuzzer-compatible target in fuzz/fuzztarget.
func FuzzRender(f *testing.F) {
	f.Add([]byte(`<p>{{a}}</p>{{b}}`), "<x>&\"'", uint16(8), uint16(64))
	f.Add([]byte(`{{unterminated`), "v", uint16(0), uint16(0))
	f.Add([]byte{0xff, 0xfe, '{', '{', 'a', '}', '}'}, "\xff\x00<", uint16(2), uint16(4))
	f.Fuzz(func(t *testing.T, tmpl []byte, val string, maxVal, maxOut uint16) {
		lim := Limits{MaxValueBytes: int(maxVal), MaxOutputBytes: int(maxOut)}
		vars := map[string]string{"a": val, "b": val}
		r1, err1 := Render(tmpl, vars, lim)
		r2, err2 := Render(tmpl, vars, lim)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("error mismatch: %v vs %v", err1, err2)
		}
		if !bytes.Equal(r1.Output, r2.Output) {
			t.Fatal("non-deterministic output")
		}
		if len(r1.Events) != len(r2.Events) {
			t.Fatal("non-deterministic events")
		}
		if err1 != nil {
			return
		}
		if lim.MaxOutputBytes > 0 && len(r1.Output) > lim.MaxOutputBytes {
			t.Fatalf("output %d exceeds budget %d", len(r1.Output), lim.MaxOutputBytes)
		}
		if !r1.Degraded && len(r1.Events) != 0 {
			t.Fatal("events without degradation flag")
		}
		// Escaped output must never contain a raw '<' contributed by
		// a variable value; any '<' in the output must come from the
		// literal template text.
		if countByte(r1.Output, '<') > countByte(tmpl, '<') {
			t.Fatal("unescaped '<' leaked into output")
		}
	})
}

func countByte(b []byte, c byte) int {
	return bytes.Count(b, []byte{c})
}
