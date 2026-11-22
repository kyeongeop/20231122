package reconcile

import (
	"testing"
	"truncstream/internal/stream"
)

func TestFingerprintStable(t *testing.T) {
	a := stream.GenRecords(101, "obj", 9, 1000, 1000, 0)
	b := stream.GenRecords(202, "obj", 9, 1000, 1000, 4200)
	fa, _ := stream.BuildStream(a, stream.EncodeOptions{Compress: true})
	fb, _ := stream.BuildStream(b, stream.EncodeOptions{Compress: true})
	h1 := Fingerprint(stream.Parse(fa), stream.Parse(fb))
	h2 := Fingerprint(stream.Parse(fa), stream.Parse(fb))
	if h1 != h2 {
		t.Fatalf("unstable: %s != %s", h1, h2)
	}
	t.Log("ok", h1[:12])
}
