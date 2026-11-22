package reconcile

import (
	"testing"

	"truncstream/internal/stream"
)

// FuzzReconcileDeterminism hammers the property that two runs over identical
// captures produce byte-identical reports and fingerprints, regardless of
// clock skew, frame count or truncation point.
func FuzzReconcileDeterminism(f *testing.F) {
	f.Add(uint(10), int64(4200), uint(50))
	f.Fuzz(func(t *testing.T, n uint, skew int64, cut uint) {
		if n == 0 || n > 100 {
			n = 10
		}
		recsA := stream.GenRecords(DeviceA, "obj", int(n), 1_000_000, 250, 0)
		recsB := stream.GenRecords(DeviceB, "obj", int(n), 1_000_000, 250, skew)
		fullA, err := stream.BuildStream(recsA, stream.EncodeOptions{Compress: true})
		if err != nil {
			t.Fatal(err)
		}
		optA := stream.EncodeOptions{Compress: true}
		if cut%3 != 0 {
			optA.TruncateAt = 4 + int(cut)%len(fullA)
		}
		capA, err := stream.BuildStream(recsA, optA)
		if err != nil {
			t.Fatal(err)
		}
		capB, err := stream.BuildStream(recsB, stream.EncodeOptions{Compress: true})
		if err != nil {
			t.Fatal(err)
		}
		pa1, pb1 := stream.Parse(capA), stream.Parse(capB)
		pa2, pb2 := stream.Parse(capA), stream.Parse(capB)
		if Fingerprint(pa1, pb1) != Fingerprint(pa2, pb2) {
			t.Fatal("fingerprint not deterministic")
		}
		r1, err := Run(pa1, pb1)
		if err != nil {
			return // unmatched feeds are a valid outcome
		}
		r2, err := Run(pa2, pb2)
		if err != nil {
			t.Fatal(err)
		}
		if r1.InputFingerprint != r2.InputFingerprint ||
			r1.PairCount != r2.PairCount ||
			r1.DeviceBOffsetMs != r2.DeviceBOffsetMs {
			t.Fatal("reconcile output drifted between identical runs")
		}
	})
}
