package reconcile

import (
	"testing"

	"truncstream/internal/stream"
)

func TestMedianOffsetDeterministic(t *testing.T) {
	build := func() (map[key]stream.Record, map[key]stream.Record) {
		a := map[key]stream.Record{}
		b := map[key]stream.Record{}
		for seq := uint64(1); seq <= 21; seq++ {
			k := key{object: "obj", seq: seq}
			a[k] = stream.Record{ObjectID: "obj", Seq: seq, TsMillis: int64(seq) * 1000}
			// Constant 4200 skew plus a couple of outliers that the median
			// must ignore.
			skew := int64(4200)
			if seq == 3 {
				skew = 90_000
			}
			if seq == 17 {
				skew = -80_000
			}
			b[k] = stream.Record{ObjectID: "obj", Seq: seq, TsMillis: int64(seq)*1000 + skew}
		}
		return a, b
	}
	var want int64 = 4200
	for i := 0; i < 50; i++ {
		a, b := build()
		_, off, err := EstimateOffsets(a, b)
		if err != nil {
			t.Fatal(err)
		}
		if off != want {
			t.Fatalf("iteration %d: offset %d want %d", i, off, want)
		}
	}
}

func TestRunRejectsMixedObjects(t *testing.T) {
	pa := stream.ParseResult{Frames: []stream.Frame{
		{Record: stream.Record{ObjectID: "a", Seq: 1}},
		{Record: stream.Record{ObjectID: "b", Seq: 2}},
	}}
	if _, err := Run(pa, stream.ParseResult{}); err != ErrMixedObjects {
		t.Fatalf("err = %v want ErrMixedObjects", err)
	}
}

func TestRunNoCommonPoint(t *testing.T) {
	pa := stream.ParseResult{Frames: []stream.Frame{
		{Record: stream.Record{ObjectID: "o", Seq: 1, DeviceID: DeviceA}},
	}}
	pb := stream.ParseResult{Frames: []stream.Frame{
		{Record: stream.Record{ObjectID: "o", Seq: 9, DeviceID: DeviceB}},
	}}
	if _, err := Run(pa, pb); err != ErrNoCommonPoint {
		t.Fatalf("err = %v want ErrNoCommonPoint", err)
	}
}
