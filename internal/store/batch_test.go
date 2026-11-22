package store

import "testing"

func TestWindowClamping(t *testing.T) {
	cases := []struct {
		lo, hi, n      int
		wantLo, wantHi int
	}{
		{0, 5, 10, 0, 5},
		{8, 12, 10, 8, 10},
		{-3, 2, 10, 0, 2},
		{10, 15, 10, 10, 10},
		{5, 3, 10, 5, 5},
	}
	for _, c := range cases {
		gotLo, gotHi := window(c.lo, c.hi, c.n)
		if gotLo != c.wantLo || gotHi != c.wantHi {
			t.Fatalf("window(%d,%d,%d) = (%d,%d), want (%d,%d)",
				c.lo, c.hi, c.n, gotLo, gotHi, c.wantLo, c.wantHi)
		}
	}
}

func TestFlushInBatchesCoverage(t *testing.T) {
	var seen []int
	err := flushInBatches(2, 5, func(start, end int) error {
		seen = append(seen, start, end)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []int{0, 2, 2, 4, 4, 5}
	if len(seen) != len(want) {
		t.Fatalf("windows = %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("windows = %v, want %v", seen, want)
		}
	}

	called := 0
	if err := flushInBatches(10, 3, func(start, end int) error {
		called++
		if start != 0 || end != 3 {
			t.Fatalf("single-batch window = (%d,%d)", start, end)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("callback calls = %d, want 1", called)
	}
}
