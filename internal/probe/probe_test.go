package probe

import (
	"testing"

	"corpusd/internal/model"
)

func TestAnalyzeDeterministic(t *testing.T) {
	input := []byte("libfuzzer seed \x00\xff repeated object")
	a := Analyze(input, "", model.ModeFull)
	b := Analyze(append([]byte(nil), input...), "", model.ModeFull)
	if a != b {
		t.Fatalf("analysis is not deterministic:\n%+v\n%+v", a, b)
	}
	if a.Features == 0 || a.CoverageBytes != len(input) || a.ResultSHA256 == "" {
		t.Fatalf("unexpected analysis: %+v", a)
	}
}

func TestDegradedHasNoContentFeatures(t *testing.T) {
	a := Analyze([]byte("secret content"), "abc", model.ModeDegraded)
	if a.Features != 0 || a.CoverageBytes != 0 || a.ContentSHA256 != "abc" {
		t.Fatalf("degraded analysis leaked content work: %+v", a)
	}
}

func FuzzAnalyze(f *testing.F) {
	f.Add([]byte("FUZZ"))
	f.Add([]byte{})
	f.Add([]byte{0x00, 0xff, 0x7f, 0x80})
	f.Fuzz(func(t *testing.T, data []byte) {
		full := Analyze(data, "", model.ModeFull)
		degraded := Analyze(data, "", model.ModeDegraded)
		if full.ContentSHA256 != degraded.ContentSHA256 {
			t.Fatal("content hash changed with mode")
		}
		if full.Features > 256 {
			t.Fatalf("feature count exceeds bitmap: %d", full.Features)
		}
	})
}
