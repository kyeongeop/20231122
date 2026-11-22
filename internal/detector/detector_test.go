package detector

import "testing"

func TestAnalyzeCRLFInjection(t *testing.T) {
	raw := []byte(`value="ok %0d%0a2026-11-22T20:40:01Z INFO audit actor=admin action=export"`)
	got := Analyze("CHK-T", "ATT-T", raw)
	if got.AutoVerdict != "malicious" {
		t.Fatalf("verdict = %q, want malicious", got.AutoVerdict)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(got.Findings))
	}
}

func TestAnalyzeUnicodeBoundary(t *testing.T) {
	got := Analyze("CHK-T", "ATT-T", []byte("partner=alpha\u2028beta"))
	if got.AmbiguousRule != "BOUNDARY-07" {
		t.Fatalf("ambiguous rule = %q", got.AmbiguousRule)
	}
	if got.AutoVerdict != "unknown" {
		t.Fatalf("verdict = %q, want unknown", got.AutoVerdict)
	}
}
