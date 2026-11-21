package runner

import (
	"strings"
	"testing"
)

func TestParseHarnessOutputUsesLastMarker(t *testing.T) {
	stdout := "noise\n" +
		`AUDITFIX_RESULT {"schema":"auditfix.harness.v1","verdict":"PASS","classification":"OK","chain_ok":true,"anchor_pairs":2,"clock_offset_ns":0,"findings":[],"missing_segments":[]}` +
		"\n"
	result, err := ParseHarnessOutput(stdout)
	if err != nil {
		t.Fatal(err)
	}
	if result.Classification != "OK" || !result.ChainOK || result.AnchorPairs != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Findings == nil || result.MissingSegments == nil {
		t.Fatal("nil slices must be normalized for stable comparison")
	}
}

func TestNormalizeResultTimeoutAndDigest(t *testing.T) {
	sampleSHA := strings.Repeat("1", 64)
	harnessSHA := strings.Repeat("2", 64)
	first, digestOne, err := NormalizeResult(sampleSHA, harnessSHA, "", "timed out",
		0, 9, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, digestTwo, err := NormalizeResult(sampleSHA, harnessSHA, "", "timed out",
		0, 9, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || digestOne != digestTwo {
		t.Fatal("normalized evidence is not deterministic")
	}
	if !strings.Contains(first, `"classification":"TIMEOUT"`) {
		t.Fatalf("timeout evidence: %s", first)
	}
}

func TestParseHarnessOutputRejectsMissingMarker(t *testing.T) {
	if _, err := ParseHarnessOutput("libFuzzer only\n"); err == nil {
		t.Fatal("missing result marker was accepted")
	}
}
