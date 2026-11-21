package forensics

import (
	"errors"
	"testing"
)

func TestSeedSampleIsTraceable(t *testing.T) {
	sample := BuildSeedSample()
	if len(sample) != 84 {
		t.Fatalf("sample length = %d, want 84", len(sample))
	}
	if got := Digest(sample); got != "287490add021cb61c47750442a4b715c9ac55d03d8972c71e565f2e1f9d7e7fb" {
		t.Fatalf("digest = %s", got)
	}
	analysis, err := AnalyzeSample(sample)
	if !errors.Is(err, ErrUnknownExtension) {
		t.Fatalf("AnalyzeSample error = %v, want ErrUnknownExtension", err)
	}
	if analysis.Unknown == nil {
		t.Fatal("unknown extension was not retained")
	}
	if analysis.Unknown.Tag != UnknownTag {
		t.Fatalf("tag = 0x%x, want 0x%x", analysis.Unknown.Tag, UnknownTag)
	}
	if analysis.Unknown.TagOffset != 0x14 || analysis.Unknown.DataOffset != 0x1d {
		t.Fatalf("unexpected offsets: tag=%#x data=%#x", analysis.Unknown.TagOffset, analysis.Unknown.DataOffset)
	}
	if analysis.Unknown.Boundary != 0x29 || analysis.PayloadLen != 43 {
		t.Fatalf("boundary=%#x payload=%d", analysis.Unknown.Boundary, analysis.PayloadLen)
	}
	if analysis.Unknown.DataHex != "deadbeef00000001525a0007" {
		t.Fatalf("extension bytes = %s", analysis.Unknown.DataHex)
	}
}

func TestRegisteredExtensionDoesNotStopAtBoundary(t *testing.T) {
	sample := BuildSeedSample()
	sample[20] = 0x03
	analysis, err := AnalyzeSample(sample)
	if err != nil {
		t.Fatalf("AnalyzeSample returned %v", err)
	}
	if analysis.Unknown != nil {
		t.Fatal("registered extension was reported as unknown")
	}
}

func TestTruncatedInputIsRejected(t *testing.T) {
	_, err := AnalyzeSample([]byte("RZ31"))
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("error = %v, want ErrTruncated", err)
	}
}
