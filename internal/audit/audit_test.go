package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

const sampleCapture = `# capture v1
#@anchor 1 label=prelude captured_at=2026-11-22T08:00:00.120Z
100 1 0:52 / / rw,relatime shared:1 - overlay overlay rw,lowerdir=/lower
101 100 0:53 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
#@anchor 2 label=host captured_at=2026-11-22T08:00:02.340Z
102 100 8:1 / /var/run/docker.sock rw,relatime - ext4 /dev/sda1 rw
103 100 0:55 / /data rw,nosuid,nodev,noexec,relatime shared:7 - tmpfs tmpfs rw
#@anchor 3 label=eof captured_at=2026-11-22T08:00:05.900Z
`

func TestResolveExplicitAnchorsOffsets(t *testing.T) {
	plan := MakePlan([]byte(sampleCapture), nil)
	if plan.AnchorFallback {
		t.Fatalf("unexpected anchor fallback: %s", plan.FallbackReason)
	}
	want := []int64{
		int64(bytes.Index([]byte(sampleCapture), []byte("#@anchor 1"))),
		int64(bytes.Index([]byte(sampleCapture), []byte("#@anchor 2"))),
		int64(bytes.Index([]byte(sampleCapture), []byte("#@anchor 3"))),
	}
	for index, anchor := range plan.Anchors {
		if anchor.Offset != want[index] {
			t.Fatalf("anchor %d offset=%d want %d", anchor.Number, anchor.Offset, want[index])
		}
		if anchor.Line < 1 {
			t.Fatalf("anchor %d has invalid line %d", anchor.Number, anchor.Line)
		}
	}
	if plan.Anchors[0].CapturedAt != "2026-11-22T08:00:00.12Z" {
		t.Fatalf("captured_at=%q", plan.Anchors[0].CapturedAt)
	}
}

func TestFallbackAnchorsUseLineBoundaries(t *testing.T) {
	input := []byte(strings.Repeat("100 1 0:1 / /mnt rw - tmpfs tmpfs rw\n", 30))
	plan := MakePlan(input, func() time.Time {
		return time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)
	})
	if !plan.AnchorFallback {
		t.Fatal("expected fallback anchors")
	}
	for _, anchor := range plan.Anchors[:2] {
		if anchor.Offset > 0 && input[anchor.Offset-1] != '\n' {
			t.Fatalf("anchor %d at %d is not a line start", anchor.Number, anchor.Offset)
		}
	}
}

func TestAnalyzePreservesRawOffsets(t *testing.T) {
	input := []byte(sampleCapture)
	analysis := Analyze(input, DefaultLimits(), nil)
	if len(analysis.Records) != 4 {
		t.Fatalf("records=%d want 4", len(analysis.Records))
	}
	if len(analysis.Findings) == 0 {
		t.Fatal("expected findings")
	}
	for _, record := range analysis.Records {
		raw := input[record.StartOffset:record.EndOffset]
		if record.StartOffset >= record.EndOffset {
			t.Fatalf("record %d has empty raw span", record.Ordinal)
		}
		if !strings.Contains(string(raw), record.MountID+" ") {
			t.Fatalf("record %d offsets do not point at its raw line", record.Ordinal)
		}
	}
	for _, finding := range analysis.Findings {
		if finding.StartOffset < 0 || finding.EndOffset > int64(len(input)) {
			t.Fatalf("finding raw span out of bounds: [%d,%d)", finding.StartOffset, finding.EndOffset)
		}
	}
}

func TestAnalyzeResourceCapsAreExplicit(t *testing.T) {
	analysis := Analyze([]byte(sampleCapture), Limits{
		MaxInputBytes: 1 << 20,
		MaxScanBytes:  180,
		MaxRecords:    1,
	}, nil)
	if !analysis.Degraded {
		t.Fatal("expected degraded analysis")
	}
	if analysis.ScannedBytes > 180 {
		t.Fatalf("scanned bytes %d exceeds budget", analysis.ScannedBytes)
	}
	if len(analysis.Records) != 1 {
		t.Fatalf("records=%d want record cap 1", len(analysis.Records))
	}
	if analysis.StopOffset <= 0 {
		t.Fatalf("expected concrete stop offset, got %d", analysis.StopOffset)
	}
}

func FuzzAnalyze(f *testing.F) {
	f.Add([]byte(sampleCapture))
	f.Add([]byte("#@anchor 1 label=x\n100 1 0:1 / / rw - tmpfs tmpfs rw\n"))
	f.Add([]byte("\x00\xff\n#@anchor 2\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		analysis := Analyze(data, DefaultLimits(), nil)
		if analysis.ScannedBytes < 0 {
			t.Fatal("negative scanned bytes")
		}
		for _, record := range analysis.Records {
			if record.StartOffset < 0 || record.EndOffset > int64(len(data)) ||
				record.StartOffset > record.EndOffset {
				t.Fatalf("invalid record span [%d,%d)", record.StartOffset, record.EndOffset)
			}
		}
	})
}
