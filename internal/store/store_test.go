package store

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "forensics.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st, ctx
}

func TestSeedReportKeepsEvidenceAndBoundary(t *testing.T) {
	st, ctx := openTestStore(t)
	report, err := st.GetReport(ctx, DefaultSampleID)
	if err != nil {
		t.Fatalf("GetReport: %v", err)
	}
	if report.Sample.Size != 84 || report.Sample.SHA256 == "" {
		t.Fatalf("unexpected sample: %+v", report.Sample)
	}
	if report.Summary.AutoCount != 5 || report.Summary.AutoUndecided != 1 {
		t.Fatalf("unexpected auto summary: %+v", report.Summary)
	}
	if report.Summary.ManualCount != 4 || report.Summary.ManualPending != 4 {
		t.Fatalf("unexpected manual summary: %+v", report.Summary)
	}
	if len(report.Evidence) != 9 || len(report.Replays) != 2 {
		t.Fatalf("evidence=%d replays=%d", len(report.Evidence), len(report.Replays))
	}
	if len(report.UnknownExtensions) != 1 {
		t.Fatalf("unknown extensions = %d", len(report.UnknownExtensions))
	}
	unknown := report.UnknownExtensions[0]
	if unknown.Tag != "0x7E" || unknown.Boundary != 41 || unknown.RawHex == "" {
		t.Fatalf("unknown extension not preserved: %+v", unknown)
	}
	if report.Replays[0].Status != "failed" || report.Replays[1].Status != "reproduced" {
		t.Fatalf("replay sequence: %+v", report.Replays)
	}
}

func TestManualReviewIsStoredSeparately(t *testing.T) {
	st, ctx := openTestStore(t)
	report, err := st.ReviewManual(ctx, DefaultSampleID, "MC-04", "confirmed", "qa@example.test", "owner 补充了扩展注册表")
	if err != nil {
		t.Fatalf("ReviewManual: %v", err)
	}
	if report.Summary.ManualResolved != 1 || report.Summary.ManualPending != 3 {
		t.Fatalf("unexpected summary: %+v", report.Summary)
	}
	var check ManualCheck
	for _, item := range report.ManualChecks {
		if item.ID == "MC-04" {
			check = item
		}
	}
	if check.Status != "confirmed" || check.Reviewer != "qa@example.test" {
		t.Fatalf("manual check not persisted: %+v", check)
	}
	for _, conclusion := range report.Conclusions {
		if conclusion.ID == "AC-04" && conclusion.Status != "undecided" {
			t.Fatalf("automatic conclusion was overwritten: %+v", conclusion)
		}
	}
}

func TestReplayAppendsTraceEvidence(t *testing.T) {
	st, ctx := openTestStore(t)
	report, err := st.RunReplay(ctx, DefaultSampleID)
	if err != nil {
		t.Fatalf("RunReplay: %v", err)
	}
	if len(report.Steps) != 8 || len(report.Replays) != 3 || len(report.Evidence) != 10 {
		t.Fatalf("steps=%d replays=%d evidence=%d", len(report.Steps), len(report.Replays), len(report.Evidence))
	}
	last := report.Replays[len(report.Replays)-1]
	if last.Status != "reproduced" || last.Reproduced != 3 {
		t.Fatalf("last replay: %+v", last)
	}
	if _, _, err := st.EvidenceContent(ctx, last.EvidenceID); err != nil {
		t.Fatalf("trace evidence missing: %v", err)
	}
}

func TestExportContainsOriginalAndEvidence(t *testing.T) {
	st, ctx := openTestStore(t)
	pkg, err := st.Export(ctx, DefaultSampleID)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	original, err := base64.StdEncoding.DecodeString(pkg.Original)
	if err != nil {
		t.Fatalf("decode original: %v", err)
	}
	if len(original) != 84 {
		t.Fatalf("exported original = %d bytes", len(original))
	}
	if len(pkg.Evidence) != 9 {
		t.Fatalf("exported evidence = %d", len(pkg.Evidence))
	}
}
