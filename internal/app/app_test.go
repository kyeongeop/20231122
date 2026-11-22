package app

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"serrfix/internal/model"
)

func TestEndToEndPauseResumeCompareExport(t *testing.T) {
	root := t.TempDir()
	originalPath := filepath.Join(root, "errors.txt")
	original := []byte(strings.Join([]string{
		"[case-long] Authorization: Bearer abc.def.ghi123456 failed",
		`[case-json] {"password":"hunter2","tenant":"acme"}`,
		"[case-unicode] 错误 password=秘密值 token=tok-123",
		"[case-safe] timeout after 30s",
	}, "\n") + "\n")
	if err := os.WriteFile(originalPath, original, 0o644); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(root, ".serrfix")
	a, err := Open(ws, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 11, 22, 8, 30, 0, 0, time.UTC)
	a.Now = func() time.Time {
		now := clock
		clock = clock.Add(time.Millisecond)
		return now
	}
	defer a.Close()

	initResult, err := a.Init(InitOptions{OriginalPath: originalPath})
	if err != nil {
		t.Fatal(err)
	}
	if initResult.Samples != 4 {
		t.Fatalf("samples = %d, want 4", initResult.Samples)
	}
	snapshot, err := os.ReadFile(a.WS.Resolve(initResult.SnapshotPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshot, original) {
		t.Fatalf("snapshot bytes changed")
	}
	info, err := os.Stat(a.WS.Resolve(initResult.SnapshotPath))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("snapshot is writable: %o", info.Mode().Perm())
	}

	first, err := a.Run(context.Background(), RunOptions{Resume: true, StopAfter: 2})
	if err != nil {
		t.Fatal(err)
	}
	if first.CompletedRuns != 2 || first.Pending != 2 || !first.Paused {
		t.Fatalf("unexpected pause summary: %+v", first)
	}
	second, err := a.Run(context.Background(), RunOptions{Resume: true})
	if err != nil {
		t.Fatal(err)
	}
	if second.CompletedRuns != 2 || second.Pending != 0 || second.Paused {
		t.Fatalf("unexpected resume summary: %+v", second)
	}

	report, err := a.Report()
	if err != nil {
		t.Fatal(err)
	}
	if report.Totals.Runs != 4 || report.Totals.Passed != 4 {
		t.Fatalf("unexpected totals: %+v", report.Totals)
	}
	for _, sample := range report.Samples {
		got := original[sample.SourceOffset : sample.SourceOffset+sample.SourceLength]
		if model.SHA256(got) != sample.SourceSHA256 {
			t.Fatalf("offset mismatch for %s", sample.SampleID)
		}
	}

	unicodeSample := report.Samples[2]
	rerun, err := a.Run(context.Background(), RunOptions{
		SampleID: unicodeSample.SampleID, Repeat: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rerun.CompletedRuns != 2 || rerun.Failed != 0 {
		t.Fatalf("unexpected rerun: %+v", rerun)
	}
	comparison, err := a.Compare(CompareOptions{SampleID: unicodeSample.SampleID})
	if err != nil {
		t.Fatal(err)
	}
	if !comparison.SameOriginal || !comparison.SameRedacted || !comparison.SameSpanLayout {
		t.Fatalf("expected deterministic comparison: %+v", comparison)
	}
	if comparison.SourceOffset != unicodeSample.SourceOffset {
		t.Fatalf("comparison offset = %d, want %d", comparison.SourceOffset, unicodeSample.SourceOffset)
	}

	export, err := a.Export(ExportOptions{SampleID: unicodeSample.SampleID})
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(export.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name] = data
	}
	var manifest ExportManifest
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SourceOffset != unicodeSample.SourceOffset ||
		manifest.SourceLength != unicodeSample.SourceLength {
		t.Fatalf("manifest offset mismatch: %+v", manifest)
	}
	if !bytes.Equal(files["original/material.bin"], original) {
		t.Fatalf("exported original is not byte-identical")
	}
	wantSlice := original[manifest.SourceOffset : manifest.SourceOffset+manifest.SourceLength]
	if !bytes.Equal(files["source/sample.bin"], wantSlice) {
		t.Fatalf("exported source slice does not match original offset")
	}
	if !strings.Contains(string(files["summary.md"]), "First run started") {
		t.Fatalf("summary missing run timeline")
	}

	verify, err := a.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !verify.OK {
		for _, check := range verify.Checks {
			if !check.OK {
				t.Logf("failed check: %s: %s", check.Name, check.Detail)
			}
		}
		t.Fatalf("verify failed")
	}
	if verify.FirstRunAt == "" || verify.LastRunAt == "" ||
		verify.FirstRunAt >= verify.LastRunAt {
		t.Fatalf("run time window not concrete/ordered: %s .. %s",
			verify.FirstRunAt, verify.LastRunAt)
	}
	after, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("source original was modified")
	}
}

func TestVerifyDetectsTamperedEvidence(t *testing.T) {
	root := t.TempDir()
	originalPath := filepath.Join(root, "errors.txt")
	if err := os.WriteFile(originalPath, []byte("[case] password=secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := Open(filepath.Join(root, ".serrfix"), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Init(InitOptions{OriginalPath: originalPath}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Run(context.Background(), RunOptions{Resume: true}); err != nil {
		t.Fatal(err)
	}
	runs, err := a.DB.ListRuns("")
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs: %v %v", runs, err)
	}
	path := a.WS.Resolve(runs[0].EvidencePath)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"tampered":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := a.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if report.OK {
		t.Fatalf("tampered evidence passed verification")
	}
}
