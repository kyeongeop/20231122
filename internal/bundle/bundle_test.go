package bundle_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"auditfix/internal/audit"
	"auditfix/internal/bundle"
	"auditfix/internal/db"
	"auditfix/internal/model"
	"auditfix/internal/runner"
)

type logEvent struct {
	Seq           int64  `json:"seq"`
	Device        string `json:"device"`
	TimeUnixNS    int64  `json:"time_unix_ns"`
	Kind          string `json:"kind"`
	AnchorID      string `json:"anchor_id"`
	Subject       string `json:"subject"`
	PayloadSHA256 string `json:"payload_sha256"`
	PrevHash      string `json:"prev_hash"`
	RecordHash    string `json:"record_hash"`
}

func TestExportVerifyDeterminismAndRestore(t *testing.T) {
	ctx := context.Background()
	store, runID := createReviewState(t)
	defer store.Close()
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	if _, err := bundle.Export(ctx, store, runID, first, false); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Export(ctx, store, runID, second, false); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"manifest.json", "case.json", "events.jsonl", "corrections.jsonl",
		"samples.jsonl", "attempts.jsonl", "state.sqlite", "manifest.sha256",
	} {
		left, err := os.ReadFile(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.ReadFile(filepath.Join(second, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(left, right) {
			t.Fatalf("%s is not deterministic across exports", name)
		}
	}
	report, err := bundle.Verify(ctx, first, bundle.VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.CaseID != "case-test" || report.RunID != runID {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.RowsChecked != 8+1+2+2+3 {
		t.Fatalf("row count: %d", report.RowsChecked)
	}

	tampered := filepath.Join(root, "tampered")
	if _, err := bundle.Export(ctx, store, runID, tampered, false); err != nil {
		t.Fatal(err)
	}
	samplePath := filepath.Join(tampered, "samples",
		"0001-"+digest([]byte("AFXS1\nsample-one\n"))+".sample")
	if err := os.WriteFile(samplePath, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Verify(ctx, tampered, bundle.VerifyOptions{}); err == nil {
		t.Fatal("tampered sample bytes were accepted")
	}
	tamperedOutput := filepath.Join(root, "tampered-output")
	if _, err := bundle.Export(ctx, store, runID, tamperedOutput, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tamperedOutput, "attempts", "0001-0001.stdout"),
		[]byte("forged output"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Verify(ctx, tamperedOutput, bundle.VerifyOptions{}); err == nil {
		t.Fatal("tampered captured stdout was accepted")
	}

	restored := filepath.Join(root, "restored.sqlite")
	if err := bundle.Restore(ctx, first, restored, false); err != nil {
		t.Fatal(err)
	}
	sourceDB, err := os.ReadFile(filepath.Join(first, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	restoredDB, err := os.ReadFile(restored)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sourceDB, restoredDB) {
		t.Fatal("restore changed the exported SQLite bytes")
	}
	restoredStore, err := db.Open(restored)
	if err != nil {
		t.Fatal(err)
	}
	defer restoredStore.Close()
	restoredRun, err := restoredStore.GetRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if restoredRun.AttemptCount != 3 || restoredRun.CompletedCount != 2 {
		t.Fatalf("restored run counts: %+v", restoredRun)
	}
	attempts, err := restoredStore.ListAttempts(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 3 || attempts[0].SampleIndex != 1 || attempts[0].AttemptNo != 1 ||
		attempts[2].SampleIndex != 2 {
		t.Fatalf("restored attempt order changed: %+v", attempts)
	}
}

func createReviewState(t *testing.T) (*db.Store, string) {
	t.Helper()
	ctx := context.Background()
	const base int64 = 1_763_772_000_000_000_000
	logA := buildLog(t, "device-a", base, 0, map[int64]bool{3: true, 4: true})
	logB := buildLog(t, "device-b", base, 10*time.Second, nil)
	eventsA, err := audit.ParseDeviceLog(bytes.NewReader(logA), "device-a")
	if err != nil {
		t.Fatal(err)
	}
	eventsB, err := audit.ParseDeviceLog(bytes.NewReader(logB), "device-b")
	if err != nil {
		t.Fatal(err)
	}
	created := "2026-01-01T00:00:00Z"
	analysis := audit.Analyze(eventsA, eventsB, "case-test", created)
	caseRow := model.Case{
		CaseID: "case-test", CreatedAt: created, Description: "test",
		Status: analysis.Status, AnalyzerVersion: model.ToolVersion,
		ClockOffsetNS: analysis.ClockOffsetNS, ChainStatus: analysis.ChainStatus,
		AnchorPairCount: analysis.AnchorPairs, DeviceAEventRows: len(eventsA),
		DeviceBEventRows: len(eventsB), CorrectionCount: len(analysis.Corrections),
	}
	store, err := db.Open(filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	blobs := []db.EvidenceBlob{
		{Role: "device-a-log", SourceName: "a.jsonl", SHA256: digest(logA), Data: logA},
		{Role: "device-b-log", SourceName: "b.jsonl", SHA256: digest(logB), Data: logB},
	}
	if err := store.CreateCaseAtomic(ctx, caseRow, blobs, analysis.Events,
		analysis.Corrections); err != nil {
		t.Fatal(err)
	}
	sampleData := [][]byte{[]byte("AFXS1\nsample-one\n"), []byte("AFXS1\nsample-two\n")}
	samples := make([]model.Sample, 2)
	for i := range samples {
		sum := digest(sampleData[i])
		samples[i] = model.Sample{
			SampleID: "sample-" + sum[:12], CaseID: "case-test",
			SampleIndex: i + 1, Name: fmt.Sprintf("0%d-test.sample", i+1),
			SHA256: sum, Size: int64(len(sampleData[i])),
			SourceName: fmt.Sprintf("0%d-test.sample", i+1),
			ImportedAt: created,
		}
	}
	if err := store.InsertSamples(ctx, samples, sampleData); err != nil {
		t.Fatal(err)
	}
	harnessSHA := digest([]byte("fake-harness"))
	runID := "run-test"
	run := model.Run{
		RunID: runID, CaseID: "case-test", HarnessSHA256: harnessSHA,
		HarnessPath: "/tmp/auditfix_harness", TimeoutMS: 5000,
		FuzzArgs: "-runs=1", Status: "complete", CreatedAt: created,
		StartedAt: created, FinishedAt: created, RequestedLimit: 0,
		CompletedCount: 2, AttemptCount: 3, SchemaVersion: model.SchemaVersion,
	}
	if err := store.InsertRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	insertAttempt(t, store, runID, samples[0], 1, harnessSHA)
	insertAttempt(t, store, runID, samples[0], 2, harnessSHA)
	insertAttempt(t, store, runID, samples[1], 1, harnessSHA)
	return store, runID
}

func insertAttempt(t *testing.T, store *db.Store, runID string, sample model.Sample,
	attemptNo int, harnessSHA string) {
	t.Helper()
	stdout := `AUDITFIX_RESULT {"schema":"auditfix.harness.v1","verdict":"PASS","classification":"OK","chain_ok":true,"anchor_pairs":1,"clock_offset_ns":0,"findings":[],"missing_segments":[]}` + "\n"
	parsed, err := runner.ParseHarnessOutput(stdout)
	if err != nil {
		t.Fatal(err)
	}
	resultJSON, evidenceSHA, err := runner.NormalizeResult(sample.SHA256, harnessSHA,
		stdout, "", 0, 0, false, &parsed)
	if err != nil {
		t.Fatal(err)
	}
	attempt := model.Attempt{
		RunID: runID, SampleID: sample.SampleID, SampleIndex: sample.SampleIndex,
		AttemptNo: attemptNo, Status: "complete", StartedAt: "2026-01-01T00:00:00Z",
		FinishedAt: "2026-01-01T00:00:01Z", StdoutSHA256: digest([]byte(stdout)),
		Stdout: []byte(stdout), Stderr: []byte{}, StderrSHA256: digest(nil),
		HarnessOutput: strings.TrimSpace(stdout),
		ResultJSON:    resultJSON, EvidenceSHA256: evidenceSHA,
	}
	id, err := store.InsertRunningAttempt(context.Background(), attempt)
	if err != nil {
		t.Fatal(err)
	}
	attempt.AttemptID = id
	if err := store.FinishAttempt(context.Background(), attempt); err != nil {
		t.Fatal(err)
	}
}

func buildLog(t *testing.T, device string, base int64, skew time.Duration,
	skip map[int64]bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	last := strings.Repeat("0", 64)
	for seq := int64(1); seq <= 5; seq++ {
		if skip[seq] {
			continue
		}
		kind, anchor, subject := "operation", "", "auth.verify"
		payload := digest([]byte(fmt.Sprintf("%s:%d", device, seq)))
		if seq == 1 || seq == 5 {
			kind, anchor, subject = "anchor", "beacon-test", "clock.sync"
			payload = digest([]byte("beacon:beacon-test"))
		}
		timeNS := base + seq*int64(time.Second) + int64(skew)
		event := logEvent{
			Seq: seq, Device: device, TimeUnixNS: timeNS, Kind: kind,
			AnchorID: anchor, Subject: subject, PayloadSHA256: payload,
			PrevHash: last,
			RecordHash: audit.HashEvent(device, seq, timeNS, kind, anchor,
				subject, payload, last),
		}
		if err := encoder.Encode(event); err != nil {
			t.Fatal(err)
		}
		last = event.RecordHash
	}
	return buf.Bytes()
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
