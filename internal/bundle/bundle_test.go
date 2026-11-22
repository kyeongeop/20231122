package bundle

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"apiskew.local/apiskew/internal/domain"
	"apiskew.local/apiskew/internal/store"
)

func TestExportVerifyAndStableReloadOrder(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	session, err := st.CreateSession(ctx, "sess-bundle", "bundle", domain.DefaultScenario())
	if err != nil {
		t.Fatal(err)
	}
	inputs := [][]byte{
		domain.MustEncodeAttack(domain.Attack{ActorRole: domain.RoleEditor, Action: domain.ActionRead, TenantMatch: true, SkewBMS: 4500}),
		domain.MustEncodeAttack(domain.Attack{ActorRole: domain.RoleViewer, Action: domain.ActionUpdate, TenantMatch: true, SkewBMS: 7000}),
	}
	for _, input := range inputs {
		sample, inserted, err := st.InsertSample(ctx, session.ID, "test", input)
		if err != nil || !inserted {
			t.Fatalf("insert sample: %v inserted=%t", err, inserted)
		}
		evaluation, err := domain.Evaluate(session.Scenario, sample.Input, "test")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := saveTestRun(ctx, st, session.ID, sample.ID, evaluation); err != nil {
			t.Fatal(err)
		}
		if sample.ID == "s0001" {
			if _, err := saveTestRun(ctx, st, session.ID, sample.ID, evaluation); err != nil {
				t.Fatal(err)
			}
		}
	}
	out := filepath.Join(dir, "published")
	manifest, err := Export(ctx, st, ExportOptions{SessionID: session.ID, OutDir: out})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.RecordCount != 2 || len(manifest.RecordFields) != len(RecordFields) {
		t.Fatalf("manifest = %#v", manifest)
	}
	if !reflect.DeepEqual(manifest.RecordFields, RecordFields) {
		t.Fatalf("manifest field order = %v", manifest.RecordFields)
	}
	verification, err := Verify(VerifyOptions{Dir: out})
	if err != nil {
		t.Fatal(err)
	}
	if verification.RecordCount != 2 || verification.CheckedCount != 2 || verification.AttemptCount != 3 {
		t.Fatalf("verification = %#v", verification)
	}
	single, err := Verify(VerifyOptions{Dir: out, SampleID: "s0001"})
	if err != nil {
		t.Fatal(err)
	}
	if single.CheckedCount != 1 {
		t.Fatalf("single verification = %#v", single)
	}
	singleOut := filepath.Join(dir, "single")
	singleManifest, err := Export(ctx, st, ExportOptions{SessionID: session.ID, SampleID: "s0002", OutDir: singleOut})
	if err != nil {
		t.Fatal(err)
	}
	if singleManifest.RecordCount != 1 {
		t.Fatalf("single manifest = %#v", singleManifest)
	}
	singleSample, err := Verify(VerifyOptions{Dir: singleOut, SampleID: "s0002"})
	if err != nil {
		t.Fatal(err)
	}
	if singleSample.RecordCount != 1 || singleSample.AttemptCount != 1 {
		t.Fatalf("single-sample export = %#v", singleSample)
	}
	file, err := os.Open(filepath.Join(out, "records.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var lines [][]byte
	for scanner.Scan() {
		lines = append(lines, append([]byte{}, scanner.Bytes()...))
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("record lines = %d", len(lines))
	}
	for _, line := range lines {
		keys, err := topLevelKeys(line)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(keys, RecordFields) {
			t.Fatalf("JSONL field order = %v", keys)
		}
	}
}

func TestVerifyRejectsTamperedBundle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	session, err := st.CreateSession(ctx, "sess-tamper", "tamper", domain.DefaultScenario())
	if err != nil {
		t.Fatal(err)
	}
	input := domain.MustEncodeAttack(domain.Attack{ActorRole: domain.RoleEditor, Action: domain.ActionRead, TenantMatch: true, SkewBMS: 4500})
	sample, _, err := st.InsertSample(ctx, session.ID, "test", input)
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := domain.Evaluate(session.Scenario, sample.Input, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := saveTestRun(ctx, st, session.ID, sample.ID, evaluation); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "published")
	if _, err := Export(ctx, st, ExportOptions{SessionID: session.ID, OutDir: out}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(out, "records.jsonl")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{}\n"); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, err := Verify(VerifyOptions{Dir: out}); err == nil {
		t.Fatal("tampered bundle passed verification")
	}
}

func saveTestRun(ctx context.Context, st *store.Store, sessionID, sampleID string, evaluation domain.Evaluation) (store.Run, error) {
	raw, err := evaluation.EvidenceJSON()
	if err != nil {
		return store.Run{}, err
	}
	return st.AddRun(ctx, store.Run{
		SessionID:            sessionID,
		SampleID:             sampleID,
		Engine:               "test",
		Status:               "ok",
		V1Allow:              evaluation.Evidence.V1.Allow,
		V2Allow:              evaluation.Evidence.V2.Allow,
		V1Reason:             evaluation.Evidence.V1.Reason,
		V2Reason:             evaluation.Evidence.V2.Reason,
		V1Replica:            evaluation.Evidence.V1.SelectedReplica,
		V2Replica:            evaluation.Evidence.V2.SelectedReplica,
		PermissionDifference: evaluation.Comparison.PermissionDifference,
		Comparable:           true,
		EvidenceJSON:         string(raw),
		EvidenceSHA256:       domain.SHA256Hex(raw),
		StartedAt:            "2026-01-01T00:00:00Z",
		CompletedAt:          "2026-01-01T00:00:00Z",
	})
}
