package report

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"example.com/deserialize-boundary/internal/ledger"
)

func TestFailureReportKeepsManualPendingAndProvidesFollowUp(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	evidenceDir := filepath.Join(dir, "evidence")
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := ledger.Open(filepath.Join(evidenceDir, "experiment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PutCheck(ctx, ledger.Check{
		ID:       "core_run_command",
		Category: "pipeline",
		Passed:   false,
		Expected: "command exits 0",
		Observed: "exit=1",
		Evidence: "core-run.err",
	}); err != nil {
		t.Fatal(err)
	}
	generated, err := Generate(ctx, db, db.Path(), evidenceDir, outDir)
	if err != nil {
		t.Fatal(err)
	}
	if generated.Automated.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", generated.Automated.Verdict)
	}
	if generated.Manual.Status != "PENDING" {
		t.Fatalf("manual status = %s, want PENDING", generated.Manual.Status)
	}
	if len(generated.FollowUps) == 0 || generated.FollowUps[0].Command == "" {
		t.Fatalf("missing executable follow-up: %+v", generated.FollowUps)
	}
	if _, err := os.Stat(filepath.Join(outDir, "automated-conclusions.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "manual-confirmation.md")); err != nil {
		t.Fatal(err)
	}
}

func TestManifestDetectsMutation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.txt")
	if err := os.WriteFile(path, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteManifest(dir); err != nil {
		t.Fatal(err)
	}
	if _, problems, err := VerifyManifest(dir); err != nil || len(problems) != 0 {
		t.Fatalf("initial verification failed: %v %v", err, problems)
	}
	if err := os.WriteFile(path, []byte("modified"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, problems, err := VerifyManifest(dir); err != nil || len(problems) == 0 {
		t.Fatalf("mutation was not detected: %v %v", err, problems)
	}
}
