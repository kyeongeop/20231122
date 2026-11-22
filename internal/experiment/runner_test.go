package experiment

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunRecordsEveryStepAndCleansTemp(t *testing.T) {
	workspace := t.TempDir()
	summary, err := Run(context.Background(), Options{
		Workspace: workspace,
		RunID:     "test-run",
		FuzzMode:  "skip",
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Status != "completed" || len(summary.Scenarios) != 5 {
		t.Fatalf("unexpected summary: status=%s scenarios=%d", summary.Status, len(summary.Scenarios))
	}
	totalSteps := 0
	for _, scenario := range summary.Scenarios {
		totalSteps += scenario.StepCount
	}
	if totalSteps != 20 {
		t.Fatalf("expected 20 persisted requests, got %d", totalSteps)
	}
	if summary.TempPathsLeft != 0 {
		t.Fatalf("temporary paths remain: %d", summary.TempPathsLeft)
	}
	if _, err := os.Stat(filepath.Join(workspace, ".tmp")); !os.IsNotExist(err) {
		t.Fatalf("workspace temp root still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workspace, "evidence.db")); err != nil {
		t.Fatalf("SQLite evidence database missing: %v", err)
	}
	if _, err := os.Stat(summary.KeyEvidencePath); err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
	for _, scenario := range summary.Scenarios {
		if !scenario.CleanupOK {
			t.Fatalf("scenario %s did not record cleanup", scenario.Name)
		}
		switch scenario.Name {
		case "order-forward":
			if scenario.LeakCount != 3 {
				t.Fatalf("forward leak count = %d, want 3", scenario.LeakCount)
			}
		case "order-reverse":
			if scenario.LeakCount != 3 {
				t.Fatalf("reverse leak count = %d, want 3", scenario.LeakCount)
			}
		case "error-continuation":
			if scenario.ErrorCount != 1 || scenario.StepCount != 6 {
				t.Fatalf("error continuation counts: %+v", scenario)
			}
		}
	}
	passedKinds := map[string]bool{}
	for _, v := range summary.Verifications {
		passedKinds[v.Kind] = v.Passed
	}
	for _, kind := range []string{"unknown-extension", "order-change", "repeated-submission", "error-continuation", "cleanup"} {
		if !passedKinds[kind] {
			t.Fatalf("verification %q did not pass", kind)
		}
	}
	if passedKinds["libfuzzer"] {
		t.Fatal("skipped libFuzzer verification must not pass")
	}
}
