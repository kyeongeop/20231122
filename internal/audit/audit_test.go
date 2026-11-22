package audit

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"cacheleak.local/experiment/internal/experiment"
)

func TestAuditFullyRunsEvidence(t *testing.T) {
	if _, err := exec.LookPath("clang++"); err != nil {
		t.Skip("clang++ unavailable; libFuzzer-dependent audit is covered by the recorded evidence run")
	}
	_, current, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	t.Setenv("CACHELEAK_ROOT", root)
	workspace := t.TempDir()
	summary, err := experiment.Run(context.Background(), experiment.Options{
		Workspace: workspace,
		RunID:     "audit-run",
		FuzzMode:  "run",
		FuzzRuns:  50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Fuzz == nil || !summary.Fuzz.Found || summary.Fuzz.Status != "completed" {
		t.Fatalf("libFuzzer did not retain a finding: %+v", summary.Fuzz)
	}
	report, err := Verify(context.Background(), filepath.Join(workspace, "evidence.db"), "audit-run")
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK {
		for _, check := range report.Checks {
			if !check.Passed {
				t.Errorf("failed check %s: %s", check.Name, check.Detail)
			}
		}
		t.Fatal("audit did not pass")
	}
}
