package experiment

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExecuteProducesVerifiableFirstErrorEvidence(t *testing.T) {
	dir := t.TempDir()
	recordPath := filepath.Join(dir, "crash.graphql")
	query := "query Deep { viewer { friends { friends { friends { name } } } } }"
	if err := os.WriteFile(recordPath, []byte(query), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "artifacts")
	report, err := Execute(Options{OutDir: out, FuzzRecordPath: recordPath, Limit: 4})
	if err != nil {
		t.Fatal(err)
	}
	if report.FirstErrors["truncated"].Seq != 3 {
		t.Fatalf("truncated first error = %+v", report.FirstErrors["truncated"])
	}
	if report.FirstErrors["recovered_control"].Seq != 5 {
		t.Fatalf("recovered first error = %+v", report.FirstErrors["recovered_control"])
	}
	if report.FirstErrors["check_order_changed"].Code != "STEP_OUT_OF_ORDER" {
		t.Fatalf("order check first error = %+v", report.FirstErrors["check_order_changed"])
	}
	if report.FirstErrors["check_duplicate_submission"].Code != "DUPLICATE_STEP" {
		t.Fatalf("duplicate check first error = %+v", report.FirstErrors["check_duplicate_submission"])
	}
	message, err := Verify(
		filepath.Join(out, "evidence.sqlite"),
		filepath.Join(out, "report.json"),
		filepath.Join(out, "manifest.sha256"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if message == "" {
		t.Fatal("verification message is empty")
	}
}
