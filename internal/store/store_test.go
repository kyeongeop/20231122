package store

import (
	"errors"
	"path/filepath"
	"testing"

	"depthlab/internal/graphql"
)

func TestSQLiteEventChainAndDuplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.sqlite")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	rows, err := s.DB.Query("SELECT sqlite_version()")
	if err != nil {
		t.Fatal(err)
	}
	var version string
	if !rows.Next() {
		t.Fatal("sqlite_version returned no row")
	}
	if err := rows.Scan(&version); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if version == "" {
		t.Fatal("sqlite version is empty")
	}

	recordID := "rec_test"
	err = s.InsertRecord(Record{
		RecordID: recordID, Kind: "test",
		OriginalSHA256: "a", TruncatedSHA256: "b", RecoverySHA256: "a",
		OmittedSuffix: []byte("}"),
		Original:      []byte("query { a }"), Truncated: []byte("query { a"),
		Recovered: []byte("query { a }"), FuzzerArtifactPath: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	runID := "run_test"
	if err := s.CreateRun(Run{RunID: runID, RecordID: recordID, Scenario: "test"}); err != nil {
		t.Fatal(err)
	}

	trace := graphql.Analyze("query { a }", 4)
	if trace.FirstError != nil {
		t.Fatalf("unexpected analysis failure: %+v", trace.FirstError)
	}
	for _, step := range trace.Steps {
		if _, err := s.SubmitStep(runID, step, runID+"/"+step.Stage); err != nil {
			t.Fatalf("submit %s: %v", step.Stage, err)
		}
	}
	if err := s.FinishRun(runID, trace); err != nil {
		t.Fatal(err)
	}

	steps, err := s.LoadSteps(runID)
	if err != nil {
		t.Fatal(err)
	}
	if violation := VerifyChain(runID, steps); violation != nil {
		t.Fatalf("chain verification failed: %v", violation)
	}

	_, err = s.SubmitStep(runID, trace.Steps[1], "duplicate-key")
	var violation *Violation
	if !errors.As(err, &violation) {
		t.Fatalf("duplicate submit error = %v, want *Violation", err)
	}
	if violation.Code != "DUPLICATE_STEP" || violation.Seq != 2 {
		t.Fatalf("duplicate violation = %+v", violation)
	}
	rejected, err := s.Count("SELECT COUNT(*) FROM submissions WHERE run_id=? AND decision='rejected'", runID)
	if err != nil {
		t.Fatal(err)
	}
	if rejected != 1 {
		t.Fatalf("rejected submissions = %d, want 1", rejected)
	}
}

func TestOutOfOrderSubmissionIsRejectedAtFirstBadStep(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.sqlite")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.InsertRecord(Record{
		RecordID: "rec", Kind: "test", OriginalSHA256: "a", TruncatedSHA256: "a",
		RecoverySHA256: "a", Original: []byte("x"), Truncated: []byte("x"),
		Recovered: []byte("x"), FuzzerArtifactPath: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRun(Run{RunID: "run", RecordID: "rec", Scenario: "test"}); err != nil {
		t.Fatal(err)
	}
	trace := graphql.Analyze("query { a }", 4)
	_, err = s.SubmitStep("run", trace.Steps[2], "run/3")
	var violation *Violation
	if !errors.As(err, &violation) {
		t.Fatalf("out-of-order error = %v, want *Violation", err)
	}
	if violation.Code != "STEP_OUT_OF_ORDER" || violation.Seq != 3 {
		t.Fatalf("out-of-order violation = %+v", violation)
	}
}
