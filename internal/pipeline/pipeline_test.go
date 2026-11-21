package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"lfireview/internal/model"
)

const validV2 = `{
	"schema": "lfi-evidence/v2",
	"incident": {
		"correlation_id": "LFI-T1",
		"attack": {"input": "../../etc/passwd"},
		"trigger": {"file": "fs.go", "line": 9, "symbol": "Serve"},
		"permission": {"decision": "permit", "rule": "prefix"},
		"log": {"path": "a.log", "line": 1, "snippet": "200"}
	}
}`

const truncatedV1 = `{
	"correlation_id": "LFI-T2",
	"payload": "php://filter/x",
	"trigger_file": "t.go",
	"trigger_line": 3`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunContinuesAfterBadObjectsAndCleansTemp(t *testing.T) {
	root := t.TempDir()
	v1 := filepath.Join(root, "v1")
	v2 := filepath.Join(root, "v2")

	writeFile(t, filepath.Join(v1, "good.json"),
		`{"correlation_id":"LFI-T1","payload":"../../etc/passwd",
		  "trigger_file":"fs.go","trigger_line":9,"trigger_symbol":"Serve",
		  "access_verdict":"permit","access_rule":"prefix",
		  "log_file":"a.log","log_line":1,"log_evidence":"200"}`)
	writeFile(t, filepath.Join(v1, "cut.json"), truncatedV1)
	writeFile(t, filepath.Join(v1, "bad.json"), `###not-json###`)
	writeFile(t, filepath.Join(v2, "good.json"), validV2)
	writeFile(t, filepath.Join(v2, "cut.json"),
		`{"schema":"lfi-evidence/v2","incident":{"correlation_id":"LFI-T2"`)

	// Empty DBPath -> temporary database that must be removed on cleanup.
	report, err := Run(context.Background(), Config{SnapshotV1: v1, SnapshotV2: v2})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if report.Total != 5 {
		t.Fatalf("total = %d, want 5 (all objects attempted)", report.Total)
	}
	if report.Failed != 1 {
		t.Fatalf("failed = %d, want 1 (only the garbage object)", report.Failed)
	}
	if report.TruncatedN != 2 {
		t.Fatalf("truncated = %d, want 2", report.TruncatedN)
	}

	byStatus := map[string]model.ParseStatus{}
	for _, res := range report.Results {
		byStatus[res.Version+"/"+res.Object] = res.Status
	}
	if byStatus["v1/good.json"] != model.StatusOK {
		t.Fatalf("good v1 object not ok: %+v", byStatus)
	}
	if byStatus["v1/cut.json"] != model.StatusTruncated {
		t.Fatalf("cut v1 not truncated: %+v", byStatus)
	}
	if byStatus["v1/bad.json"] != model.StatusMalformed {
		t.Fatalf("bad v1 not malformed: %+v", byStatus)
	}
	if byStatus["v2/cut.json"] != model.StatusTruncated {
		t.Fatalf("cut v2 not truncated: %+v", byStatus)
	}

	if !report.TempDB {
		t.Fatal("expected temporary database")
	}
	for _, p := range report.CleanedUp {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("temporary state still present: %s (err=%v)", p, err)
		}
	}
	if _, err := os.Stat(report.TempWorkDir); !os.IsNotExist(err) {
		t.Fatalf("work dir not removed: %s", report.TempWorkDir)
	}
}

func TestRunPersistsToNamedDatabase(t *testing.T) {
	root := t.TempDir()
	v1 := filepath.Join(root, "v1")
	v2 := filepath.Join(root, "v2")
	writeFile(t, filepath.Join(v1, "good.json"),
		`{"correlation_id":"LFI-T1","payload":"x"}`)
	writeFile(t, filepath.Join(v2, "good.json"), validV2)

	dbPath := filepath.Join(root, "keep", "review.sqlite")
	report, err := Run(context.Background(),
		Config{SnapshotV1: v1, SnapshotV2: v2, DBPath: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	if report.TempDB {
		t.Fatal("named database must not be treated as temp")
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("named database missing after run: %v", err)
	}
}

func TestRunMissingSnapshotFails(t *testing.T) {
	if _, err := Run(context.Background(), Config{
		SnapshotV1: filepath.Join(t.TempDir(), "missing"),
		SnapshotV2: t.TempDir(),
	}); err == nil {
		t.Fatal("missing snapshot must be a fatal error")
	}
}
