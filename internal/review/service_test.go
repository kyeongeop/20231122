package review_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"example.com/migration-review/internal/evidence"
	"example.com/migration-review/internal/manifest"
	"example.com/migration-review/internal/model"
	"example.com/migration-review/internal/policy"
	"example.com/migration-review/internal/review"
	_ "modernc.org/sqlite"
)

func TestCancellationRollsBackAndRetainsEvidence(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.db")
	initTarget(t, target)
	store, err := evidence.Open(filepath.Join(dir, "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := loadEngine(t)
	m := loadManifest(t, "../../testdata/migrations/new-cancel-index.json", "new-cancel-index.json")

	record, err := review.Run(context.Background(), store, engine, m, review.Options{
		TargetPath:  target,
		InputPath:   "testdata/migrations/new-cancel-index.json",
		RunID:       "cancel-test",
		CancelAfter: 1,
	})
	var runErr *review.RunError
	if !errors.As(err, &runErr) || runErr.Status != model.StatusCancelled {
		t.Fatalf("expected cancellation, got record=%#v err=%v", record, err)
	}
	if !record.RollbackOK || record.SchemaBefore != record.SchemaAfter {
		t.Fatalf("rollback evidence mismatch: %#v", record)
	}
	assertTableMissing(t, target, "cancel_probe")
	if err := store.VerifyChain(context.Background(), record.RunID); err != nil {
		t.Fatalf("log chain invalid: %v", err)
	}
	if err := store.VerifyArtifacts(context.Background(), record.RunID); err != nil {
		t.Fatalf("artifact hash invalid: %v", err)
	}
	logs, err := store.Logs(context.Background(), record.RunID)
	if err != nil {
		t.Fatal(err)
	}
	events := map[string]bool{}
	for _, entry := range logs {
		events[entry.Event] = true
	}
	for _, want := range []string{"preflight", "permission_decision", "statement_executed", "cancel_requested", "rollback"} {
		if !events[want] {
			t.Fatalf("missing log event %q in %#v", want, events)
		}
	}
}

func TestDeniedAttackIsNotExecuted(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.db")
	initTarget(t, target)
	store, err := evidence.Open(filepath.Join(dir, "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := loadEngine(t)
	m := loadManifest(t, "../../testdata/attack/legacy-drop-audit.json", "legacy-drop-audit.json")
	record, err := review.Run(context.Background(), store, engine, m, review.Options{
		TargetPath: target,
		InputPath:  "testdata/attack/legacy-drop-audit.json",
		RunID:      "attack-test",
	})
	var runErr *review.RunError
	if !errors.As(err, &runErr) || runErr.Status != model.StatusDenied {
		t.Fatalf("expected denial, got record=%#v err=%v", record, err)
	}
	if record.Trigger.Token != "DROP" || record.Trigger.Line != 3 {
		t.Fatalf("attack trigger not retained: %#v", record.Trigger)
	}
	assertTableExists(t, target, "audit_log")
	assertColumnMissing(t, target, "accounts", "last_seen")
}

func initTarget(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	statements := []string{
		"CREATE TABLE accounts (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
		"CREATE TABLE audit_log (id INTEGER PRIMARY KEY, event TEXT NOT NULL)",
		"INSERT INTO accounts(name) VALUES ('reviewer')",
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("initialize target: %v", err)
		}
	}
}

func assertTableMissing(t *testing.T, path, table string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("table %q survived rollback", table)
	}
}

func assertTableExists(t *testing.T, path, table string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("table %q missing", table)
	}
}

func assertColumnMissing(t *testing.T, path, table, column string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, kind string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		if name == column {
			t.Fatalf("column %s.%s was applied by denied input", table, column)
		}
	}
}

func loadEngine(t *testing.T) *policy.Engine {
	t.Helper()
	data, err := os.ReadFile("../../config/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func loadManifest(t *testing.T, path, source string) *model.Manifest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse(data, source)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
