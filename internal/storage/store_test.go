package storage

import (
	"context"
	"testing"

	"lfireview/internal/model"
)

func testRecord(corr, version string, status model.ParseStatus) model.EvidenceRecord {
	return model.EvidenceRecord{
		CorrelationID:      corr,
		SnapshotVersion:    version,
		SourceObject:       corr + ".json",
		AttackInput:        "../../etc/passwd",
		TriggerFile:        "fs.go",
		TriggerLine:        10,
		TriggerSymbol:      "Serve",
		PermissionDecision: model.PermitAll,
		PermissionRule:     "prefix",
		LogPath:            "access.log",
		LogLine:            88,
		LogSnippet:         "200",
		Status:             status,
		ParseError:         "unexpected end of JSON input",
		Raw:                []byte("{truncated"),
	}
}

func TestInsertAndQueryTruncated(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close(ctx)

	if err := store.BeginRun(ctx, "run-1", "2026-11-22T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InsertRecord(ctx, "run-1", "2026-11-22T00:00:01Z",
		testRecord("LFI-1", "v1", model.StatusOK)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InsertRecord(ctx, "run-1", "2026-11-22T00:00:02Z",
		testRecord("LFI-3", "v1", model.StatusTruncated)); err != nil {
		t.Fatal(err)
	}

	rows, err := store.QueryTruncated(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].CorrelationID != "LFI-3" {
		t.Fatalf("want exactly one truncated row LFI-3, got %+v", rows)
	}
	if rows[0].Recovered["attack_input"] != "../../etc/passwd" {
		t.Fatalf("recovered field missing: %+v", rows[0].Recovered)
	}

	if err := store.FinishRun(ctx, "run-1", "2026-11-22T00:00:03Z",
		"completed_with_errors", 2, 0); err != nil {
		t.Fatal(err)
	}

	var status string
	var total, failed int
	err = store.db.QueryRowContext(ctx,
		`SELECT status, object_total, object_failed FROM runs WHERE run_id='run-1'`).
		Scan(&status, &total, &failed)
	if err != nil {
		t.Fatal(err)
	}
	if status != "completed_with_errors" || total != 2 {
		t.Fatalf("run counters wrong: %s %d %d", status, total, failed)
	}
}

func TestReviewViewJoinsSnapshots(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close(ctx)

	if err := store.BeginRun(ctx, "run-2", "t0"); err != nil {
		t.Fatal(err)
	}
	v1 := testRecord("LFI-9", "v1", model.StatusTruncated)
	v2 := testRecord("LFI-9", "v2", model.StatusOK)
	if _, err := store.InsertRecord(ctx, "run-2", "t1", v1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InsertRecord(ctx, "run-2", "t2", v2); err != nil {
		t.Fatal(err)
	}

	var v1Status, v2Status string
	err = store.db.QueryRowContext(ctx,
		`SELECT v1_parse_status, v2_parse_status FROM review_pairs
		 WHERE correlation_id = 'LFI-9'`).Scan(&v1Status, &v2Status)
	if err != nil {
		t.Fatalf("review view query: %v", err)
	}
	if v1Status != "truncated" || v2Status != "ok" {
		t.Fatalf("pair status wrong: %s / %s", v1Status, v2Status)
	}
}

func TestRemoveDeletesSidecars(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/nested/review.sqlite"
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginRun(ctx, "r", "t"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := store.Remove(); err != nil {
		t.Fatalf("remove must be idempotent, got %v", err)
	}
}
