package store

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"taintlab/internal/canonical"
	"taintlab/internal/model"
	"taintlab/internal/taint"
)

func sampleResult(t *testing.T) model.Result {
	t.Helper()
	data, err := os.ReadFile("../../testdata/cases/unsynced-truncation.json")
	if err != nil {
		t.Fatal(err)
	}
	return taint.Execute(data)
}

func TestSaveReloadPreservesJSONFieldsAndOrder(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "evidence.sqlite")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	result := sampleResult(t)
	runID, err := db.SaveResult(ctx, result, "2026-11-22T04:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	newID, err := db.SaveResult(ctx, result, "2026-11-22T04:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if newID != runID {
		t.Fatalf("duplicate save created a new run: %d != %d", newID, runID)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stored, err := db.LoadRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Result.Attack.Operations) != 2 ||
		stored.Result.Attack.Operations[0].Kind != "add" ||
		stored.Result.Attack.Operations[1].Kind != "trunc" {
		t.Fatalf("operation order changed: %#v", stored.Result.Attack.Operations)
	}
	for i, event := range stored.Result.Evidence.Events {
		if event.Ordinal != i+1 || event.CausalOrder != i+1 {
			t.Fatalf("event order changed: %#v", stored.Result.Evidence.Events)
		}
	}
	expectedJSON, _ := canonical.JSON(result)
	if !bytes.Equal(stored.ResultJSON, expectedJSON) {
		t.Fatal("stored JSON bytes differ from the original canonical result")
	}
	if stored.ResultSHA256 != canonical.SumBytes(expectedJSON) {
		t.Fatal("stored result digest does not cover stored bytes")
	}
}

func TestRejectedInputsArePersisted(t *testing.T) {
	ctx := context.Background()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cases := []model.Result{
		taint.Execute(nil),
		taint.Execute(bytes.Repeat([]byte("x"), taint.MaxInputBytes+1)),
		taint.Execute([]byte("{")),
	}
	for index, result := range cases {
		id, err := db.SaveResult(ctx, result, "2026-11-22T04:00:00Z")
		if err != nil {
			t.Fatalf("save case %d: %v", index, err)
		}
		stored, err := db.LoadRun(ctx, id)
		if err != nil {
			t.Fatalf("load case %d: %v", index, err)
		}
		if stored.Result.Input.SHA256 != result.Input.SHA256 ||
			stored.Result.Evidence.SHA256 != result.Evidence.SHA256 {
			t.Fatalf("evidence changed for case %d", index)
		}
	}
	count, err := db.CountRuns(ctx)
	if err != nil || count != 3 {
		t.Fatalf("count = %d, err=%v", count, err)
	}
}

func TestTamperIsDetected(t *testing.T) {
	ctx := context.Background()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	runID, err := db.SaveResult(ctx, sampleResult(t), "2026-11-22T04:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	var resultJSON []byte
	if err := db.sql.QueryRowContext(ctx,
		`SELECT result_json FROM runs WHERE run_id = ?`, runID).Scan(&resultJSON); err != nil {
		t.Fatal(err)
	}
	var changed map[string]any
	if err := json.Unmarshal(resultJSON, &changed); err != nil {
		t.Fatal(err)
	}
	changed["status"] = "tampered"
	tampered, _ := json.Marshal(changed)
	if _, err := db.sql.ExecContext(ctx,
		`UPDATE runs SET result_json = ? WHERE run_id = ?`, tampered, runID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.LoadRun(ctx, runID); err == nil {
		t.Fatal("tampered JSON was accepted")
	}
}

func TestDetailRowTamperIsDetected(t *testing.T) {
	ctx := context.Background()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	runID, err := db.SaveResult(ctx, sampleResult(t), "2026-11-22T04:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx,
		`UPDATE evidence_events SET kind = 'tampered' WHERE run_id = ? AND ordinal = 2`,
		runID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.LoadRun(ctx, runID); err == nil {
		t.Fatal("tampered event row was accepted")
	}
}
