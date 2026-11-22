package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"

	"taintlab/internal/canonical"
	"taintlab/internal/model"
)

func (db *DB) LoadRun(ctx context.Context, runID int64) (StoredRun, error) {
	var stored StoredRun
	err := db.sql.QueryRowContext(ctx, `
		SELECT run_id, created_at, result_sha256, result_json
		FROM runs WHERE run_id = ?`, runID).
		Scan(&stored.RunID, &stored.CreatedAt, &stored.ResultSHA256, &stored.ResultJSON)
	if err != nil {
		return stored, fmt.Errorf("load run %d: %w", runID, err)
	}
	if got := canonical.SumBytes(stored.ResultJSON); got != stored.ResultSHA256 {
		return stored, fmt.Errorf("run %d result hash mismatch: stored=%s actual=%s",
			runID, stored.ResultSHA256, got)
	}
	if err := json.Unmarshal(stored.ResultJSON, &stored.Result); err != nil {
		return stored, fmt.Errorf("decode result JSON for run %d: %w", runID, err)
	}
	remarshaled, err := canonical.JSON(stored.Result)
	if err != nil {
		return stored, fmt.Errorf("re-encode result for run %d: %w", runID, err)
	}
	if !bytes.Equal(remarshaled, stored.ResultJSON) {
		return stored, fmt.Errorf("run %d canonical JSON changed after reload", runID)
	}

	operations, err := loadOperations(ctx, db.sql, runID)
	if err != nil {
		return stored, err
	}
	steps, err := loadTaintSteps(ctx, db.sql, runID)
	if err != nil {
		return stored, err
	}
	events, err := loadEvents(ctx, db.sql, runID)
	if err != nil {
		return stored, err
	}
	key, err := loadKeyEvidence(ctx, db.sql, runID)
	if err != nil {
		return stored, err
	}
	diagnostics, err := loadDiagnostics(ctx, db.sql, runID)
	if err != nil {
		return stored, err
	}
	if !reflect.DeepEqual(operations, stored.Result.Attack.Operations) {
		return stored, fmt.Errorf("run %d operations order/content differs from result JSON", runID)
	}
	if !reflect.DeepEqual(steps, stored.Result.Attack.TaintPath) {
		return stored, fmt.Errorf("run %d taint path order/content differs from result JSON", runID)
	}
	if !reflect.DeepEqual(events, stored.Result.Evidence.Events) {
		return stored, fmt.Errorf("run %d evidence event order/content differs from result JSON", runID)
	}
	if !reflect.DeepEqual(key, stored.Result.Evidence.Key) {
		return stored, fmt.Errorf("run %d key evidence order/content differs from result JSON", runID)
	}
	if !reflect.DeepEqual(diagnostics, stored.Result.Diagnostics) {
		return stored, fmt.Errorf("run %d diagnostics order/content differs from result JSON", runID)
	}

	stored.Result.Attack.Operations = operations
	stored.Result.Attack.TaintPath = steps
	stored.Result.Evidence.Events = events
	stored.Result.Evidence.Key = key
	stored.Result.Diagnostics = diagnostics
	return stored, nil
}

func loadOperations(ctx context.Context, db *sql.DB, runID int64) ([]model.Operation, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT ordinal, seq, kind, operand, width_bits, note
		FROM operations WHERE run_id = ? ORDER BY ordinal ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("load operations: %w", err)
	}
	defer rows.Close()
	items := make([]model.Operation, 0)
	for rows.Next() {
		var ordinal int
		var item model.Operation
		if err := rows.Scan(&ordinal, &item.Seq, &item.Kind, &item.Operand,
			&item.WidthBits, &item.Note); err != nil {
			return nil, fmt.Errorf("scan operation: %w", err)
		}
		if ordinal != len(items)+1 {
			return nil, fmt.Errorf("operation ordinal gap: got %d at %d", ordinal, len(items)+1)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func loadTaintSteps(ctx context.Context, db *sql.DB, runID int64) ([]model.TaintStep, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT ordinal, seq, kind, operand, width_bits, before_value, after_value,
			tainted, changed, wrapped, location
		FROM taint_steps WHERE run_id = ? ORDER BY ordinal ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("load taint steps: %w", err)
	}
	defer rows.Close()
	items := make([]model.TaintStep, 0)
	for rows.Next() {
		var ordinal int
		var tainted, changed, wrapped int
		var item model.TaintStep
		if err := rows.Scan(&ordinal, &item.Seq, &item.Kind, &item.Operand,
			&item.WidthBits, &item.Before, &item.After, &tainted, &changed,
			&wrapped, &item.Location); err != nil {
			return nil, fmt.Errorf("scan taint step: %w", err)
		}
		if ordinal != len(items)+1 {
			return nil, fmt.Errorf("taint ordinal gap: got %d at %d", ordinal, len(items)+1)
		}
		item.Ordinal = ordinal
		item.Tainted = tainted != 0
		item.Changed = changed != 0
		item.Wrapped = wrapped != 0
		items = append(items, item)
	}
	return items, rows.Err()
}

func loadEvents(ctx context.Context, db *sql.DB, runID int64) ([]model.LogEvent, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT ordinal, event_id, device_id, kind, causal_order, wall_time,
			monotonic_ns, payload_sha256, detail
		FROM evidence_events WHERE run_id = ? ORDER BY ordinal ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("load events: %w", err)
	}
	defer rows.Close()
	items := make([]model.LogEvent, 0)
	for rows.Next() {
		var item model.LogEvent
		if err := rows.Scan(&item.Ordinal, &item.EventID, &item.DeviceID, &item.Kind,
			&item.CausalOrder, &item.WallTime, &item.MonotonicNS,
			&item.PayloadSHA256, &item.Detail); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		if item.Ordinal != len(items)+1 {
			return nil, fmt.Errorf("event ordinal gap: got %d at %d", item.Ordinal, len(items)+1)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func loadKeyEvidence(ctx context.Context, db *sql.DB, runID int64) ([]model.EvidencePointer, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT ordinal, kind, ref, sha256, note
		FROM key_evidence WHERE run_id = ? ORDER BY ordinal ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("load key evidence: %w", err)
	}
	defer rows.Close()
	items := make([]model.EvidencePointer, 0)
	for rows.Next() {
		var ordinal int
		var item model.EvidencePointer
		if err := rows.Scan(&ordinal, &item.Kind, &item.Ref, &item.SHA256,
			&item.Note); err != nil {
			return nil, fmt.Errorf("scan key evidence: %w", err)
		}
		if ordinal != len(items)+1 {
			return nil, fmt.Errorf("key evidence ordinal gap: got %d at %d", ordinal, len(items)+1)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func loadDiagnostics(ctx context.Context, db *sql.DB, runID int64) ([]model.Diagnostic, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT ordinal, level, code, message
		FROM diagnostics WHERE run_id = ? ORDER BY ordinal ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("load diagnostics: %w", err)
	}
	defer rows.Close()
	items := make([]model.Diagnostic, 0)
	for rows.Next() {
		var item model.Diagnostic
		if err := rows.Scan(&item.Ordinal, &item.Level, &item.Code,
			&item.Message); err != nil {
			return nil, fmt.Errorf("scan diagnostic: %w", err)
		}
		if item.Ordinal != len(items)+1 {
			return nil, fmt.Errorf("diagnostic ordinal gap: got %d at %d", item.Ordinal, len(items)+1)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) LoadAll(ctx context.Context, caseID string) ([]StoredRun, error) {
	query := `SELECT run_id FROM runs`
	args := []any{}
	if caseID != "" {
		query += ` WHERE case_id = ?`
		args = append(args, caseID)
	}
	query += ` ORDER BY run_id ASC`
	rows, err := db.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan run id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	runs := make([]StoredRun, 0, len(ids))
	for _, id := range ids {
		run, err := db.LoadRun(ctx, id)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, nil
}

func (db *DB) CountRuns(ctx context.Context) (int, error) {
	var count int
	if err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count runs: %w", err)
	}
	return count, nil
}
