package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"taintlab/internal/canonical"
	"taintlab/internal/model"
)

func (db *DB) SaveResult(ctx context.Context, result model.Result, createdAt string) (int64, error) {
	if createdAt == "" {
		createdAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if _, err := time.Parse(time.RFC3339Nano, createdAt); err != nil {
		return 0, fmt.Errorf("created_at is not RFC3339: %w", err)
	}
	if err := validateResultOrder(result); err != nil {
		return 0, err
	}
	resultJSON, err := canonical.JSON(result)
	if err != nil {
		return 0, fmt.Errorf("encode result: %w", err)
	}
	resultSHA := canonical.SumBytes(resultJSON)

	var existing int64
	err = db.sql.QueryRowContext(ctx, `
		SELECT run_id FROM runs
		WHERE case_id = ? AND trace_id = ? AND result_sha256 = ?`,
		result.CaseID, result.TraceID, resultSHA).Scan(&existing)
	if err == nil {
		return existing, nil
	}
	if err != sql.ErrNoRows {
		return 0, fmt.Errorf("check existing run: %w", err)
	}

	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin save: %w", err)
	}
	defer tx.Rollback()

	insert, err := tx.ExecContext(ctx, `
		INSERT INTO runs(
			case_id, trace_id, created_at, status, decision,
			trigger_detected, tainted_escalation, clock_skew_ms,
			input_sha256, input_size, input_state, evidence_sha256,
			result_sha256, result_json
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.CaseID, result.TraceID, createdAt, result.Status, result.Permission.Decision,
		boolInt(result.Trigger.Detected), boolInt(result.Permission.TaintedEscalation),
		result.Evidence.Clock.SkewMS, result.Input.SHA256, result.Input.SizeBytes,
		result.Input.State, result.Evidence.SHA256, resultSHA, resultJSON)
	if err != nil {
		return 0, fmt.Errorf("insert run: %w", err)
	}
	runID, err := insert.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read run id: %w", err)
	}
	if err := insertDetails(ctx, tx, runID, result); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit save: %w", err)
	}
	return runID, nil
}

func insertDetails(ctx context.Context, tx *sql.Tx, runID int64, result model.Result) error {
	for index, operation := range result.Attack.Operations {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO operations(run_id, ordinal, seq, kind, operand, width_bits, note)
			VALUES(?, ?, ?, ?, ?, ?, ?)`,
			runID, index+1, operation.Seq, operation.Kind, operation.Operand,
			operation.WidthBits, operation.Note); err != nil {
			return fmt.Errorf("insert operation %d: %w", index+1, err)
		}
	}
	for _, step := range result.Attack.TaintPath {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO taint_steps(
				run_id, ordinal, seq, kind, operand, width_bits,
				before_value, after_value, tainted, changed, wrapped, location
			) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			runID, step.Ordinal, step.Seq, step.Kind, step.Operand, step.WidthBits,
			step.Before, step.After, boolInt(step.Tainted), boolInt(step.Changed),
			boolInt(step.Wrapped), step.Location); err != nil {
			return fmt.Errorf("insert taint step %d: %w", step.Ordinal, err)
		}
	}
	for _, event := range result.Evidence.Events {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO evidence_events(
				run_id, ordinal, event_id, device_id, kind, causal_order,
				wall_time, monotonic_ns, payload_sha256, detail
			) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			runID, event.Ordinal, event.EventID, event.DeviceID, event.Kind,
			event.CausalOrder, event.WallTime, event.MonotonicNS,
			event.PayloadSHA256, event.Detail); err != nil {
			return fmt.Errorf("insert evidence event %d: %w", event.Ordinal, err)
		}
	}
	for index, pointer := range result.Evidence.Key {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO key_evidence(run_id, ordinal, kind, ref, sha256, note)
			VALUES(?, ?, ?, ?, ?, ?)`,
			runID, index+1, pointer.Kind, pointer.Ref, pointer.SHA256, pointer.Note); err != nil {
			return fmt.Errorf("insert key evidence %d: %w", index+1, err)
		}
	}
	for _, diagnostic := range result.Diagnostics {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO diagnostics(run_id, ordinal, level, code, message)
			VALUES(?, ?, ?, ?, ?)`,
			runID, diagnostic.Ordinal, diagnostic.Level, diagnostic.Code,
			diagnostic.Message); err != nil {
			return fmt.Errorf("insert diagnostic %d: %w", diagnostic.Ordinal, err)
		}
	}
	return nil
}

func validateResultOrder(result model.Result) error {
	for index, step := range result.Attack.TaintPath {
		if step.Ordinal != index+1 {
			return fmt.Errorf("taint step ordinal %d at position %d", step.Ordinal, index+1)
		}
	}
	for index, event := range result.Evidence.Events {
		if event.Ordinal != index+1 {
			return fmt.Errorf("event ordinal %d at position %d", event.Ordinal, index+1)
		}
		if event.CausalOrder != index+1 {
			return fmt.Errorf("event causal order %d at position %d", event.CausalOrder, index+1)
		}
	}
	for index, diagnostic := range result.Diagnostics {
		if diagnostic.Ordinal != index+1 {
			return fmt.Errorf("diagnostic ordinal %d at position %d", diagnostic.Ordinal, index+1)
		}
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
