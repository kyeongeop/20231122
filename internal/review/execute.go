package review

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"example.com/migration-review/internal/evidence"
	"example.com/migration-review/internal/model"
	_ "modernc.org/sqlite"
)

type schemaSnapshot struct {
	UserVersion int              `json:"user_version"`
	Objects     []map[string]any `json:"objects"`
	Hash        string           `json:"hash"`
}

func executeAllowed(ctx, evCtx context.Context, store *evidence.Store, manifest *model.Manifest, record model.RunRecord, headHash string, opts Options) (model.RunRecord, error) {
	db, err := openTarget(opts.TargetPath)
	if err != nil {
		return failBeforeExecution(evCtx, store, record, headHash, err)
	}
	defer db.Close()

	before, err := captureSchema(ctx, db)
	if err != nil {
		return failBeforeExecution(evCtx, store, record, headHash, fmt.Errorf("capture schema before: %w", err))
	}
	record.SchemaBefore = before.Hash
	record.Trigger = record.Decision.Statements[0].Trigger
	if err := store.AddArtifact(evCtx, record.RunID, evidence.Artifact{
		Kind: "schema", Name: "before.json", Content: mustPretty(before),
	}); err != nil {
		return failBeforeExecution(evCtx, store, record, headHash, fmt.Errorf("record schema before: %w", err))
	}
	entry, err := store.Log(evCtx, record.RunID, "INFO", "execution_start", mustJSON(map[string]any{
		"target":        opts.TargetPath,
		"schema_before": before.Hash,
		"cancel_after":  opts.CancelAfter,
	}))
	if err != nil {
		return record, err
	}
	headHash = entry.Hash

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	tx, err := db.BeginTx(runCtx, nil)
	if err != nil {
		return failBeforeExecution(evCtx, store, record, headHash, fmt.Errorf("begin migration transaction: %w", err))
	}
	defer tx.Rollback()

	executed := 0
	for _, statement := range manifest.Statements {
		if err := runCtx.Err(); err != nil {
			reason := fmt.Sprintf("cancelled after %d of %d statements; transaction rolled back", executed, len(manifest.Statements))
			return finishRollback(evCtx, store, db, tx, record, headHash, model.StatusCancelled, reason, err)
		}
		started := time.Now()
		entry, logErr := store.Log(evCtx, record.RunID, "INFO", "statement_start", mustJSON(map[string]any{
			"index":   statement.Index,
			"trigger": record.Decision.Statements[statement.Index].Trigger,
			"sha256":  model.SHA256Hex([]byte(statement.SQL)),
		}))
		if logErr != nil {
			return record, logErr
		}
		headHash = entry.Hash
		executed++
		_, execErr := tx.ExecContext(runCtx, statement.SQL)
		if execErr != nil {
			status := model.StatusFailed
			reason := fmt.Sprintf("statement %d failed: %v", statement.Index+1, execErr)
			if runCtx.Err() != nil {
				status = model.StatusCancelled
				reason = "cancelled while executing statement"
			}
			return finishRollback(evCtx, store, db, tx, record, headHash, status, reason, execErr)
		}
		entry, logErr = store.Log(evCtx, record.RunID, "INFO", "statement_executed", mustJSON(map[string]any{
			"index":       statement.Index,
			"duration_ms": time.Since(started).Milliseconds(),
			"trigger":     record.Decision.Statements[statement.Index].Trigger,
		}))
		if logErr != nil {
			return record, logErr
		}
		headHash = entry.Hash
		if opts.AfterStatement != nil {
			opts.AfterStatement(runCtx, statement.Index)
		}
		if opts.CancelAfter > 0 && statement.Index+1 >= opts.CancelAfter {
			entry, logErr = store.Log(evCtx, record.RunID, "WARN", "cancel_requested", mustJSON(map[string]any{
				"after_statement": statement.Index + 1,
				"reason":          "scenario cancellation drill",
			}))
			if logErr != nil {
				return record, logErr
			}
			headHash = entry.Hash
			cancelRun()
		}
	}
	if err := runCtx.Err(); err != nil {
		reason := fmt.Sprintf("cancelled after %d of %d statements before commit", executed, len(manifest.Statements))
		return finishRollback(evCtx, store, db, tx, record, headHash, model.StatusCancelled, reason, err)
	}
	if err := tx.Commit(); err != nil {
		if runCtx.Err() != nil {
			return finishRollback(evCtx, store, db, tx, record, headHash, model.StatusCancelled, "cancelled during commit", err)
		}
		return finishRollback(evCtx, store, db, tx, record, headHash, model.StatusFailed, "commit failed", err)
	}

	after, err := captureSchema(context.Background(), db)
	if err != nil {
		return finishCommittedFailure(evCtx, store, record, headHash, fmt.Errorf("capture schema after commit: %w", err))
	}
	record.SchemaAfter = after.Hash
	record.RollbackOK = true
	record.Status = model.StatusAllowed
	record.Reason = "all statements executed and committed"
	if err := store.AddArtifact(evCtx, record.RunID, evidence.Artifact{
		Kind: "schema", Name: "after.json", Content: mustPretty(after),
	}); err != nil {
		return record, fmt.Errorf("record schema after: %w", err)
	}
	entry, err = store.Log(evCtx, record.RunID, "INFO", "commit", mustJSON(map[string]any{
		"schema_before":  before.Hash,
		"schema_after":   after.Hash,
		"schema_changed": before.Hash != after.Hash,
	}))
	if err != nil {
		return record, err
	}
	record.LogHeadHash = entry.Hash
	now := time.Now().UTC()
	record.CompletedAt = &now
	if err := store.CompleteRun(evCtx, record); err != nil {
		return record, err
	}
	return store.GetRun(evCtx, record.RunID)
}

func finishRollback(evCtx context.Context, store *evidence.Store, db *sql.DB, tx *sql.Tx, record model.RunRecord, headHash string, status model.RunStatus, reason string, cause error) (model.RunRecord, error) {
	_ = cause
	if txErr := tx.Rollback(); txErr != nil && txErr != sql.ErrTxDone {
		reason += "; rollback error: " + txErr.Error()
	}
	return finishStopped(evCtx, store, db, record, headHash, status, reason, true)
}

func finishStopped(evCtx context.Context, store *evidence.Store, db *sql.DB, record model.RunRecord, headHash string, status model.RunStatus, reason string, attemptedRollback bool) (model.RunRecord, error) {
	after, schemaErr := captureSchema(context.Background(), db)
	if schemaErr != nil {
		reason += "; schema verification failed: " + schemaErr.Error()
		record.SchemaAfter = ""
	} else {
		record.SchemaAfter = after.Hash
	}
	record.RollbackOK = attemptedRollback && schemaErr == nil && record.SchemaBefore != "" && record.SchemaBefore == record.SchemaAfter
	record.Status = status
	record.Reason = reason
	if after.Hash != "" {
		if err := store.AddArtifact(evCtx, record.RunID, evidence.Artifact{
			Kind: "schema", Name: "after.json", Content: mustPretty(after),
		}); err != nil {
			return record, fmt.Errorf("record schema after %s: %w", status, err)
		}
	}
	level := "WARN"
	if status == model.StatusFailed {
		level = "ERROR"
	}
	entry, err := store.Log(evCtx, record.RunID, level, "rollback", mustJSON(map[string]any{
		"status":        status,
		"reason":        reason,
		"schema_before": record.SchemaBefore,
		"schema_after":  record.SchemaAfter,
		"rollback_ok":   record.RollbackOK,
		"head_before":   headHash,
	}))
	if err != nil {
		return record, fmt.Errorf("log rollback: %w", err)
	}
	record.LogHeadHash = entry.Hash
	now := time.Now().UTC()
	record.CompletedAt = &now
	if err := store.CompleteRun(evCtx, record); err != nil {
		return record, err
	}
	stored, err := store.GetRun(evCtx, record.RunID)
	if err != nil {
		return record, err
	}
	return stored, &RunError{RunID: record.RunID, Status: status, Reason: reason}
}

func failBeforeExecution(evCtx context.Context, store *evidence.Store, record model.RunRecord, headHash string, cause error) (model.RunRecord, error) {
	record.Status = model.StatusFailed
	record.Reason = cause.Error()
	entry, err := store.Log(evCtx, record.RunID, "ERROR", "pre_execution_failure", cause.Error())
	if err == nil {
		record.LogHeadHash = entry.Hash
	}
	now := time.Now().UTC()
	record.CompletedAt = &now
	if completeErr := store.CompleteRun(evCtx, record); completeErr != nil {
		return record, fmt.Errorf("%v; complete evidence: %w", cause, completeErr)
	}
	stored, getErr := store.GetRun(evCtx, record.RunID)
	if getErr != nil {
		return record, getErr
	}
	return stored, &RunError{RunID: record.RunID, Status: model.StatusFailed, Reason: record.Reason}
}

func finishCommittedFailure(evCtx context.Context, store *evidence.Store, record model.RunRecord, headHash string, cause error) (model.RunRecord, error) {
	record.Status = model.StatusFailed
	record.Reason = cause.Error() + "; migration may already be committed"
	entry, err := store.Log(evCtx, record.RunID, "ERROR", "post_commit_failure", record.Reason)
	if err == nil {
		record.LogHeadHash = entry.Hash
	} else {
		record.LogHeadHash = headHash
	}
	now := time.Now().UTC()
	record.CompletedAt = &now
	if completeErr := store.CompleteRun(evCtx, record); completeErr != nil {
		return record, completeErr
	}
	return store.GetRun(evCtx, record.RunID)
}

func openTarget(path string) (*sql.DB, error) {
	resolved, err := resolvePath(path)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(resolved) && len(resolved) > 0 && resolved[0] != ':' {
		if err := os.MkdirAll(filepath.Dir(resolved), 0o755); err != nil {
			return nil, fmt.Errorf("create target directory: %w", err)
		}
	}
	dsn := resolved
	if resolved != ":memory:" {
		dsn = (&url.URL{Scheme: "file", Path: resolved}).String() +
			"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open target database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping target database: %w", err)
	}
	return db, nil
}

func captureSchema(ctx context.Context, db *sql.DB) (schemaSnapshot, error) {
	var snapshot schemaSnapshot
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&snapshot.UserVersion); err != nil {
		return snapshot, err
	}
	rows, err := db.QueryContext(ctx, `SELECT type, name, tbl_name, COALESCE(sql, '')
		FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'
		ORDER BY type, name`)
	if err != nil {
		return snapshot, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, name, table, sqlText string
		if err := rows.Scan(&kind, &name, &table, &sqlText); err != nil {
			return snapshot, err
		}
		snapshot.Objects = append(snapshot.Objects, map[string]any{
			"type": kind, "name": name, "table": table, "sql": sqlText,
		})
	}
	if err := rows.Err(); err != nil {
		return snapshot, err
	}
	payload, _ := json.Marshal(snapshot)
	snapshot.Hash = model.SHA256Hex(payload)
	return snapshot, nil
}

func mustPretty(value any) []byte {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return []byte(fmt.Sprintf("%+v", value))
	}
	return data
}
