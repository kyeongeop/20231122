package db

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"auditfix/internal/model"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("database path is required")
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(FULL)"
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	store := &Store{db: sqlDB}
	if err := store.init(context.Background()); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return store, nil
}

func OpenReadOnly(path string) (*Store, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn := "file:" + absolute + "?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)"
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite read-only: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping sqlite read-only: %w", err)
	}
	return &Store{db: sqlDB}, nil
}

func (s *Store) init(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("initialize schema: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES('schema_version', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, model.SchemaVersion); err != nil {
		return fmt.Errorf("write schema version: %w", err)
	}
	return nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) SQL() *sql.DB {
	return s.db
}

func (s *Store) Begin(ctx context.Context) (*sql.Tx, error) {
	return s.db.BeginTx(ctx, nil)
}

func (s *Store) InsertCase(ctx context.Context, c model.Case) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cases(
			case_id, created_at, description, status, analyzer_version,
			clock_offset_ns, chain_status, anchor_pair_count,
			device_a_event_rows, device_b_event_rows, correction_count
		) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		c.CaseID, c.CreatedAt, c.Description, c.Status, c.AnalyzerVersion,
		c.ClockOffsetNS, c.ChainStatus, c.AnchorPairCount,
		c.DeviceAEventRows, c.DeviceBEventRows, c.CorrectionCount)
	if err != nil {
		return fmt.Errorf("insert case: %w", err)
	}
	return nil
}

func (s *Store) ReplaceCaseAnalysis(ctx context.Context, c model.Case, events []model.Event,
	corrections []model.Correction) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM corrections WHERE case_id = ?`, c.CaseID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE case_id = ?`, c.CaseID); err != nil {
		return err
	}
	for _, e := range events {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO events(
				case_id, device, ordinal, seq, time_unix_ns, corrected_time_unix_ns,
				kind, anchor_id, subject, payload_sha256, prev_hash, record_hash,
				line_no, raw_line, hash_valid, chain_relation
			) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			c.CaseID, e.Device, e.Ordinal, e.Seq, e.TimeUnixNS, e.CorrectedNS,
			e.Kind, e.AnchorID, e.Subject, e.PayloadSHA256, e.PrevHash, e.RecordHash,
			e.LineNo, e.RawLine, boolInt(e.HashValid), e.ChainRelation); err != nil {
			return fmt.Errorf("insert event %s/%d: %w", e.Device, e.Seq, err)
		}
	}
	for _, corr := range corrections {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO corrections(
				correction_id, case_id, device, seq_from, seq_to, missing_count,
				left_seq, left_hash, right_seq, right_prev_hash,
				corrected_time_from_unix_ns, corrected_time_to_unix_ns,
				anchor_pairs_used, rationale_code, status, created_at
			) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			corr.CorrectionID, corr.CaseID, corr.Device, corr.SeqFrom, corr.SeqTo,
			corr.MissingCount, corr.LeftSeq, corr.LeftHash, corr.RightSeq,
			corr.RightPrevHash, corr.CorrectedTimeFrom, corr.CorrectedTimeTo,
			corr.AnchorPairsUsed, corr.RationaleCode, corr.Status, corr.CreatedAt); err != nil {
			return fmt.Errorf("insert correction %s: %w", corr.CorrectionID, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE cases SET status=?, analyzer_version=?, clock_offset_ns=?,
			chain_status=?, anchor_pair_count=?, device_a_event_rows=?,
			device_b_event_rows=?, correction_count=? WHERE case_id=?`,
		c.Status, c.AnalyzerVersion, c.ClockOffsetNS, c.ChainStatus,
		c.AnchorPairCount, c.DeviceAEventRows, c.DeviceBEventRows,
		c.CorrectionCount, c.CaseID); err != nil {
		return err
	}
	return tx.Commit()
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func intBool(v int) bool {
	return v != 0
}
