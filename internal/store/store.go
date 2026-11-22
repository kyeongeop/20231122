package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"taintlab/internal/model"
)

type DB struct {
	sql  *sql.DB
	path string
}

type StoredRun struct {
	RunID        int64
	CreatedAt    string
	ResultSHA256 string
	ResultJSON   []byte
	Result       model.Result
}

func Open(path string) (*DB, error) {
	if path == "" {
		return nil, fmt.Errorf("database path is empty")
	}
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	db := &DB{sql: sqlDB, path: path}
	if err := db.initialize(context.Background()); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) Close() error {
	return db.sql.Close()
}

func (db *DB) Path() string {
	return db.path
}

func (db *DB) initialize(ctx context.Context) error {
	for _, statement := range schemaStatements {
		if _, err := db.sql.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize sqlite: %w", err)
		}
	}
	for key, value := range map[string]string{
		"schema_version": model.SchemaVersion,
		"result_schema":  model.ResultSchema,
		"format":         "sqlite",
	} {
		if _, err := db.sql.ExecContext(ctx,
			`INSERT OR IGNORE INTO artifact_meta(key, value) VALUES(?, ?)`, key, value); err != nil {
			return fmt.Errorf("write artifact metadata: %w", err)
		}
	}
	return nil
}
