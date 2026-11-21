package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"auditfix/internal/model"
)

func (s *Store) InsertSamples(ctx context.Context, samples []model.Sample, contents [][]byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i, sample := range samples {
		if i >= len(contents) {
			return errors.New("sample content count mismatch")
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO samples(sample_id, case_id, sample_index, name, sha256,
				size, source_name, imported_at, bytes)
			VALUES(?,?,?,?,?,?,?,?,?)`,
			sample.SampleID, sample.CaseID, sample.SampleIndex, sample.Name,
			sample.SHA256, sample.Size, sample.SourceName, sample.ImportedAt,
			contents[i]); err != nil {
			return fmt.Errorf("insert sample %q: %w", sample.Name, err)
		}
	}
	return tx.Commit()
}

func (s *Store) ListSamples(ctx context.Context, caseID string) ([]model.Sample, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sample_id, case_id, sample_index, name, sha256, size,
			source_name, imported_at
		FROM samples WHERE case_id = ? ORDER BY sample_index`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Sample
	for rows.Next() {
		var sample model.Sample
		if err := rows.Scan(&sample.SampleID, &sample.CaseID, &sample.SampleIndex,
			&sample.Name, &sample.SHA256, &sample.Size, &sample.SourceName,
			&sample.ImportedAt); err != nil {
			return nil, err
		}
		out = append(out, sample)
	}
	return out, rows.Err()
}

func (s *Store) FindSample(ctx context.Context, caseID, ref string) (model.Sample, []byte, error) {
	var sample model.Sample
	var data []byte
	query := `SELECT sample_id, case_id, sample_index, name, sha256, size,
		source_name, imported_at, bytes FROM samples
		WHERE case_id = ? AND (sample_id = ? OR name = ? OR sha256 = ?)`
	args := []any{caseID, ref, ref, strings.ToLower(ref)}
	if index, err := strconv.Atoi(ref); err == nil {
		query = `SELECT sample_id, case_id, sample_index, name, sha256, size,
			source_name, imported_at, bytes FROM samples
			WHERE case_id = ? AND (sample_id = ? OR name = ? OR sha256 = ? OR sample_index = ?)`
		args = append(args, index)
	}
	if len(ref) >= 6 && len(ref) < 64 {
		query = `SELECT sample_id, case_id, sample_index, name, sha256, size,
			source_name, imported_at, bytes FROM samples
			WHERE case_id = ? AND (sample_id = ? OR name = ? OR sha256 = ? OR sha256 LIKE ?)
			ORDER BY sample_index LIMIT 1`
		args = append(args, strings.ToLower(ref)+"%")
	}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&sample.SampleID, &sample.CaseID, &sample.SampleIndex, &sample.Name,
		&sample.SHA256, &sample.Size, &sample.SourceName, &sample.ImportedAt, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Sample{}, nil, fmt.Errorf("sample %q: %w", ref, ErrNotFound)
	}
	if err != nil {
		return model.Sample{}, nil, err
	}
	return sample, data, nil
}

func (s *Store) SampleCount(ctx context.Context, caseID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM samples WHERE case_id = ?`, caseID).Scan(&count)
	return count, err
}
