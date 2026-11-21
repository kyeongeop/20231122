package store

import (
	"context"
	"database/sql"
	"time"
)

// NowUTC returns the canonical timestamp format: RFC3339 nanosecond UTC.
func NowUTC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// Sample is one attack or benign input with its three raw anchor offsets.
type Sample struct {
	ID            int64
	Name          string
	Kind          string
	RawPath       string
	SHA256        string
	Size          int64
	AnchorOffsets [3]int64
	ClientEpoch   int64
	ServerEpoch   int64
	AttestEpoch   int64
	ImportedAtUTC string
}

// Job is one resumable unit of work: a sample against one harness phase.
type Job struct {
	ID            int64
	SampleID      int64
	Phase         string
	State         string
	Attempts      int
	CreatedAtUTC  string
	StartedAtUTC  sql.NullString
	FinishedAtUTC sql.NullString
}

// Run is a concrete execution attempt and its verdict.
type Run struct {
	ID            int64
	JobID         int64
	Attempt       int
	VerdictCode   sql.NullInt64
	VerdictLabel  sql.NullString
	ExitCode      sql.NullInt64
	DurationNS    sql.NullInt64
	StartedAtUTC  string
	FinishedAtUTC sql.NullString
}

// SetMeta upserts a run_meta key/value pair.
func SetMeta(ctx context.Context, db *sql.DB, key, value string) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO run_meta(key,value,updated_at_utc) VALUES(?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value,
		 updated_at_utc=excluded.updated_at_utc`,
		key, value, NowUTC())
	return err
}

// GetMeta reads a run_meta value.
func GetMeta(ctx context.Context, db *sql.DB, key string) (string, error) {
	var v string
	err := db.QueryRowContext(ctx,
		`SELECT value FROM run_meta WHERE key=?`, key).Scan(&v)
	return v, err
}

// InsertAnchor records one located anchor with its raw byte offset.
func InsertAnchor(ctx context.Context, db *sql.DB, index int, magic, name string,
	offset, length int64) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO anchors(anchor_index,magic,name,raw_offset,length,located_at_utc)
		 VALUES(?,?,?,?,?,?)`,
		index, magic, name, offset, length, NowUTC())
	return err
}

// AnchorOffsets returns the three raw offsets in anchor order.
func AnchorOffsets(ctx context.Context, db *sql.DB) ([3]int64, error) {
	var out [3]int64
	rows, err := db.QueryContext(ctx,
		`SELECT anchor_index, raw_offset FROM anchors ORDER BY anchor_index`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var idx int
		var off int64
		if err := rows.Scan(&idx, &off); err != nil {
			return out, err
		}
		out[idx-1] = off
	}
	return out, rows.Err()
}

// InsertSample registers one sample and its per-sample anchor offsets.
func InsertSample(ctx context.Context, db *sql.DB, s Sample) (int64, error) {
	res, err := db.ExecContext(ctx,
		`INSERT INTO samples(name,kind,raw_path,sha256,size_bytes,
		   anchor1_offset,anchor2_offset,anchor3_offset,
		   client_epoch,server_epoch,attest_epoch,imported_at_utc)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		s.Name, s.Kind, s.RawPath, s.SHA256, s.Size,
		s.AnchorOffsets[0], s.AnchorOffsets[1], s.AnchorOffsets[2],
		s.ClientEpoch, s.ServerEpoch, s.AttestEpoch, NowUTC())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SampleByName looks up a sample by its unique name.
func SampleByName(ctx context.Context, db *sql.DB, name string) (*Sample, error) {
	row := db.QueryRowContext(ctx,
		`SELECT id,name,kind,raw_path,sha256,size_bytes,
		        anchor1_offset,anchor2_offset,anchor3_offset,
		        client_epoch,server_epoch,attest_epoch,imported_at_utc
		 FROM samples WHERE name=?`, name)
	s := &Sample{}
	err := row.Scan(&s.ID, &s.Name, &s.Kind, &s.RawPath, &s.SHA256, &s.Size,
		&s.AnchorOffsets[0], &s.AnchorOffsets[1], &s.AnchorOffsets[2],
		&s.ClientEpoch, &s.ServerEpoch, &s.AttestEpoch, &s.ImportedAtUTC)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ListSamples returns all registered samples ordered by name.
func ListSamples(ctx context.Context, db *sql.DB) ([]Sample, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id,name,kind,raw_path,sha256,size_bytes,
		        anchor1_offset,anchor2_offset,anchor3_offset,
		        client_epoch,server_epoch,attest_epoch,imported_at_utc
		 FROM samples ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sample
	for rows.Next() {
		var s Sample
		if err := rows.Scan(&s.ID, &s.Name, &s.Kind, &s.RawPath, &s.SHA256,
			&s.Size, &s.AnchorOffsets[0], &s.AnchorOffsets[1], &s.AnchorOffsets[2],
			&s.ClientEpoch, &s.ServerEpoch, &s.AttestEpoch,
			&s.ImportedAtUTC); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
