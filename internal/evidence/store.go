package evidence

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Store persists evidence records in SQLite so key evidence survives the
// run and remains reviewable afterwards.
type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS evidence (
		id TEXT PRIMARY KEY,
		format INTEGER NOT NULL,
		object TEXT NOT NULL,
		decision TEXT NOT NULL,
		payload TEXT NOT NULL,
		created_at TEXT NOT NULL
	)`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Save stores the record in the given wire format.
func (s *Store) Save(r Record, format int) error {
	b, err := Marshal(r, format)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO evidence (id, format, object, decision, payload, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		r.ID, format, r.Object, r.Decision, string(b),
		r.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z"),
	)
	return err
}

// List returns all records, transparently decoding both formats.
func (s *Store) List() ([]Record, error) {
	rows, err := s.db.Query(`SELECT payload FROM evidence ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		r, err := Unmarshal([]byte(payload))
		if err != nil {
			return nil, fmt.Errorf("evidence: decode row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
