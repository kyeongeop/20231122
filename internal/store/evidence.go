package store

import (
	"crypto/sha256"
	"encoding/hex"
)

// AddEvidence stores an exact byte blob plus its sha256. Raw captures,
// parser results and before/after diffs all land here untouched.
func (s *Store) AddEvidence(runID, kind string, content []byte) (string, error) {
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	_, err := s.db.Exec(`INSERT INTO evidence(
		run_id,kind,content_sha256,content,created_unix_nano)
		VALUES(?,?,?,?,?)`, runID, kind, digest, content, nowNs())
	return digest, err
}

// EvidenceRow is one stored blob with its hash.
type EvidenceRow struct {
	ID      int64
	RunID   string
	Kind    string
	SHA256  string
	Content []byte
}

// EvidenceByKind returns all blobs of a kind in insertion order.
func (s *Store) EvidenceByKind(runID, kind string) ([]EvidenceRow, error) {
	rows, err := s.db.Query(`SELECT id,run_id,kind,content_sha256,content
		FROM evidence WHERE run_id=? AND kind=? ORDER BY id ASC`, runID, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvidenceRow
	for rows.Next() {
		var e EvidenceRow
		if err := rows.Scan(&e.ID, &e.RunID, &e.Kind, &e.SHA256, &e.Content); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddDegradation records one resource-pressure transition.
func (s *Store) AddDegradation(runID string, level int, reason, detail string) error {
	_, err := s.db.Exec(`INSERT INTO degradation_events(
		run_id,level,reason,detail,created_unix_nano)
		VALUES(?,?,?,?,?)`, runID, level, reason, detail, nowNs())
	return err
}

// DegradationRow mirrors degradation_events.
type DegradationRow struct {
	ID      int64
	Level   int
	Reason  string
	Detail  string
	Created int64
}

// ListDegradation returns events in occurrence order.
func (s *Store) ListDegradation(runID string) ([]DegradationRow, error) {
	rows, err := s.db.Query(`SELECT id,level,reason,detail,created_unix_nano
		FROM degradation_events WHERE run_id=? ORDER BY id ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DegradationRow
	for rows.Next() {
		var d DegradationRow
		if err := rows.Scan(&d.ID, &d.Level, &d.Reason, &d.Detail, &d.Created); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SaveReport persists the final deterministic report and its hash.
func (s *Store) SaveReport(runID, reportJSON string) (string, error) {
	sum := sha256.Sum256([]byte(reportJSON))
	digest := hex.EncodeToString(sum[:])
	_, err := s.db.Exec(`INSERT INTO reports(run_id,report_json,report_sha256,created_unix_nano)
		VALUES(?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET
		report_json=excluded.report_json,
		report_sha256=excluded.report_sha256,
		created_unix_nano=excluded.created_unix_nano`,
		runID, reportJSON, digest, nowNs())
	return digest, err
}

// GetReport loads a persisted report.
func (s *Store) GetReport(runID string) (jsonText, sha string, err error) {
	err = s.db.QueryRow(`SELECT report_json,report_sha256 FROM reports WHERE run_id=?`,
		runID).Scan(&jsonText, &sha)
	return
}
