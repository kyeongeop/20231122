package store

import (
	"database/sql"
	"encoding/json"
	"fmt"

	_ "modernc.org/sqlite"

	"quotabypass/internal/evidence"
	"quotabypass/internal/model"
)

const schemaVersion = "quota-bypass.export/v1"

// OpenV2 创建/打开与参考证据对齐的 SQLite 库。
func OpenV2(path string) (*StoreV2, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	st := &StoreV2{db: db}
	if err := st.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return st, nil
}

type StoreV2 struct{ db *sql.DB }

func (s *StoreV2) Close() error { return s.db.Close() }

func (s *StoreV2) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
  ordinal INTEGER PRIMARY KEY,
  run_id TEXT NOT NULL UNIQUE,
  scenario TEXT NOT NULL,
  mode TEXT NOT NULL,
  created_at TEXT NOT NULL,
  attack_input TEXT NOT NULL,
  input_evidence TEXT NOT NULL,
  permission TEXT NOT NULL,
  summary TEXT NOT NULL,
  record_sha256 TEXT NOT NULL,
  input_sha256 TEXT NOT NULL,
  quota_count INTEGER NOT NULL,
  concurrent_requests INTEGER NOT NULL,
  decision TEXT NOT NULL,
  authorized INTEGER NOT NULL,
  allowed_count INTEGER NOT NULL,
  denied_count INTEGER NOT NULL,
  bypass_detected INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS attempts (
  record_ordinal INTEGER NOT NULL REFERENCES records(ordinal) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  request_id TEXT NOT NULL,
  decision TEXT NOT NULL,
  http_status INTEGER NOT NULL,
  reason TEXT NOT NULL,
  response TEXT NOT NULL,
  trigger_file TEXT NOT NULL,
  trigger_line INTEGER NOT NULL,
  trigger_function TEXT NOT NULL,
  at TEXT NOT NULL,
  PRIMARY KEY (record_ordinal, ordinal)
);
CREATE TABLE IF NOT EXISTS logs (
  record_ordinal INTEGER NOT NULL REFERENCES records(ordinal) ON DELETE CASCADE,
  seq INTEGER NOT NULL,
  at TEXT NOT NULL,
  level TEXT NOT NULL,
  event TEXT NOT NULL,
  attempt INTEGER NOT NULL,
  message TEXT NOT NULL,
  PRIMARY KEY (record_ordinal, seq)
);`)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO metadata(key, value) VALUES('schema', ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, schemaVersion)
	return err
}

func mustJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// Save 在单事务内写入记录、尝试与日志；写入前校验记录指纹。
func (s *StoreV2) Save(rec model.Record) error {
	if err := evidence.VerifyRecord(rec); err != nil {
		return fmt.Errorf("refuse unverified record %s: %w", rec.RunID, err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM logs WHERE record_ordinal=?`, rec.Ordinal); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM attempts WHERE record_ordinal=?`, rec.Ordinal); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM records WHERE ordinal=?`, rec.Ordinal); err != nil {
		return err
	}

	auth := 0
	if rec.Permission.Authorized {
		auth = 1
	}
	bypass := 0
	if rec.Summary.BypassDetected {
		bypass = 1
	}
	_, err = tx.Exec(`INSERT INTO records
	(ordinal, run_id, scenario, mode, created_at, attack_input, input_evidence,
	 permission, summary, record_sha256, input_sha256, quota_count,
	 concurrent_requests, decision, authorized, allowed_count, denied_count, bypass_detected)
	VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		rec.Ordinal, rec.RunID, rec.Scenario, rec.Mode, rec.CreatedAt,
		mustJSON(rec.AttackInput), mustJSON(rec.Input), mustJSON(rec.Permission),
		mustJSON(rec.Summary), rec.RecordSHA256, rec.Input.SHA256,
		rec.AttackInput.QuotaCount, rec.AttackInput.ConcurrentRequests,
		rec.Permission.Decision, auth, rec.Summary.Allowed, rec.Summary.Denied, bypass)
	if err != nil {
		return fmt.Errorf("save record: %w", err)
	}

	for _, a := range rec.Attempts {
		_, err = tx.Exec(`INSERT INTO attempts
		(record_ordinal, ordinal, request_id, decision, http_status, reason,
		 response, trigger_file, trigger_line, trigger_function, at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			rec.Ordinal, a.Ordinal, a.RequestID, a.Decision, a.HTTPStatus,
			a.Reason, a.Response, a.Trigger.File, a.Trigger.Line, a.Trigger.Function, a.At)
		if err != nil {
			return fmt.Errorf("save attempt: %w", err)
		}
	}
	for _, l := range rec.Logs {
		_, err = tx.Exec(`INSERT INTO logs
		(record_ordinal, seq, at, level, event, attempt, message)
		VALUES (?,?,?,?,?,?,?)`,
			rec.Ordinal, l.Seq, l.At, l.Level, l.Event, l.Attempt, l.Message)
		if err != nil {
			return fmt.Errorf("save log: %w", err)
		}
	}
	return tx.Commit()
}

// Load 按 ordinal 重载完整记录并重新校验指纹。
func (s *StoreV2) Load(ordinal int) (model.Record, error) {
	row := s.db.QueryRow(`SELECT ordinal, run_id, scenario, mode, created_at,
		attack_input, input_evidence, permission, summary, record_sha256
		FROM records WHERE ordinal=?`, ordinal)
	var rec model.Record
	var attack, inputEv, perm, summary, hash string
	scanErr := row.Scan(&rec.Ordinal, &rec.RunID, &rec.Scenario, &rec.Mode,
		&rec.CreatedAt, &attack, &inputEv, &perm, &summary, &hash)
	if scanErr == sql.ErrNoRows {
		return model.Record{}, fmt.Errorf("%w: ordinal %d", ErrNotFoundV2, ordinal)
	}
	if scanErr != nil {
		return model.Record{}, scanErr
	}
	if err := json.Unmarshal([]byte(attack), &rec.AttackInput); err != nil {
		return model.Record{}, err
	}
	if err := json.Unmarshal([]byte(inputEv), &rec.Input); err != nil {
		return model.Record{}, err
	}
	if err := json.Unmarshal([]byte(perm), &rec.Permission); err != nil {
		return model.Record{}, err
	}
	if err := json.Unmarshal([]byte(summary), &rec.Summary); err != nil {
		return model.Record{}, err
	}
	rec.RecordSHA256 = hash

	rows, err := s.db.Query(`SELECT ordinal, request_id, decision, http_status,
		reason, response, trigger_file, trigger_line, trigger_function, at
		FROM attempts WHERE record_ordinal=? ORDER BY ordinal`, ordinal)
	if err != nil {
		return model.Record{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var a model.Attempt
		if err := rows.Scan(&a.Ordinal, &a.RequestID, &a.Decision, &a.HTTPStatus,
			&a.Reason, &a.Response, &a.Trigger.File, &a.Trigger.Line,
			&a.Trigger.Function, &a.At); err != nil {
			return model.Record{}, err
		}
		rec.Attempts = append(rec.Attempts, a)
	}

	logRows, err := s.db.Query(`SELECT seq, at, level, event, attempt, message
		FROM logs WHERE record_ordinal=? ORDER BY seq`, ordinal)
	if err != nil {
		return model.Record{}, err
	}
	defer logRows.Close()
	for logRows.Next() {
		var l model.LogEntry
		if err := logRows.Scan(&l.Seq, &l.At, &l.Level, &l.Event, &l.Attempt, &l.Message); err != nil {
			return model.Record{}, err
		}
		rec.Logs = append(rec.Logs, l)
	}
	return normalizeAndVerify(rec)
}

// normalizeAndVerify 把 SQL 往返产生的 nil 切片还原为 []，再校验指纹。
func normalizeAndVerify(rec model.Record) (model.Record, error) {
	if rec.Attempts == nil {
		rec.Attempts = []model.Attempt{}
	}
	if rec.Logs == nil {
		rec.Logs = []model.LogEntry{}
	}
	if rec.Input.MissingFields == nil {
		rec.Input.MissingFields = []string{}
	}
	if err := evidence.VerifyRecord(rec); err != nil {
		return model.Record{}, err
	}
	return rec, nil
}

// Ordinals 返回全部记录序号（即导出顺序）。
func (s *StoreV2) Ordinals() ([]int, error) {
	rows, err := s.db.Query(`SELECT ordinal FROM records ORDER BY ordinal`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
