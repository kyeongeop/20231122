package store

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/example/syscallwhitelist/internal/model"
	_ "modernc.org/sqlite"
)

// Store 封装审计结果的 SQLite 持久化。
type Store struct {
	db *sql.DB
}

// Open 打开（或创建）审计数据库并初始化表结构。
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS trusted_sources(
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			pubkey TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS snapshots(
			version TEXT PRIMARY KEY,
			source_id TEXT NOT NULL,
			signature TEXT NOT NULL,
			issued_at TEXT NOT NULL,
			fingerprint TEXT NOT NULL,
			payload TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS findings(
			record_id TEXT PRIMARY KEY,
			verdict TEXT NOT NULL,
			reason TEXT NOT NULL,
			snapshot_version TEXT,
			matched_syscall TEXT,
			evidence TEXT NOT NULL,
			steps TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS raw_inputs(
			record_id TEXT PRIMARY KEY,
			raw TEXT NOT NULL,
			raw_sha256 TEXT NOT NULL,
			truncated INTEGER NOT NULL)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// UpsertSource 登记一个受信任来源。
func (s *Store) UpsertSource(src model.Source) error {
	_, err := s.db.Exec(
		`INSERT INTO trusted_sources(id,name,pubkey) VALUES(?,?,?)
		 ON CONFLICT(id) DO UPDATE SET name=excluded.name, pubkey=excluded.pubkey`,
		src.ID, src.Name, src.PubKey)
	return err
}

// GetSource 按 ID 查询受信任来源。
func (s *Store) GetSource(id string) (model.Source, bool, error) {
	row := s.db.QueryRow(`SELECT id,name,pubkey FROM trusted_sources WHERE id=?`, id)
	var src model.Source
	if err := row.Scan(&src.ID, &src.Name, &src.PubKey); err != nil {
		if err == sql.ErrNoRows {
			return model.Source{}, false, nil
		}
		return model.Source{}, false, err
	}
	return src, true, nil
}

// SaveSnapshot 保存一个不可变白名单版本快照。
func (s *Store) SaveSnapshot(snap model.Snapshot) error {
	payload, err := json.Marshal(snap.Syscalls)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO snapshots(version,source_id,signature,issued_at,fingerprint,payload)
		 VALUES(?,?,?,?,?,?)
		 ON CONFLICT(version) DO UPDATE SET
		   source_id=excluded.source_id, signature=excluded.signature,
		   issued_at=excluded.issued_at, fingerprint=excluded.fingerprint,
		   payload=excluded.payload`,
		snap.Version, snap.SourceID, snap.Signature, snap.IssuedAt,
		snap.Fingerprint, string(payload))
	return err
}

// GetSnapshot 读取指定版本快照。
func (s *Store) GetSnapshot(version string) (model.Snapshot, bool, error) {
	row := s.db.QueryRow(
		`SELECT version,source_id,signature,issued_at,fingerprint,payload
		 FROM snapshots WHERE version=?`, version)
	var snap model.Snapshot
	var payload string
	err := row.Scan(&snap.Version, &snap.SourceID, &snap.Signature,
		&snap.IssuedAt, &snap.Fingerprint, &payload)
	if err == sql.ErrNoRows {
		return model.Snapshot{}, false, nil
	}
	if err != nil {
		return model.Snapshot{}, false, err
	}
	if err := json.Unmarshal([]byte(payload), &snap.Syscalls); err != nil {
		return model.Snapshot{}, false, err
	}
	return snap, true, nil
}

// SnapshotVersions 返回已保存的全部快照版本号（按版本升序）。
func (s *Store) SnapshotVersions() ([]string, error) {
	rows, err := s.db.Query(`SELECT version FROM snapshots ORDER BY version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SaveRawInput 留存原始输入及其哈希，保证结论可回溯到原始字节。
func (s *Store) SaveRawInput(rec model.Record, rawSHA string) error {
	_, err := s.db.Exec(
		`INSERT INTO raw_inputs(record_id,raw,raw_sha256,truncated)
		 VALUES(?,?,?,?) ON CONFLICT(record_id) DO UPDATE SET
		   raw=excluded.raw, raw_sha256=excluded.raw_sha256,
		   truncated=excluded.truncated`,
		rec.ID, rec.Raw, rawSHA, boolToInt(rec.Truncated))
	return err
}

// SaveFinding 持久化一条结论及其证据链。
func (s *Store) SaveFinding(f model.Finding) error {
	evidence, err := json.Marshal(f.Evidence)
	if err != nil {
		return err
	}
	steps, err := json.Marshal(f.Steps)
	if err != nil {
		return err
	}
	matched := ""
	if f.Matched != nil {
		matched = fmt.Sprintf("%d:%s:%s", f.Matched.Number, f.Matched.Name, f.Matched.Risk)
	}
	_, err = s.db.Exec(
		`INSERT INTO findings(record_id,verdict,reason,snapshot_version,
		   matched_syscall,evidence,steps)
		 VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(record_id) DO UPDATE SET
		   verdict=excluded.verdict, reason=excluded.reason,
		   snapshot_version=excluded.snapshot_version,
		   matched_syscall=excluded.matched_syscall,
		   evidence=excluded.evidence, steps=excluded.steps`,
		f.RecordID, string(f.Verdict), f.Reason, f.SnapshotVersion,
		matched, string(evidence), string(steps))
	return err
}

// AllFindings 读取全部结论（按记录 ID 排序），供报告页使用。
func (s *Store) AllFindings() ([]model.Finding, error) {
	rows, err := s.db.Query(
		`SELECT record_id,verdict,reason,snapshot_version,matched_syscall,evidence,steps
		 FROM findings ORDER BY record_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Finding
	for rows.Next() {
		var f model.Finding
		var verdict, matched, evidence, steps string
		var snapshot sql.NullString
		if err := rows.Scan(&f.RecordID, &verdict, &f.Reason, &snapshot,
			&matched, &evidence, &steps); err != nil {
			return nil, err
		}
		f.Verdict = model.Verdict(verdict)
		f.SnapshotVersion = snapshot.String
		if matched != "" {
			f.Matched = parseMatched(matched)
		}
		if err := json.Unmarshal([]byte(evidence), &f.Evidence); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(steps), &f.Steps); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func parseMatched(s string) *model.Syscall {
	var no int
	var name, risk string
	if _, err := fmt.Sscanf(s, "%d:%[^:]:%s", &no, &name, &risk); err != nil {
		return nil
	}
	return &model.Syscall{Number: no, Name: name, Risk: risk}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
