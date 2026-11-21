package lockout

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store 是证据与账户状态的 SQLite 持久层。
// attempts 表是只追加的审计日志, 每行带 UTC 纳秒时间戳与原始偏移。
type Store struct {
	db *sql.DB
}

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	return s, s.migrate()
}

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS accounts(
			username TEXT PRIMARY KEY,
			fail_count INTEGER NOT NULL DEFAULT 0,
			locked_until INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS attempts(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT NOT NULL,
			request_id TEXT,
			raw_offset INTEGER,
			username TEXT,
			phase TEXT NOT NULL,
			decision TEXT,
			detail TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS evidence(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT NOT NULL,
			kind TEXT NOT NULL,
			raw_offset INTEGER,
			sha256 TEXT,
			note TEXT
		)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// LogAttempt 追加一条审计日志, 返回行号作为证据锚点。
func (s *Store) LogAttempt(requestID string, rawOffset int64, username, phase, decision, detail string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO attempts(ts,request_id,raw_offset,username,phase,decision,detail) VALUES(?,?,?,?,?,?,?)`,
		nowUTC(), requestID, rawOffset, username, phase, decision, detail)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) LogEvidence(kind string, rawOffset int64, sha256, note string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO evidence(ts,kind,raw_offset,sha256,note) VALUES(?,?,?,?,?)`,
		nowUTC(), kind, rawOffset, sha256, note)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) GetAccount(username string) (failCount int, lockedUntil int64, err error) {
	err = s.db.QueryRow(`SELECT fail_count, locked_until FROM accounts WHERE username=?`, username).
		Scan(&failCount, &lockedUntil)
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	return
}

// SetFail 写入失败计数。与 GetAccount 分离且不加事务,
// 故意构成非原子读-改-写, 用于重建并发丢失更新场景。
func (s *Store) SetFail(username string, failCount int) error {
	_, err := s.db.Exec(
		`INSERT INTO accounts(username,fail_count,locked_until) VALUES(?,?,0)
		 ON CONFLICT(username) DO UPDATE SET fail_count=excluded.fail_count`,
		username, failCount)
	return err
}

func (s *Store) Lock(username string, until int64) error {
	_, err := s.db.Exec(`UPDATE accounts SET locked_until=? WHERE username=?`, until, username)
	return err
}

// DumpAttempts 供报告生成读取全部审计行。
func (s *Store) DumpAttempts() ([]AttemptRow, error) {
	rows, err := s.db.Query(`SELECT id,ts,request_id,raw_offset,username,phase,decision,detail FROM attempts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AttemptRow
	for rows.Next() {
		var a AttemptRow
		if err := rows.Scan(&a.ID, &a.TS, &a.RequestID, &a.RawOffset, &a.Username, &a.Phase, &a.Decision, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type AttemptRow struct {
	ID        int64
	TS        string
	RequestID string
	RawOffset int64
	Username  string
	Phase     string
	Decision  string
	Detail    string
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) String() string {
	return fmt.Sprintf("Store(%p)", s.db)
}
