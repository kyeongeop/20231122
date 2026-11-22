// Package store is a minimal cgo binding to the system libsqlite3.
// The sqlite3 C ABI is stable, so the few prototypes we need are
// declared locally instead of requiring the dev headers.
package store

/*
#cgo LDFLAGS: -L${SRCDIR}/../../lib -lsqlite3
#include <stdlib.h>

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

int sqlite3_open(const char *filename, sqlite3 **ppDb);
int sqlite3_close(sqlite3*);
int sqlite3_exec(sqlite3*, const char *sql, void *cb, void *arg, char **errmsg);
int sqlite3_prepare_v2(sqlite3*, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);
int sqlite3_step(sqlite3_stmt*);
int sqlite3_finalize(sqlite3_stmt*);
int sqlite3_bind_text(sqlite3_stmt*, int, const char*, int, void(*)(void*));
int sqlite3_bind_int64(sqlite3_stmt*, int, long long);
const unsigned char *sqlite3_column_text(sqlite3_stmt*, int);
long long sqlite3_column_int64(sqlite3_stmt*, int);
const char *sqlite3_errmsg(sqlite3*);

// SQLITE_TRANSIENT is ((sqlite3_destructor_type)-1); wrap it in a
// static helper because cgo cannot express that cast directly.
static int bind_text_transient(sqlite3_stmt *s, int i, const char *v, int n) {
	return sqlite3_bind_text(s, i, v, n, (void(*)(void*))-1);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

const (
	sqliteOK   = 0
	sqliteRow  = 100
	sqliteDone = 101
)

// DB wraps a sqlite3 handle.
type DB struct {
	h *C.sqlite3
}

// Open opens (creating if needed) the SQLite database at path.
func Open(path string) (*DB, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var h *C.sqlite3
	if rc := C.sqlite3_open(cpath, &h); rc != sqliteOK {
		return nil, fmt.Errorf("sqlite3_open: rc=%d", rc)
	}
	db := &DB{h: h}
	if err := db.exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  note TEXT
);
CREATE TABLE IF NOT EXISTS checkpoints(
  run_id INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  processed INTEGER NOT NULL,
  findings INTEGER NOT NULL,
  digest TEXT NOT NULL,
  last_hash TEXT NOT NULL,
  degraded INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings(
  run_id INTEGER NOT NULL,
  item_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  len INTEGER NOT NULL,
  validator_ok INTEGER NOT NULL,
  oracle_danger INTEGER NOT NULL,
  bypass INTEGER NOT NULL,
  degraded INTEGER NOT NULL,
  segment TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS degradations(
  run_id INTEGER NOT NULL,
  item_id INTEGER NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS boundary_samples(
  run_id INTEGER NOT NULL,
  boundary INTEGER NOT NULL,
  side TEXT NOT NULL,
  item_id INTEGER NOT NULL,
  len INTEGER NOT NULL,
  validator_ok INTEGER NOT NULL,
  oracle_danger INTEGER NOT NULL,
  segment TEXT NOT NULL
);`); err != nil {
		C.sqlite3_close(h)
		return nil, err
	}
	return db, nil
}

// Close closes the database handle.
func (db *DB) Close() error {
	if rc := C.sqlite3_close(db.h); rc != sqliteOK {
		return fmt.Errorf("sqlite3_close: rc=%d", rc)
	}
	return nil
}

func (db *DB) errmsg() string {
	return C.GoString(C.sqlite3_errmsg(db.h))
}

func (db *DB) exec(sql string) error {
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	if rc := C.sqlite3_exec(db.h, csql, nil, nil, nil); rc != sqliteOK {
		return fmt.Errorf("exec %q: %s", sql, db.errmsg())
	}
	return nil
}

// BeginTx starts an immediate transaction.
func (db *DB) BeginTx() error { return db.exec("BEGIN IMMEDIATE") }

// Commit commits the current transaction.
func (db *DB) Commit() error { return db.exec("COMMIT") }

// Rollback aborts the current transaction.
func (db *DB) Rollback() error { return db.exec("ROLLBACK") }

// Stmt is a prepared statement.
type Stmt struct {
	db *DB
	s  *C.sqlite3_stmt
}

// Prepare compiles sql into a statement.
func (db *DB) Prepare(sql string) (*Stmt, error) {
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	var s *C.sqlite3_stmt
	if rc := C.sqlite3_prepare_v2(db.h, csql, -1, &s, nil); rc != sqliteOK {
		return nil, fmt.Errorf("prepare %q: %s", sql, db.errmsg())
	}
	return &Stmt{db: db, s: s}, nil
}

// Close finalizes the statement.
func (st *Stmt) Close() { C.sqlite3_finalize(st.s) }

// BindText binds a UTF-8 string to the 1-based parameter index.
func (st *Stmt) BindText(idx int, v string) {
	cv := C.CString(v)
	defer C.free(unsafe.Pointer(cv))
	// SQLITE_TRANSIENT makes sqlite copy the value during the call.
	C.bind_text_transient(st.s, C.int(idx), cv, C.int(len(v)))
}

// BindInt binds an int64 to the 1-based parameter index.
func (st *Stmt) BindInt(idx int, v int64) {
	C.sqlite3_bind_int64(st.s, C.int(idx), C.longlong(v))
}

// Exec runs the statement to completion (no result rows expected).
func (st *Stmt) Exec() error {
	rc := C.sqlite3_step(st.s)
	if rc != sqliteDone && rc != sqliteRow {
		return fmt.Errorf("step: %s", st.db.errmsg())
	}
	return nil
}

// QueryRow runs the statement and returns the first row as strings.
// Returns nil, nil when there is no row.
func (st *Stmt) QueryRow(ncols int) ([]string, error) {
	rc := C.sqlite3_step(st.s)
	if rc == sqliteDone {
		return nil, nil
	}
	if rc != sqliteRow {
		return nil, fmt.Errorf("step: %s", st.db.errmsg())
	}
	row := make([]string, ncols)
	for i := 0; i < ncols; i++ {
		p := C.sqlite3_column_text(st.s, C.int(i))
		if p != nil {
			row[i] = C.GoString((*C.char)(unsafe.Pointer(p)))
		}
	}
	return row, nil
}

// QueryInt returns the int64 in the first column of the first row.
func (st *Stmt) QueryInt() (int64, error) {
	rc := C.sqlite3_step(st.s)
	if rc == sqliteDone {
		return 0, errors.New("no row")
	}
	if rc != sqliteRow {
		return 0, fmt.Errorf("step: %s", st.db.errmsg())
	}
	return int64(C.sqlite3_column_int64(st.s, 0)), nil
}
