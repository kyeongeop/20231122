// Package store persists pipeline state in SQLite. The container ships
// only the SQLite runtime library (no headers), so the small subset of
// the stable C ABI we need is declared directly in the cgo preamble.
package store

/*
#cgo LDFLAGS: -l:libsqlite3.so.0
#include <stdlib.h>

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef long long sqlite3_int64;

extern int sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs);
extern int sqlite3_close_v2(sqlite3*);
extern const char *sqlite3_errmsg(sqlite3*);
extern int sqlite3_exec(sqlite3*, const char *sql, void *cb, void *arg, char **errmsg);
extern int sqlite3_prepare_v2(sqlite3*, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);
extern int sqlite3_step(sqlite3_stmt*);
extern int sqlite3_finalize(sqlite3_stmt*);
extern int sqlite3_reset(sqlite3_stmt*);
extern int sqlite3_bind_int64(sqlite3_stmt*, int, sqlite3_int64);
extern int sqlite3_bind_text(sqlite3_stmt*, int, const char*, int, void*);
extern int sqlite3_bind_blob(sqlite3_stmt*, int, const void*, int, void*);
extern sqlite3_int64 sqlite3_column_int64(sqlite3_stmt*, int);
extern const unsigned char *sqlite3_column_text(sqlite3_stmt*, int);
extern const void *sqlite3_column_blob(sqlite3_stmt*, int);
extern int sqlite3_column_bytes(sqlite3_stmt*, int);
extern sqlite3_int64 sqlite3_last_insert_rowid(sqlite3*);

#define TVE_OPEN_RW_CREATE 0x6
#define TVE_OPEN_FULLMUTEX 0x10000
#define TVE_ROW 100
#define TVE_DONE 101

static int tve_open(const char *path, sqlite3 **db) {
	return sqlite3_open_v2(path, db, TVE_OPEN_RW_CREATE | TVE_OPEN_FULLMUTEX, 0);
}
static int tve_bind_text(sqlite3_stmt *s, int i, const char *v, int n) {
	return sqlite3_bind_text(s, i, v, n, (void*)-1); // SQLITE_TRANSIENT
}
static int tve_bind_blob(sqlite3_stmt *s, int i, const void *v, int n) {
	return sqlite3_bind_blob(s, i, v, n, (void*)-1); // SQLITE_TRANSIENT
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// DB is a minimal SQLite handle.
type DB struct {
	h *C.sqlite3
}

// Open opens (and creates if needed) the SQLite database at path.
func Open(path string) (*DB, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var h *C.sqlite3
	if rc := C.tve_open(cpath, &h); rc != 0 {
		return nil, fmt.Errorf("sqlite open %s: rc=%d", path, rc)
	}
	return &DB{h: h}, nil
}

// Close closes the database handle.
func (d *DB) Close() error {
	if d.h == nil {
		return nil
	}
	rc := C.sqlite3_close_v2(d.h)
	d.h = nil
	if rc != 0 {
		return fmt.Errorf("sqlite close: rc=%d", rc)
	}
	return nil
}

// Exec runs one or more semicolon-separated statements without results.
func (d *DB) Exec(sql string) error {
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	if rc := C.sqlite3_exec(d.h, csql, nil, nil, nil); rc != 0 {
		return fmt.Errorf("exec: %s", d.errMsg())
	}
	return nil
}

func (d *DB) errMsg() string {
	return C.GoString(C.sqlite3_errmsg(d.h))
}

// Stmt is a prepared statement.
type Stmt struct {
	db *DB
	s  *C.sqlite3_stmt
}

// Prepare compiles sql into a statement.
func (d *DB) Prepare(sql string) (*Stmt, error) {
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	var s *C.sqlite3_stmt
	if rc := C.sqlite3_prepare_v2(d.h, csql, -1, &s, nil); rc != 0 {
		return nil, fmt.Errorf("prepare %q: %s", sql, d.errMsg())
	}
	return &Stmt{db: d, s: s}, nil
}

// Close finalizes the statement.
func (s *Stmt) Close() {
	if s.s != nil {
		C.sqlite3_finalize(s.s)
		s.s = nil
	}
}

// Reset rewinds the statement for reuse.
func (s *Stmt) Reset() { C.sqlite3_reset(s.s) }

// BindInt binds an int64 to the 1-based parameter index.
func (s *Stmt) BindInt(idx int, v int64) error {
	if rc := C.sqlite3_bind_int64(s.s, C.int(idx), C.sqlite3_int64(v)); rc != 0 {
		return fmt.Errorf("bind int: %s", s.db.errMsg())
	}
	return nil
}

// BindText binds a string to the 1-based parameter index.
func (s *Stmt) BindText(idx int, v string) error {
	cv := C.CString(v)
	defer C.free(unsafe.Pointer(cv))
	if rc := C.tve_bind_text(s.s, C.int(idx), cv, C.int(len(v))); rc != 0 {
		return fmt.Errorf("bind text: %s", s.db.errMsg())
	}
	return nil
}

// BindBlob binds bytes to the 1-based parameter index.
func (s *Stmt) BindBlob(idx int, v []byte) error {
	var p unsafe.Pointer
	if len(v) > 0 {
		p = unsafe.Pointer(&v[0])
	} else {
		// Bind a zero-length non-NULL blob (NULL pointer would store NULL).
		p = unsafe.Pointer(&emptyBlob[0])
	}
	if rc := C.tve_bind_blob(s.s, C.int(idx), p, C.int(len(v))); rc != 0 {
		return fmt.Errorf("bind blob: %s", s.db.errMsg())
	}
	return nil
}

var emptyBlob = [1]byte{0}

// Step advances the statement; hasRow is true when a row is available.
func (s *Stmt) Step() (hasRow bool, err error) {
	rc := C.sqlite3_step(s.s)
	switch rc {
	case C.TVE_ROW:
		return true, nil
	case C.TVE_DONE:
		return false, nil
	}
	return false, fmt.Errorf("step: %s", s.db.errMsg())
}

// ColumnInt returns the int64 value of the 0-based column.
func (s *Stmt) ColumnInt(col int) int64 {
	return int64(C.sqlite3_column_int64(s.s, C.int(col)))
}

// ColumnText returns the string value of the 0-based column.
func (s *Stmt) ColumnText(col int) string {
	p := C.sqlite3_column_text(s.s, C.int(col))
	if p == nil {
		return ""
	}
	return C.GoString((*C.char)(unsafe.Pointer(p)))
}

// ColumnBlob returns a copy of the blob value of the 0-based column.
func (s *Stmt) ColumnBlob(col int) []byte {
	n := C.sqlite3_column_bytes(s.s, C.int(col))
	if n == 0 {
		return nil
	}
	p := C.sqlite3_column_blob(s.s, C.int(col))
	if p == nil {
		return nil
	}
	return C.GoBytes(p, n)
}

// LastInsertRowID returns the rowid of the most recent insert.
func (d *DB) LastInsertRowID() int64 {
	return int64(C.sqlite3_last_insert_rowid(d.h))
}
