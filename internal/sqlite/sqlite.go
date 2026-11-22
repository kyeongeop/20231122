package sqlite

/*
#cgo LDFLAGS: -lsqlite3
#include <stdlib.h>

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

extern int sqlite3_open(const char*, sqlite3**);
extern int sqlite3_close_v2(sqlite3*);
extern int sqlite3_exec(sqlite3*, const char*, void*, void*, char**);
extern int sqlite3_prepare_v2(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
extern int sqlite3_step(sqlite3_stmt*);
extern int sqlite3_finalize(sqlite3_stmt*);
extern int sqlite3_reset(sqlite3_stmt*);
extern int sqlite3_bind_text(sqlite3_stmt*, int, const char*, int, void(*)(void*));
extern int sqlite3_bind_int64(sqlite3_stmt*, int, long long);
extern int sqlite3_bind_null(sqlite3_stmt*, int);
extern const unsigned char *sqlite3_column_text(sqlite3_stmt*, int);
extern long long sqlite3_column_int64(sqlite3_stmt*, int);
extern int sqlite3_column_type(sqlite3_stmt*, int);
extern int sqlite3_column_count(sqlite3_stmt*);
extern const char *sqlite3_errmsg(sqlite3*);
extern int sqlite3_changes(sqlite3*);
extern long long sqlite3_last_insert_rowid(sqlite3*);
extern void sqlite3_free(void*);

static void transient_dtor(void *p) { (void)p; }
static int bind_text_tr(sqlite3_stmt* s, int i, const char* t, int n) {
	return sqlite3_bind_text(s, i, t, n, transient_dtor);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

const (
	SQLITE_OK   = 0
	SQLITE_ROW  = 100
	SQLITE_DONE = 101
	SQLITE_NULL = 5
)

type DB struct {
	handle *C.sqlite3
}

func Open(path string) (*DB, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var handle *C.sqlite3
	if rc := C.sqlite3_open(cpath, &handle); rc != SQLITE_OK {
		msg := "open failed"
		if handle != nil {
			msg = C.GoString(C.sqlite3_errmsg(handle))
			C.sqlite3_close_v2(handle)
		}
		return nil, fmt.Errorf("sqlite open %s: %s", path, msg)
	}
	db := &DB{handle: handle}
	pragmas := "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;"
	if err := db.Exec(pragmas); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func (d *DB) Close() error {
	if d.handle == nil {
		return nil
	}
	rc := C.sqlite3_close_v2(d.handle)
	d.handle = nil
	if rc != SQLITE_OK {
		return fmt.Errorf("sqlite close rc=%d", rc)
	}
	return nil
}

func (d *DB) err() error {
	return errors.New(C.GoString(C.sqlite3_errmsg(d.handle)))
}

func (d *DB) Exec(sql string, args ...any) error {
	stmt, alloc, err := d.prepare(sql, args)
	if err != nil {
		return err
	}
	defer C.sqlite3_finalize(stmt)
	defer func() {
		for _, p := range alloc {
			C.free(unsafe.Pointer(p))
		}
	}()
	for {
		rc := C.sqlite3_step(stmt)
		if rc == SQLITE_ROW {
			continue
		}
		if rc != SQLITE_DONE {
			return fmt.Errorf("exec failed: %w", d.err())
		}
		break
	}
	return nil
}

func (d *DB) LastInsertRowID() int64 {
	return int64(C.sqlite3_last_insert_rowid(d.handle))
}

func (d *DB) Changes() int {
	return int(C.sqlite3_changes(d.handle))
}

func (d *DB) ExecScript(script string) error {
	csql := C.CString(script)
	defer C.free(unsafe.Pointer(csql))
	var errMsg *C.char
	if rc := C.sqlite3_exec(d.handle, csql, nil, nil, &errMsg); rc != SQLITE_OK {
		msg := "exec script failed"
		if errMsg != nil {
			msg = C.GoString(errMsg)
			C.sqlite3_free(unsafe.Pointer(errMsg))
		}
		return fmt.Errorf("%s: %w", msg, d.err())
	}
	return nil
}
