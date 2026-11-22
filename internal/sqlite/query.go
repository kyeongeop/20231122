package sqlite

/*
#include <stdlib.h>

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

extern int sqlite3_prepare_v2(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
extern int sqlite3_step(sqlite3_stmt*);
extern int sqlite3_finalize(sqlite3_stmt*);
extern int sqlite3_bind_text(sqlite3_stmt*, int, const char*, int, void(*)(void*));
extern int sqlite3_bind_int64(sqlite3_stmt*, int, long long);
extern int sqlite3_bind_null(sqlite3_stmt*, int);
extern const unsigned char *sqlite3_column_text(sqlite3_stmt*, int);
extern long long sqlite3_column_int64(sqlite3_stmt*, int);
extern int sqlite3_column_type(sqlite3_stmt*, int);
extern int sqlite3_column_count(sqlite3_stmt*);

static void transient_dtor2(void *p) { (void)p; }
static int bind_text_tr2(sqlite3_stmt* s, int i, const char* t, int n) {
	return sqlite3_bind_text(s, i, t, n, transient_dtor2);
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

type Rows struct {
	db    *DB
	stmt  *C.sqlite3_stmt
	ncols int
	alloc []*C.char
}

func (d *DB) prepare(sql string, args []any) (*C.sqlite3_stmt, []*C.char, error) {
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	var stmt *C.sqlite3_stmt
	rc := C.sqlite3_prepare_v2(d.handle, csql, C.int(len(sql)+1), &stmt, nil)
	if rc != SQLITE_OK {
		return nil, nil, fmt.Errorf("prepare %q: %w", sql, d.err())
	}
	var alloc []*C.char
	for i, arg := range args {
		idx := C.int(i + 1)
		switch v := arg.(type) {
		case string:
			cv := C.CString(v)
			alloc = append(alloc, cv)
			if rc = C.bind_text_tr2(stmt, idx, cv, C.int(len(v))); rc != SQLITE_OK {
				return nil, alloc, fmt.Errorf("bind text: %w", d.err())
			}
		case int64:
			if rc = C.sqlite3_bind_int64(stmt, idx, C.longlong(v)); rc != SQLITE_OK {
				return nil, alloc, fmt.Errorf("bind int: %w", d.err())
			}
		case int:
			if rc = C.sqlite3_bind_int64(stmt, idx, C.longlong(int64(v))); rc != SQLITE_OK {
				return nil, alloc, fmt.Errorf("bind int: %w", d.err())
			}
		case nil:
			if rc = C.sqlite3_bind_null(stmt, idx); rc != SQLITE_OK {
				return nil, alloc, fmt.Errorf("bind null: %w", d.err())
			}
		default:
			return nil, alloc, fmt.Errorf("unsupported bind type %T", arg)
		}
	}
	return stmt, alloc, nil
}

func (d *DB) Query(sql string, args ...any) (*Rows, error) {
	stmt, alloc, err := d.prepare(sql, args)
	if err != nil {
		return nil, err
	}
	return &Rows{db: d, stmt: stmt, ncols: int(C.sqlite3_column_count(stmt)), alloc: alloc}, nil
}

func (r *Rows) Next() bool {
	return C.sqlite3_step(r.stmt) == SQLITE_ROW
}

func (r *Rows) ColumnText(idx int) string {
	if C.sqlite3_column_type(r.stmt, C.int(idx)) == SQLITE_NULL {
		return ""
	}
	ptr := C.sqlite3_column_text(r.stmt, C.int(idx))
	if ptr == nil {
		return ""
	}
	return C.GoString((*C.char)(unsafe.Pointer(ptr)))
}

func (r *Rows) ColumnInt64(idx int) int64 {
	return int64(C.sqlite3_column_int64(r.stmt, C.int(idx)))
}

func (r *Rows) ColumnIsNull(idx int) bool {
	return C.sqlite3_column_type(r.stmt, C.int(idx)) == SQLITE_NULL
}

func (r *Rows) Close() {
	C.sqlite3_finalize(r.stmt)
	for _, p := range r.alloc {
		C.free(unsafe.Pointer(p))
	}
}

func (d *DB) QueryString(sql string, args ...any) (string, error) {
	rows, err := d.Query(sql, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		return "", fmt.Errorf("no rows")
	}
	return rows.ColumnText(0), nil
}
