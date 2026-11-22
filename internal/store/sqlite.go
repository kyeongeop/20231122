package store

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef void (*destructor_fn)(void*);

static void* sqlite_lib;
static const char* sqlite_load_error;

static void sqlite_load(void) {
	if (sqlite_lib != NULL || sqlite_load_error != NULL) {
		return;
	}
	sqlite_lib = dlopen("libsqlite3.so.0", RTLD_NOW | RTLD_LOCAL);
	if (sqlite_lib == NULL) {
		sqlite_load_error = dlerror();
	}
}

static void* sqlite_sym(const char* name) {
	sqlite_load();
	if (sqlite_lib == NULL) {
		return NULL;
	}
	return dlsym(sqlite_lib, name);
}

static int sqlite3_open_v2(const char* path, sqlite3** db, int flags, const char* vfs);
static int sqlite3_close_v2(sqlite3* db);
static int sqlite3_busy_timeout(sqlite3* db, int ms);
static const char* sqlite3_errmsg(sqlite3* db);
static int sqlite3_exec(sqlite3* db, const char* sql, void* cb, void* arg, char** msg);
static int sqlite3_prepare_v2(sqlite3* db, const char* sql, int n, sqlite3_stmt** stmt, const char** tail);
static int sqlite3_step(sqlite3_stmt* stmt);
static int sqlite3_reset(sqlite3_stmt* stmt);
static int sqlite3_clear_bindings(sqlite3_stmt* stmt);
static int sqlite3_finalize(sqlite3_stmt* stmt);
static int sqlite3_bind_null(sqlite3_stmt* stmt, int index);
static int sqlite3_bind_int64(sqlite3_stmt* stmt, int index, long long value);
static int sqlite3_bind_text(sqlite3_stmt* stmt, int index, const char* value, int n, destructor_fn destructor);
static int sqlite3_bind_blob(sqlite3_stmt* stmt, int index, const void* value, int n, destructor_fn destructor);
static long long sqlite3_column_int64(sqlite3_stmt* stmt, int col);
static int sqlite3_column_type(sqlite3_stmt* stmt, int col);
static const unsigned char* sqlite3_column_text(sqlite3_stmt* stmt, int col);
static const void* sqlite3_column_blob(sqlite3_stmt* stmt, int col);
static int sqlite3_column_bytes(sqlite3_stmt* stmt, int col);
static int sqlite3_column_count(sqlite3_stmt* stmt);
static long long sqlite3_last_insert_rowid(sqlite3* db);
static int sqlite3_changes(sqlite3* db);

typedef int (*open_v2_fn)(const char*, sqlite3**, int, const char*);
typedef int (*close_v2_fn)(sqlite3*);
typedef int (*busy_timeout_fn)(sqlite3*, int);
typedef const char* (*errmsg_fn)(sqlite3*);
typedef int (*exec_fn)(sqlite3*, const char*, void*, void*, char**);
typedef int (*prepare_v2_fn)(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
typedef int (*step_fn)(sqlite3_stmt*);
typedef int (*reset_fn)(sqlite3_stmt*);
typedef int (*clear_bindings_fn)(sqlite3_stmt*);
typedef int (*finalize_fn)(sqlite3_stmt*);
typedef int (*bind_null_fn)(sqlite3_stmt*, int);
typedef int (*bind_int64_fn)(sqlite3_stmt*, int, long long);
typedef int (*bind_text_fn)(sqlite3_stmt*, int, const char*, int, destructor_fn);
typedef int (*bind_blob_fn)(sqlite3_stmt*, int, const void*, int, destructor_fn);
typedef long long (*column_int64_fn)(sqlite3_stmt*, int);
typedef int (*column_type_fn)(sqlite3_stmt*, int);
typedef const unsigned char* (*column_text_fn)(sqlite3_stmt*, int);
typedef const void* (*column_blob_fn)(sqlite3_stmt*, int);
typedef int (*column_bytes_fn)(sqlite3_stmt*, int);
typedef int (*column_count_fn)(sqlite3_stmt*);
typedef long long (*last_rowid_fn)(sqlite3*);
typedef int (*changes_fn)(sqlite3*);

static open_v2_fn p_open_v2;
static close_v2_fn p_close_v2;
static busy_timeout_fn p_busy_timeout;
static errmsg_fn p_errmsg;
static exec_fn p_exec;
static prepare_v2_fn p_prepare_v2;
static step_fn p_step;
static reset_fn p_reset;
static clear_bindings_fn p_clear_bindings;
static finalize_fn p_finalize;
static bind_null_fn p_bind_null;
static bind_int64_fn p_bind_int64;
static bind_text_fn p_bind_text;
static bind_blob_fn p_bind_blob;
static column_int64_fn p_column_int64;
static column_type_fn p_column_type;
static column_text_fn p_column_text;
static column_blob_fn p_column_blob;
static column_bytes_fn p_column_bytes;
static column_count_fn p_column_count;
static last_rowid_fn p_last_rowid;
static changes_fn p_changes;

static void sqlite_load_all(void) {
	sqlite_load();
	if (sqlite_lib == NULL) {
		return;
	}
	#define LOAD(var, name) *(void**)(&(var)) = dlsym(sqlite_lib, name)
	LOAD(p_open_v2, "sqlite3_open_v2");
	LOAD(p_close_v2, "sqlite3_close_v2");
	LOAD(p_busy_timeout, "sqlite3_busy_timeout");
	LOAD(p_errmsg, "sqlite3_errmsg");
	LOAD(p_exec, "sqlite3_exec");
	LOAD(p_prepare_v2, "sqlite3_prepare_v2");
	LOAD(p_step, "sqlite3_step");
	LOAD(p_reset, "sqlite3_reset");
	LOAD(p_clear_bindings, "sqlite3_clear_bindings");
	LOAD(p_finalize, "sqlite3_finalize");
	LOAD(p_bind_null, "sqlite3_bind_null");
	LOAD(p_bind_int64, "sqlite3_bind_int64");
	LOAD(p_bind_text, "sqlite3_bind_text");
	LOAD(p_bind_blob, "sqlite3_bind_blob");
	LOAD(p_column_int64, "sqlite3_column_int64");
	LOAD(p_column_type, "sqlite3_column_type");
	LOAD(p_column_text, "sqlite3_column_text");
	LOAD(p_column_blob, "sqlite3_column_blob");
	LOAD(p_column_bytes, "sqlite3_column_bytes");
	LOAD(p_column_count, "sqlite3_column_count");
	LOAD(p_last_rowid, "sqlite3_last_insert_rowid");
	LOAD(p_changes, "sqlite3_changes");
	#undef LOAD
}

static int sqlite3_open_v2(const char* path, sqlite3** db, int flags, const char* vfs) {
	sqlite_load_all();
	if (p_open_v2 == NULL) return 1;
	return p_open_v2(path, db, flags, vfs);
}
static int sqlite3_close_v2(sqlite3* db) {
	if (p_close_v2 == NULL) return 0;
	return p_close_v2(db);
}
static int sqlite3_busy_timeout(sqlite3* db, int ms) {
	if (p_busy_timeout == NULL) return 1;
	return p_busy_timeout(db, ms);
}
static const char* sqlite3_errmsg(sqlite3* db) {
	if (sqlite_load_error != NULL) return sqlite_load_error;
	if (db == NULL) return "sqlite database is null";
	if (p_errmsg == NULL) return "sqlite3_errmsg unavailable";
	return p_errmsg(db);
}
static int sqlite3_exec(sqlite3* db, const char* sql, void* cb, void* arg, char** msg) {
	if (p_exec == NULL) return 1;
	return p_exec(db, sql, cb, arg, msg);
}
static int sqlite3_prepare_v2(sqlite3* db, const char* sql, int n, sqlite3_stmt** stmt, const char** tail) {
	if (p_prepare_v2 == NULL) return 1;
	return p_prepare_v2(db, sql, n, stmt, tail);
}
static int sqlite3_step(sqlite3_stmt* stmt) {
	if (p_step == NULL) return 1;
	return p_step(stmt);
}
static int sqlite3_reset(sqlite3_stmt* stmt) {
	if (p_reset == NULL) return 1;
	return p_reset(stmt);
}
static int sqlite3_clear_bindings(sqlite3_stmt* stmt) {
	if (p_clear_bindings == NULL) return 1;
	return p_clear_bindings(stmt);
}
static int sqlite3_finalize(sqlite3_stmt* stmt) {
	if (p_finalize == NULL) return 1;
	return p_finalize(stmt);
}
static int sqlite3_bind_null(sqlite3_stmt* stmt, int index) {
	if (p_bind_null == NULL) return 1;
	return p_bind_null(stmt, index);
}
static int sqlite3_bind_int64(sqlite3_stmt* stmt, int index, long long value) {
	if (p_bind_int64 == NULL) return 1;
	return p_bind_int64(stmt, index, value);
}
static int sqlite3_bind_text(sqlite3_stmt* stmt, int index, const char* value, int n, destructor_fn destructor) {
	if (p_bind_text == NULL) return 1;
	return p_bind_text(stmt, index, value, n, destructor);
}
static int sqlite3_bind_blob(sqlite3_stmt* stmt, int index, const void* value, int n, destructor_fn destructor) {
	if (p_bind_blob == NULL) return 1;
	return p_bind_blob(stmt, index, value, n, destructor);
}
static long long sqlite3_column_int64(sqlite3_stmt* stmt, int col) {
	if (p_column_int64 == NULL) return 0;
	return p_column_int64(stmt, col);
}
static int sqlite3_column_type(sqlite3_stmt* stmt, int col) {
	if (p_column_type == NULL) return 5;
	return p_column_type(stmt, col);
}
static const unsigned char* sqlite3_column_text(sqlite3_stmt* stmt, int col) {
	if (p_column_text == NULL) return NULL;
	return p_column_text(stmt, col);
}
static const void* sqlite3_column_blob(sqlite3_stmt* stmt, int col) {
	if (p_column_blob == NULL) return NULL;
	return p_column_blob(stmt, col);
}
static int sqlite3_column_bytes(sqlite3_stmt* stmt, int col) {
	if (p_column_bytes == NULL) return 0;
	return p_column_bytes(stmt, col);
}
static int sqlite3_column_count(sqlite3_stmt* stmt) {
	if (p_column_count == NULL) return 0;
	return p_column_count(stmt);
}
static long long sqlite3_last_insert_rowid(sqlite3* db) {
	if (p_last_rowid == NULL) return 0;
	return p_last_rowid(db);
}
static int sqlite3_changes(sqlite3* db) {
	if (p_changes == NULL) return 0;
	return p_changes(db);
}

static int dl_bind_text(sqlite3_stmt* s, int i, const char* p, int n) {
	return sqlite3_bind_text(s, i, p, n, (destructor_fn)-1);
}
static int dl_bind_blob(sqlite3_stmt* s, int i, const void* p, int n) {
	return sqlite3_bind_blob(s, i, p, n, (destructor_fn)-1);
}
static int dl_bind_empty_blob(sqlite3_stmt* s, int i) {
	static unsigned char empty = 0;
	return sqlite3_bind_blob(s, i, &empty, 0, (destructor_fn)-1);
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

const (
	sqliteOK         = 0
	sqliteRow        = 100
	sqliteDone       = 101
	sqliteReadOnly   = 0x00000001
	sqliteReadWrite  = 0x00000002
	sqliteCreate     = 0x00000004
	sqliteFullMutex  = 0x00010000
	sqliteConstraint = 19
	sqliteNull       = 5
)

type DB struct {
	ptr  *C.sqlite3
	path string
}

type Stmt struct {
	db  *DB
	ptr *C.sqlite3_stmt
}

type Rows struct {
	stmt   *C.sqlite3_stmt
	db     *DB
	step   C.int
	done   bool
	closed bool
	err    error
}

func OpenDB(path string, readOnly bool) (*DB, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	flags := C.int(sqliteReadWrite | sqliteCreate | sqliteFullMutex)
	if readOnly {
		flags = C.int(sqliteReadOnly | sqliteFullMutex)
	}
	var ptr *C.sqlite3
	if rc := C.sqlite3_open_v2(cpath, &ptr, flags, nil); rc != sqliteOK {
		msg := "unable to open sqlite database"
		if ptr != nil {
			msg = C.GoString(C.sqlite3_errmsg(ptr))
			C.sqlite3_close_v2(ptr)
		}
		return nil, fmt.Errorf("open %s: %s (rc=%d)", path, msg, int(rc))
	}
	db := &DB{ptr: ptr, path: path}
	C.sqlite3_busy_timeout(ptr, 5000)
	if !readOnly {
		for _, pragma := range []string{
			"PRAGMA foreign_keys=ON",
			"PRAGMA journal_mode=DELETE",
			"PRAGMA synchronous=FULL",
		} {
			if err := db.Exec(pragma); err != nil {
				db.Close()
				return nil, err
			}
		}
	}
	return db, nil
}

func (db *DB) Close() error {
	if db == nil || db.ptr == nil {
		return nil
	}
	rc := C.sqlite3_close_v2(db.ptr)
	db.ptr = nil
	if rc != sqliteOK {
		return fmt.Errorf("close sqlite: rc=%d", int(rc))
	}
	return nil
}

func (db *DB) Path() string {
	return db.path
}

func (db *DB) Exec(query string, args ...any) error {
	stmt, err := db.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	if _, err := stmt.Exec(args...); err != nil {
		return err
	}
	return nil
}

func (db *DB) Query(query string, args ...any) (*Rows, error) {
	stmt, err := db.Prepare(query)
	if err != nil {
		return nil, err
	}
	if err := stmt.Bind(args...); err != nil {
		stmt.Close()
		return nil, err
	}
	return &Rows{stmt: stmt.ptr, db: db}, nil
}

func (db *DB) Prepare(query string) (*Stmt, error) {
	if db.ptr == nil {
		return nil, fmt.Errorf("sqlite database is closed")
	}
	cquery := C.CString(query)
	defer C.free(unsafe.Pointer(cquery))
	var ptr *C.sqlite3_stmt
	rc := C.sqlite3_prepare_v2(db.ptr, cquery, -1, &ptr, nil)
	if rc != sqliteOK {
		return nil, db.errorf("prepare", rc)
	}
	return &Stmt{db: db, ptr: ptr}, nil
}

func (stmt *Stmt) Bind(args ...any) error {
	if stmt.ptr == nil {
		return fmt.Errorf("sqlite statement is closed")
	}
	C.sqlite3_reset(stmt.ptr)
	C.sqlite3_clear_bindings(stmt.ptr)
	for i, arg := range args {
		index := C.int(i + 1)
		var rc C.int
		switch v := arg.(type) {
		case nil:
			rc = C.sqlite3_bind_null(stmt.ptr, index)
		case string:
			cs := C.CString(v)
			rc = C.dl_bind_text(stmt.ptr, index, cs, C.int(len(v)))
			C.free(unsafe.Pointer(cs))
		case []byte:
			rc = bindBlob(stmt.ptr, index, v)
		case json.RawMessage:
			rc = bindBlob(stmt.ptr, index, []byte(v))
		case int:
			rc = C.sqlite3_bind_int64(stmt.ptr, index, C.longlong(v))
		case int64:
			rc = C.sqlite3_bind_int64(stmt.ptr, index, C.longlong(v))
		case bool:
			value := 0
			if v {
				value = 1
			}
			rc = C.sqlite3_bind_int64(stmt.ptr, index, C.longlong(value))
		default:
			return fmt.Errorf("unsupported sqlite bind type %T", arg)
		}
		if rc != sqliteOK {
			return stmt.db.errorf("bind", rc)
		}
	}
	return nil
}

func bindBlob(stmt *C.sqlite3_stmt, index C.int, data []byte) C.int {
	if len(data) == 0 {
		return C.dl_bind_empty_blob(stmt, index)
	}
	return C.dl_bind_blob(stmt, index, unsafe.Pointer(&data[0]), C.int(len(data)))
}

func (stmt *Stmt) Exec(args ...any) (bool, error) {
	if err := stmt.Bind(args...); err != nil {
		return false, err
	}
	rc := C.sqlite3_step(stmt.ptr)
	switch rc {
	case sqliteRow:
		return true, nil
	case sqliteDone:
		return false, nil
	default:
		return false, stmt.db.errorf("step", rc)
	}
}

func (stmt *Stmt) Close() error {
	if stmt == nil || stmt.ptr == nil {
		return nil
	}
	rc := C.sqlite3_finalize(stmt.ptr)
	stmt.ptr = nil
	if rc != sqliteOK {
		return fmt.Errorf("finalize sqlite statement: rc=%d", int(rc))
	}
	return nil
}

func (db *DB) LastInsertID() int64 {
	return int64(C.sqlite3_last_insert_rowid(db.ptr))
}

func (db *DB) Changes() int {
	return int(C.sqlite3_changes(db.ptr))
}

func (rows *Rows) Next() bool {
	if rows == nil || rows.done || rows.closed {
		return false
	}
	rows.step = C.sqlite3_step(rows.stmt)
	switch rows.step {
	case sqliteRow:
		return true
	case sqliteDone:
		rows.done = true
		return false
	default:
		rows.err = rows.db.errorf("rows step", rows.step)
		rows.done = true
		return false
	}
}

func (rows *Rows) Err() error {
	return rows.err
}

func (rows *Rows) Scan(dest ...any) error {
	if rows == nil || rows.step != sqliteRow {
		return fmt.Errorf("scan called without a current sqlite row")
	}
	if len(dest) != int(C.sqlite3_column_count(rows.stmt)) {
		return fmt.Errorf("scan destination count %d does not match column count %d",
			len(dest), int(C.sqlite3_column_count(rows.stmt)))
	}
	for i, target := range dest {
		if err := rows.scanColumn(i, target); err != nil {
			return err
		}
	}
	return nil
}

func (rows *Rows) scanColumn(index int, target any) error {
	col := C.int(index)
	columnType := C.sqlite3_column_type(rows.stmt, col)
	switch out := target.(type) {
	case *string:
		if columnType == sqliteNull {
			*out = ""
			return nil
		}
		*out = C.GoString((*C.char)(unsafe.Pointer(C.sqlite3_column_text(rows.stmt, col))))
	case *[]byte:
		if columnType == sqliteNull {
			*out = nil
			return nil
		}
		size := C.sqlite3_column_bytes(rows.stmt, col)
		*out = C.GoBytes(C.sqlite3_column_blob(rows.stmt, col), size)
	case *json.RawMessage:
		if columnType == sqliteNull {
			*out = nil
			return nil
		}
		size := C.sqlite3_column_bytes(rows.stmt, col)
		*out = append(json.RawMessage(nil), C.GoBytes(C.sqlite3_column_blob(rows.stmt, col), size)...)
	case *int:
		*out = int(C.sqlite3_column_int64(rows.stmt, col))
	case *int64:
		*out = int64(C.sqlite3_column_int64(rows.stmt, col))
	case *any:
		switch columnType {
		case sqliteNull:
			*out = nil
		default:
			*out = int64(C.sqlite3_column_int64(rows.stmt, col))
		}
	default:
		return fmt.Errorf("unsupported sqlite scan type %T at column %d", target, index)
	}
	return nil
}

func (rows *Rows) Close() error {
	if rows == nil || rows.closed {
		return nil
	}
	rows.closed = true
	if rows.stmt == nil {
		return nil
	}
	rc := C.sqlite3_finalize(rows.stmt)
	rows.stmt = nil
	if rc != sqliteOK {
		return fmt.Errorf("finalize sqlite rows: rc=%d", int(rc))
	}
	return rows.err
}

func (db *DB) errorf(op string, rc C.int) error {
	if db == nil || db.ptr == nil {
		return fmt.Errorf("%s: sqlite database is closed (rc=%d)", op, int(rc))
	}
	return fmt.Errorf("%s: sqlite rc=%d: %s", op, int(rc), C.GoString(C.sqlite3_errmsg(db.ptr)))
}

func (db *DB) Begin() error {
	return db.Exec("BEGIN IMMEDIATE")
}

func (db *DB) Commit() error {
	return db.Exec("COMMIT")
}

func (db *DB) Rollback() {
	_ = db.Exec("ROLLBACK")
}
