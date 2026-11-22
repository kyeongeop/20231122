package store

// schema is versioned explicitly. Every column has a stable position; future
// migrations must only append columns or add tables so reloaded artifacts keep
// their field order.
const schema = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS input_events (
    seq          INTEGER NOT NULL,
    device_id    TEXT NOT NULL,
    code         TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    kind         TEXT NOT NULL,
    observed_at  INTEGER NOT NULL,
    offset_ms    INTEGER NOT NULL,
    raw_sha256   TEXT NOT NULL,
    PRIMARY KEY (device_id, seq)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS issues (
    code               TEXT NOT NULL,
    user_id            TEXT NOT NULL,
    issue_sequence     INTEGER NOT NULL,
    device_id          TEXT NOT NULL,
    issued_at_ref      INTEGER NOT NULL,
    window_ms          INTEGER NOT NULL,
    consume_count      INTEGER NOT NULL,
    first_consume_seq  INTEGER NOT NULL,
    PRIMARY KEY (code, user_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS device_cursors (
    device_id       TEXT PRIMARY KEY,
    last_sequence   INTEGER NOT NULL,
    last_reference  INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS decisions (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    seq                  INTEGER NOT NULL,
    device_id            TEXT NOT NULL,
    code                 TEXT NOT NULL,
    user_id              TEXT NOT NULL,
    outcome              TEXT NOT NULL,
    severity             TEXT NOT NULL,
    reason               TEXT NOT NULL,
    matched_issue_seq    INTEGER NOT NULL,
    age_ms               INTEGER NOT NULL,
    window_ms            INTEGER NOT NULL,
    segment_id           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS gaps (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    after_seq     INTEGER NOT NULL,
    before_seq    INTEGER NOT NULL,
    missing_from  INTEGER NOT NULL,
    missing_to    INTEGER NOT NULL,
    detail        TEXT NOT NULL,
    segment_id    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS validation_errors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    seq         INTEGER NOT NULL,
    device_id   TEXT NOT NULL,
    message     TEXT NOT NULL,
    segment_id  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    segment_id      INTEGER PRIMARY KEY,
    reason          TEXT NOT NULL,
    paused          INTEGER NOT NULL,
    processed       INTEGER NOT NULL,
    degraded        INTEGER NOT NULL,
    budget_used     INTEGER NOT NULL,
    next_input_pos  INTEGER NOT NULL,
    detector_json   TEXT NOT NULL,
    created_at_ms   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS segments (
    segment_id    INTEGER PRIMARY KEY,
    started_ms    INTEGER NOT NULL,
    ended_ms      INTEGER NOT NULL,
    paused        INTEGER NOT NULL,
    reason        TEXT NOT NULL,
    note          TEXT NOT NULL
);
`
