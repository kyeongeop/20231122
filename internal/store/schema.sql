PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS runs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    tool       TEXT NOT NULL,
    status     TEXT NOT NULL, -- running | completed | cancelled | failed
    started_at TEXT NOT NULL,
    ended_at   TEXT
);

-- Lifecycle events of a run, including mid-run cancellations.
CREATE TABLE IF NOT EXISTS run_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id  INTEGER NOT NULL REFERENCES runs(id),
    seq     INTEGER NOT NULL,
    kind    TEXT NOT NULL, -- started | cancelled | resumed | finished | failed
    detail  TEXT NOT NULL DEFAULT '',
    at      TEXT NOT NULL
);

-- Original raw inputs; every conclusion anchors to one of these via sha256.
CREATE TABLE IF NOT EXISTS inputs (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id  INTEGER NOT NULL REFERENCES runs(id),
    label   TEXT NOT NULL,
    sha256  TEXT NOT NULL,
    content TEXT NOT NULL
);

-- Processing steps applied to an input, in order (the lineage chain).
CREATE TABLE IF NOT EXISTS steps (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    input_id INTEGER NOT NULL REFERENCES inputs(id),
    seq      INTEGER NOT NULL,
    name     TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT ''
);

-- Conclusions. kind separates automated output from human confirmation.
CREATE TABLE IF NOT EXISTS conclusions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    input_id   INTEGER NOT NULL REFERENCES inputs(id),
    kind       TEXT NOT NULL, -- automated | manual
    verdict    TEXT NOT NULL, -- bypass_detected | no_bypass | undetermined
    rationale  TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

-- Key evidence retained for edge cases (e.g. undetermined verdicts).
CREATE TABLE IF NOT EXISTS evidence (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    input_id INTEGER NOT NULL REFERENCES inputs(id),
    label    TEXT NOT NULL,
    content  TEXT NOT NULL
);

-- Actionable follow-ups attached to failed runs or undetermined conclusions.
CREATE TABLE IF NOT EXISTS next_actions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     INTEGER REFERENCES runs(id),
    input_id   INTEGER REFERENCES inputs(id),
    action     TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'open' -- open | done
);
