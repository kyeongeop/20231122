PRAGMA journal_mode = WAL;

-- Fuzz / validation runs with lifecycle events.
CREATE TABLE IF NOT EXISTS runs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    tool       TEXT NOT NULL,
    status     TEXT NOT NULL, -- running | completed | cancelled | failed
    started_at TEXT NOT NULL, -- RFC3339 UTC, concrete timestamp
    ended_at   TEXT
);

CREATE TABLE IF NOT EXISTS run_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id  INTEGER NOT NULL REFERENCES runs(id),
    seq     INTEGER NOT NULL,
    kind    TEXT NOT NULL, -- started | cancelled | resumed | finished | failed
    detail  TEXT NOT NULL DEFAULT '',
    at      TEXT NOT NULL
);

-- Original raw inputs. Every conclusion anchors to one row via sha256;
-- the bytes here are never modified after insertion (see evidence/raw).
CREATE TABLE IF NOT EXISTS inputs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id    INTEGER NOT NULL REFERENCES runs(id),
    label     TEXT NOT NULL,
    sha256    TEXT NOT NULL,
    raw_len   INTEGER NOT NULL,
    raw       TEXT NOT NULL,
    raw_hex   TEXT NOT NULL
);

-- The three anchor markers per input, with concrete raw offsets.
CREATE TABLE IF NOT EXISTS anchors (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    input_id   INTEGER NOT NULL REFERENCES inputs(id),
    seq        INTEGER NOT NULL, -- 1..3
    marker     TEXT NOT NULL,    -- ANCHOR1 | ANCHOR2 | ANCHOR3
    marker_off INTEGER NOT NULL, -- raw byte offset of the marker
    body_start INTEGER NOT NULL,
    body_end   INTEGER NOT NULL,
    body       TEXT NOT NULL
);

-- Processing steps in order: the replayable lineage chain.
CREATE TABLE IF NOT EXISTS steps (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    input_id INTEGER NOT NULL REFERENCES inputs(id),
    seq      INTEGER NOT NULL,
    name     TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT ''
);

-- Validation findings: attack input -> trigger position -> permission.
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    input_id    INTEGER NOT NULL REFERENCES inputs(id),
    anchor      TEXT NOT NULL,
    marker_off  INTEGER NOT NULL, -- trigger position (anchor marker)
    byte_offset INTEGER NOT NULL, -- exact offending byte offset in raw input
    stage       TEXT NOT NULL,
    code        TEXT NOT NULL,
    message     TEXT NOT NULL
);

-- Permission verdicts. kind separates automated output from manual review.
CREATE TABLE IF NOT EXISTS conclusions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    input_id   INTEGER NOT NULL REFERENCES inputs(id),
    kind       TEXT NOT NULL, -- automated | manual
    verdict    TEXT NOT NULL, -- deny | allow | undetermined
    rationale  TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

-- Key evidence retained for every case, especially undetermined edge cases
-- (empty / oversized inputs): raw prefixes, hashes, offsets, log excerpts.
CREATE TABLE IF NOT EXISTS evidence (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    input_id INTEGER REFERENCES inputs(id),
    label    TEXT NOT NULL,
    content  TEXT NOT NULL
);

-- Actionable follow-ups attached to failed runs or undetermined conclusions.
CREATE TABLE IF NOT EXISTS next_actions (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id   INTEGER REFERENCES runs(id),
    input_id INTEGER REFERENCES inputs(id),
    action   TEXT NOT NULL,
    reason   TEXT NOT NULL DEFAULT '',
    status   TEXT NOT NULL DEFAULT 'open' -- open | done
);
