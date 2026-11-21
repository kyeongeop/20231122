PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = FULL;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    clock_offset_ns INTEGER NOT NULL,
    chain_status TEXT NOT NULL,
    anchor_pair_count INTEGER NOT NULL,
    device_a_event_rows INTEGER NOT NULL,
    device_b_event_rows INTEGER NOT NULL,
    correction_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_blobs (
    blob_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    role TEXT NOT NULL,
    source_name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    bytes BLOB NOT NULL,
    UNIQUE(case_id, role, sha256)
);

CREATE TABLE IF NOT EXISTS events (
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    device TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    time_unix_ns INTEGER NOT NULL,
    corrected_time_unix_ns INTEGER NOT NULL,
    kind TEXT NOT NULL,
    anchor_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    line_no INTEGER NOT NULL,
    raw_line TEXT NOT NULL,
    hash_valid INTEGER NOT NULL,
    chain_relation TEXT NOT NULL,
    PRIMARY KEY(case_id, device, ordinal)
);

CREATE TABLE IF NOT EXISTS corrections (
    correction_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    device TEXT NOT NULL,
    seq_from INTEGER NOT NULL,
    seq_to INTEGER NOT NULL,
    missing_count INTEGER NOT NULL,
    left_seq INTEGER NOT NULL,
    left_hash TEXT NOT NULL,
    right_seq INTEGER NOT NULL,
    right_prev_hash TEXT NOT NULL,
    corrected_time_from_unix_ns INTEGER NOT NULL,
    corrected_time_to_unix_ns INTEGER NOT NULL,
    anchor_pairs_used INTEGER NOT NULL,
    rationale_code TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS samples (
    sample_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    sample_index INTEGER NOT NULL,
    name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    source_name TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    bytes BLOB NOT NULL,
    UNIQUE(case_id, sample_index),
    UNIQUE(case_id, name)
);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    harness_sha256 TEXT NOT NULL,
    harness_path TEXT NOT NULL,
    timeout_ms INTEGER NOT NULL,
    fuzz_args TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    requested_limit INTEGER NOT NULL,
    completed_count INTEGER NOT NULL,
    attempt_count INTEGER NOT NULL,
    resumed_count INTEGER NOT NULL,
    schema_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attempts (
    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    sample_id TEXT NOT NULL REFERENCES samples(sample_id),
    attempt_no INTEGER NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    exit_code INTEGER NOT NULL,
    signal INTEGER NOT NULL,
    timed_out INTEGER NOT NULL,
    stdout BLOB NOT NULL,
    stderr BLOB NOT NULL,
    stdout_sha256 TEXT NOT NULL,
    stderr_sha256 TEXT NOT NULL,
    harness_output TEXT NOT NULL,
    result_json TEXT NOT NULL,
    error TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    UNIQUE(run_id, sample_id, attempt_no)
);

CREATE INDEX IF NOT EXISTS idx_events_case_device_seq
    ON events(case_id, device, seq);
CREATE INDEX IF NOT EXISTS idx_corrections_case_device
    ON corrections(case_id, device, seq_from);
CREATE INDEX IF NOT EXISTS idx_samples_case_order
    ON samples(case_id, sample_index);
CREATE INDEX IF NOT EXISTS idx_attempts_run_sample
    ON attempts(run_id, sample_id, attempt_no);
