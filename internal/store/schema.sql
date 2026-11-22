PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    sha256 TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    size INTEGER NOT NULL,
    media_type TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recovery_key TEXT NOT NULL UNIQUE,
    source_format TEXT NOT NULL,
    recovery_id TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    app_version TEXT NOT NULL,
    rng_algorithm TEXT NOT NULL,
    seed TEXT NOT NULL,
    recovered_seed TEXT NOT NULL,
    state_sha256 TEXT NOT NULL,
    target TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    environment_json TEXT NOT NULL,
    notes TEXT NOT NULL,
    manifest_evidence TEXT NOT NULL REFERENCES evidence(sha256),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS replay_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES recovery_sessions(id),
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    status TEXT NOT NULL,
    exit_code INTEGER NOT NULL,
    signal TEXT NOT NULL,
    target_sha256 TEXT NOT NULL,
    target_evidence TEXT NOT NULL,
    target_path TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    input_sha256 TEXT NOT NULL,
    input_size INTEGER NOT NULL,
    input_evidence TEXT NOT NULL,
    stdout_evidence TEXT NOT NULL,
    stderr_evidence TEXT NOT NULL,
    trace_evidence TEXT NOT NULL,
    seed TEXT NOT NULL,
    effective_seed TEXT NOT NULL,
    failure_code TEXT NOT NULL,
    failure_message TEXT NOT NULL,
    next_actions_json TEXT NOT NULL,
    auto_conclusion TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS extensions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES replay_runs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    known INTEGER NOT NULL,
    source TEXT NOT NULL,
    details_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS triggers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES replay_runs(id) ON DELETE CASCADE,
    extension_id INTEGER REFERENCES extensions(id) ON DELETE SET NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    function_name TEXT NOT NULL,
    kind TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES replay_runs(id) ON DELETE CASCADE,
    extension_id INTEGER REFERENCES extensions(id) ON DELETE SET NULL,
    principal TEXT NOT NULL,
    action TEXT NOT NULL,
    expected TEXT NOT NULL,
    actual TEXT NOT NULL,
    policy TEXT NOT NULL,
    reason TEXT NOT NULL,
    log_evidence TEXT NOT NULL REFERENCES evidence(sha256)
);

CREATE TABLE IF NOT EXISTS log_lines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES replay_runs(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    start_offset INTEGER NOT NULL,
    end_offset INTEGER NOT NULL,
    line_sha256 TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL REFERENCES evidence(sha256)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES replay_runs(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    details_json TEXT NOT NULL,
    automatic INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS manual_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES replay_runs(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    question TEXT NOT NULL,
    required INTEGER NOT NULL,
    status TEXT NOT NULL,
    owner TEXT NOT NULL,
    notes TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    UNIQUE(run_id, code)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES replay_runs(id) ON DELETE CASCADE,
    at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runs_session ON replay_runs(session_id);
CREATE INDEX IF NOT EXISTS idx_extensions_run ON extensions(run_id);
CREATE INDEX IF NOT EXISTS idx_triggers_run ON triggers(run_id);
CREATE INDEX IF NOT EXISTS idx_permissions_run ON permissions(run_id);
CREATE INDEX IF NOT EXISTS idx_logs_run ON log_lines(run_id, sequence);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
