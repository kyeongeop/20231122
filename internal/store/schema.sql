PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS checks (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  source TEXT NOT NULL,
  input_name TEXT NOT NULL,
  raw_input BLOB NOT NULL,
  raw_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  status TEXT NOT NULL,
  auto_verdict TEXT NOT NULL DEFAULT '',
  auto_label TEXT NOT NULL DEFAULT '',
  confidence REAL NOT NULL DEFAULT 0,
  auto_summary TEXT NOT NULL DEFAULT '',
  ambiguous_rule TEXT NOT NULL DEFAULT '',
  ambiguous_note TEXT NOT NULL DEFAULT '',
  human_verdict TEXT NOT NULL DEFAULT '',
  human_label TEXT NOT NULL DEFAULT '',
  human_reviewer TEXT NOT NULL DEFAULT '',
  human_note TEXT NOT NULL DEFAULT '',
  human_at TEXT,
  fuzzer_version TEXT NOT NULL DEFAULT '',
  fuzzer_execs INTEGER NOT NULL DEFAULT 0,
  fuzzer_artifact TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS attempts (
  id TEXT PRIMARY KEY,
  check_id TEXT NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
  number INTEGER NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  cancelled_by TEXT NOT NULL DEFAULT '',
  cancel_reason TEXT NOT NULL DEFAULT '',
  error_code TEXT NOT NULL DEFAULT '',
  error_message TEXT NOT NULL DEFAULT '',
  next_actions TEXT NOT NULL DEFAULT '[]',
  evidence_count INTEGER NOT NULL DEFAULT 0,
  UNIQUE(check_id, number)
);

CREATE TABLE IF NOT EXISTS steps (
  id TEXT PRIMARY KEY,
  attempt_id TEXT NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  phase TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  summary TEXT NOT NULL DEFAULT '',
  input_excerpt TEXT NOT NULL DEFAULT '',
  output_excerpt TEXT NOT NULL DEFAULT '',
  tool TEXT NOT NULL DEFAULT '',
  evidence_ids TEXT NOT NULL DEFAULT '[]',
  ambiguous INTEGER NOT NULL DEFAULT 0,
  UNIQUE(attempt_id, position)
);

CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  check_id TEXT NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
  attempt_id TEXT NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
  step_id TEXT NOT NULL DEFAULT '',
  label TEXT NOT NULL,
  kind TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  content BLOB NOT NULL,
  retained INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  check_id TEXT NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
  rule TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence REAL NOT NULL,
  detail TEXT NOT NULL,
  step_id TEXT NOT NULL,
  evidence_id TEXT NOT NULL,
  position INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audits (
  id TEXT PRIMARY KEY,
  check_id TEXT NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
  attempt_id TEXT NOT NULL DEFAULT '',
  event TEXT NOT NULL,
  actor TEXT NOT NULL,
  detail TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fuzz_imports (
  id TEXT PRIMARY KEY,
  check_id TEXT NOT NULL DEFAULT '',
  artifact_sha256 TEXT NOT NULL,
  artifact_size INTEGER NOT NULL,
  minimized INTEGER NOT NULL DEFAULT 0,
  log_excerpt TEXT NOT NULL,
  imported_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attempts_check ON attempts(check_id, number DESC);
CREATE INDEX IF NOT EXISTS idx_steps_attempt ON steps(attempt_id, position);
CREATE INDEX IF NOT EXISTS idx_evidence_check ON evidence(check_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audits_check ON audits(check_id, created_at);
