package store

var schemaStatements = []string{
	`PRAGMA foreign_keys = ON`,
	`CREATE TABLE IF NOT EXISTS artifact_meta (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS runs (
		run_id INTEGER PRIMARY KEY AUTOINCREMENT,
		case_id TEXT NOT NULL,
		trace_id TEXT NOT NULL,
		created_at TEXT NOT NULL,
		status TEXT NOT NULL,
		decision TEXT NOT NULL,
		trigger_detected INTEGER NOT NULL,
		tainted_escalation INTEGER NOT NULL,
		clock_skew_ms INTEGER NOT NULL,
		input_sha256 TEXT NOT NULL,
		input_size INTEGER NOT NULL,
		input_state TEXT NOT NULL,
		evidence_sha256 TEXT NOT NULL,
		result_sha256 TEXT NOT NULL,
		result_json BLOB NOT NULL,
		UNIQUE(case_id, trace_id, result_sha256)
	)`,
	`CREATE TABLE IF NOT EXISTS operations (
		run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
		ordinal INTEGER NOT NULL,
		seq INTEGER NOT NULL,
		kind TEXT NOT NULL,
		operand INTEGER NOT NULL,
		width_bits INTEGER NOT NULL,
		note TEXT NOT NULL,
		PRIMARY KEY(run_id, ordinal)
	)`,
	`CREATE TABLE IF NOT EXISTS taint_steps (
		run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
		ordinal INTEGER NOT NULL,
		seq INTEGER NOT NULL,
		kind TEXT NOT NULL,
		operand INTEGER NOT NULL,
		width_bits INTEGER NOT NULL,
		before_value INTEGER NOT NULL,
		after_value INTEGER NOT NULL,
		tainted INTEGER NOT NULL,
		changed INTEGER NOT NULL,
		wrapped INTEGER NOT NULL,
		location TEXT NOT NULL,
		PRIMARY KEY(run_id, ordinal)
	)`,
	`CREATE TABLE IF NOT EXISTS evidence_events (
		run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
		ordinal INTEGER NOT NULL,
		event_id TEXT NOT NULL,
		device_id TEXT NOT NULL,
		kind TEXT NOT NULL,
		causal_order INTEGER NOT NULL,
		wall_time TEXT NOT NULL,
		monotonic_ns INTEGER NOT NULL,
		payload_sha256 TEXT NOT NULL,
		detail TEXT NOT NULL,
		PRIMARY KEY(run_id, ordinal)
	)`,
	`CREATE TABLE IF NOT EXISTS key_evidence (
		run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
		ordinal INTEGER NOT NULL,
		kind TEXT NOT NULL,
		ref TEXT NOT NULL,
		sha256 TEXT NOT NULL,
		note TEXT NOT NULL,
		PRIMARY KEY(run_id, ordinal)
	)`,
	`CREATE TABLE IF NOT EXISTS diagnostics (
		run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
		ordinal INTEGER NOT NULL,
		level TEXT NOT NULL,
		code TEXT NOT NULL,
		message TEXT NOT NULL,
		PRIMARY KEY(run_id, ordinal)
	)`,
	`CREATE INDEX IF NOT EXISTS runs_case_id_idx ON runs(case_id, run_id)`,
	`CREATE INDEX IF NOT EXISTS runs_created_at_idx ON runs(created_at, run_id)`,
}
