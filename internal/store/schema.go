package store

const schema = `
CREATE TABLE IF NOT EXISTS runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('running','interrupted','done','failed')),
    mode          TEXT NOT NULL CHECK (mode IN ('fuzz','single')),
    max_runs      INTEGER NOT NULL,
    max_len       INTEGER NOT NULL,
    seed          INTEGER NOT NULL,
    jobs          INTEGER NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    pid           INTEGER,
    exit_code     INTEGER,
    exec_note     TEXT
);

CREATE TABLE IF NOT EXISTS samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    sample_key      TEXT NOT NULL,
    scenario        TEXT NOT NULL,
    boundary        TEXT,
    side            TEXT CHECK (side IS NULL OR side IN ('below','above')),
    param_value     TEXT,
    input           TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','running','ok','crash','error','skipped')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    UNIQUE(run_id, sample_key)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id   INTEGER NOT NULL REFERENCES samples(id),
    severity    TEXT NOT NULL CHECK (severity IN ('CRIT','WARN','INFO')),
    code        TEXT NOT NULL,
    message     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id   INTEGER NOT NULL REFERENCES samples(id),
    kind        TEXT NOT NULL,
    path        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    bytes       INTEGER NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_samples_run ON samples(run_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_sample ON findings(sample_id);
CREATE INDEX IF NOT EXISTS idx_evidence_sample ON evidence(sample_id);
`

type Run struct {
	ID        int64
	Name      string
	Status    string
	Mode      string
	MaxRuns   int64
	MaxLen    int
	Seed      int64
	Jobs      int
	CreatedAt string
	UpdatedAt string
	PID       int64
	ExitCode  *int
	ExecNote  string
}

type Sample struct {
	ID         int64
	RunID      int64
	SampleKey  string
	Scenario   string
	Boundary   string
	Side       string
	ParamValue string
	Input      string
	Status     string
	Attempts   int
}

type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

type Evidence struct {
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
	CreatedAt string `json:"created_at"`
}
