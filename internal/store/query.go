package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"seedreview/internal/model"
)

type RunView struct {
	ID               int64
	SessionID        int64
	SourceFormat     string
	RecoveryID       string
	CapturedAt       string
	AppVersion       string
	RNGAlgorithm     string
	Seed             string
	RecoveredSeed    string
	StateSHA256      string
	Target           string
	ArtifactPath     string
	ManifestEvidence string
	StartedAt        string
	CompletedAt      string
	Status           string
	ExitCode         int
	Signal           string
	TargetSHA256     string
	TargetEvidence   string
	InputSHA256      string
	InputSize        int64
	InputEvidence    string
	StdoutEvidence   string
	StderrEvidence   string
	TraceEvidence    string
	EffectiveSeed    string
	FailureCode      string
	FailureMessage   string
	AutoConclusion   string
	NextActions      []model.NextAction
	Extensions       []model.ExtensionRecord
	Logs             []model.LogEvidence
	Findings         []model.Finding
	ManualChecks     []model.ManualCheck
	Evidence         []model.Evidence
}

func (s *Store) GetRun(ctx context.Context, runID int64) (RunView, error) {
	var view RunView
	var nextActions string
	err := s.db.QueryRowContext(ctx, `
SELECT r.id, r.session_id, s.source_format, s.recovery_id, s.captured_at,
       s.app_version, s.rng_algorithm, s.seed, s.recovered_seed,
       s.state_sha256, r.target_path, r.artifact_path, s.manifest_evidence,
       r.started_at, r.completed_at, r.status, r.exit_code, r.signal,
       r.target_sha256, r.target_evidence, r.input_sha256, r.input_size, r.input_evidence,
       r.stdout_evidence, r.stderr_evidence, r.trace_evidence,
       r.effective_seed, r.failure_code, r.failure_message,
       r.next_actions_json, r.auto_conclusion
FROM replay_runs r
JOIN recovery_sessions s ON s.id = r.session_id
WHERE r.id = ?`, runID).Scan(
		&view.ID, &view.SessionID, &view.SourceFormat, &view.RecoveryID,
		&view.CapturedAt, &view.AppVersion, &view.RNGAlgorithm, &view.Seed,
		&view.RecoveredSeed, &view.StateSHA256, &view.Target,
		&view.ArtifactPath, &view.ManifestEvidence, &view.StartedAt,
		&view.CompletedAt, &view.Status, &view.ExitCode, &view.Signal,
		&view.TargetSHA256, &view.TargetEvidence, &view.InputSHA256, &view.InputSize,
		&view.InputEvidence, &view.StdoutEvidence, &view.StderrEvidence,
		&view.TraceEvidence, &view.EffectiveSeed, &view.FailureCode,
		&view.FailureMessage, &nextActions, &view.AutoConclusion,
	)
	if err == sql.ErrNoRows {
		return RunView{}, ErrNotFound
	}
	if err != nil {
		return RunView{}, fmt.Errorf("query replay run: %w", err)
	}
	if err := json.Unmarshal([]byte(nextActions), &view.NextActions); err != nil {
		return RunView{}, fmt.Errorf("decode next actions: %w", err)
	}
	if err := s.loadRunDetails(ctx, &view); err != nil {
		return RunView{}, err
	}
	return view, nil
}

func (s *Store) loadRunDetails(ctx context.Context, view *RunView) error {
	extensions, err := s.loadExtensions(ctx, view.ID)
	if err != nil {
		return err
	}
	view.Extensions = extensions
	if err := s.loadLogs(ctx, view); err != nil {
		return err
	}
	if err := s.loadFindings(ctx, view); err != nil {
		return err
	}
	if err := s.loadManualChecks(ctx, view); err != nil {
		return err
	}
	return s.loadEvidence(ctx, view)
}

func (s *Store) loadExtensions(ctx context.Context, runID int64) ([]model.ExtensionRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT e.name, e.known, e.source, e.details_json,
       COALESCE(t.file, ''), COALESCE(t.line, 0),
       COALESCE(t.function_name, ''), COALESCE(t.kind, ''),
       COALESCE(p.principal, ''), COALESCE(p.action, ''),
       COALESCE(p.expected, ''), COALESCE(p.actual, ''),
       COALESCE(p.policy, ''), COALESCE(p.reason, '')
FROM extensions e
LEFT JOIN triggers t ON t.extension_id = e.id
LEFT JOIN permissions p ON p.extension_id = e.id
WHERE e.run_id = ?
ORDER BY e.id`, runID)
	if err != nil {
		return nil, fmt.Errorf("query extensions: %w", err)
	}
	defer rows.Close()
	var result []model.ExtensionRecord
	for rows.Next() {
		var extension model.ExtensionRecord
		var known int
		var details string
		var trigger model.TraceTrigger
		var permission model.TracePermission
		if err := rows.Scan(
			&extension.Name, &known, &extension.Source, &details,
			&trigger.File, &trigger.Line, &trigger.Function, &trigger.Kind,
			&permission.Principal, &permission.Action, &permission.Expected,
			&permission.Actual, &permission.Policy, &permission.Reason,
		); err != nil {
			return nil, fmt.Errorf("scan extension: %w", err)
		}
		extension.Known = known != 0
		if err := json.Unmarshal([]byte(details), &extension.Details); err != nil {
			return nil, fmt.Errorf("decode extension details: %w", err)
		}
		if trigger.File != "" {
			extension.Trigger = &trigger
		}
		if permission.Principal != "" {
			extension.Permission = &permission
		}
		result = append(result, extension)
	}
	return result, rows.Err()
}

func (s *Store) loadLogs(ctx context.Context, view *RunView) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT source, sequence, level, message, start_offset, end_offset,
       line_sha256, evidence_sha256
FROM log_lines WHERE run_id = ? ORDER BY sequence`, view.ID)
	if err != nil {
		return fmt.Errorf("query log lines: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var line model.LogEvidence
		if err := rows.Scan(
			&line.Source, &line.Sequence, &line.Level, &line.Message,
			&line.StartOffset, &line.EndOffset, &line.LineSHA256,
			&line.EvidenceSHA256,
		); err != nil {
			return fmt.Errorf("scan log line: %w", err)
		}
		view.Logs = append(view.Logs, line)
	}
	return rows.Err()
}

func (s *Store) loadFindings(ctx context.Context, view *RunView) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT code, severity, title, details_json
FROM findings WHERE run_id = ? ORDER BY id`, view.ID)
	if err != nil {
		return fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var finding model.Finding
		var details string
		if err := rows.Scan(&finding.Code, &finding.Severity, &finding.Title, &details); err != nil {
			return fmt.Errorf("scan finding: %w", err)
		}
		if err := json.Unmarshal([]byte(details), &finding.Details); err != nil {
			return fmt.Errorf("decode finding details: %w", err)
		}
		view.Findings = append(view.Findings, finding)
	}
	return rows.Err()
}

func (s *Store) loadManualChecks(ctx context.Context, view *RunView) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT code, question, required, status, owner, notes, decided_at
FROM manual_checks WHERE run_id = ? ORDER BY id`, view.ID)
	if err != nil {
		return fmt.Errorf("query manual checks: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var check model.ManualCheck
		var required int
		if err := rows.Scan(
			&check.Code, &check.Question, &required, &check.Status,
			&check.Owner, &check.Notes, &check.DecidedAt,
		); err != nil {
			return fmt.Errorf("scan manual check: %w", err)
		}
		check.Required = required != 0
		view.ManualChecks = append(view.ManualChecks, check)
	}
	return rows.Err()
}

func (s *Store) loadEvidence(ctx context.Context, view *RunView) error {
	hashes := []string{
		view.ManifestEvidence, view.TargetEvidence, view.InputEvidence,
		view.StdoutEvidence, view.StderrEvidence, view.TraceEvidence,
	}
	seen := map[string]bool{}
	for _, hash := range hashes {
		if hash == "" || seen[hash] {
			continue
		}
		seen[hash] = true
		var record model.Evidence
		var created string
		err := s.db.QueryRowContext(ctx, `
SELECT sha256, kind, relative_path, size, media_type, created_at
FROM evidence WHERE sha256 = ?`, hash).Scan(
			&record.SHA256, &record.Kind, &record.RelativePath, &record.Size,
			&record.MediaType, &created,
		)
		if err != nil {
			return fmt.Errorf("query evidence %s: %w", hash, err)
		}
		record.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		view.Evidence = append(view.Evidence, record)
	}
	return nil
}

func (s *Store) LatestRunID(ctx context.Context) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(id), 0) FROM replay_runs").Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("query latest run: %w", err)
	}
	if id == 0 {
		return 0, ErrNotFound
	}
	return id, nil
}
