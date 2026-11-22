package bundle

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"apiskew.local/apiskew/internal/domain"
	"apiskew.local/apiskew/internal/store"
)

const ToolVersion = "0.1.0"

type SessionSummary struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Status         string `json:"status"`
	ObjectKey      string `json:"object_key"`
	ObjectID       string `json:"object_canonical_id"`
	ScenarioSHA256 string `json:"scenario_sha256"`
	CreatedAt      string `json:"created_at"`
}

type FileInfo struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type Manifest struct {
	Schema        string         `json:"schema"`
	ToolVersion   string         `json:"tool_version"`
	CreatedAt     string         `json:"created_at"`
	Session       SessionSummary `json:"session"`
	RecordCount   int            `json:"record_count"`
	RecordFields  []string       `json:"record_fields"`
	AttemptFields []string       `json:"attempt_fields"`
	FuzzerSHA256  string         `json:"fuzzer_sha256"`
	FuzzerCommand []string       `json:"fuzzer_command"`
	VerifyCommand string         `json:"verify_command"`
	Files         []FileInfo     `json:"files"`
}

type ExportOptions struct {
	SessionID string
	SampleID  string
	OutDir    string
}

func Export(ctx context.Context, st *store.Store, options ExportOptions) (Manifest, error) {
	session, err := st.GetSession(ctx, options.SessionID)
	if err != nil {
		return Manifest{}, err
	}
	samples, err := st.ListSamples(ctx, session.ID)
	if err != nil {
		return Manifest{}, err
	}
	if len(samples) == 0 {
		return Manifest{}, errors.New("session has no samples to export")
	}
	if options.SampleID != "" {
		var selected []store.Sample
		for _, sample := range samples {
			if sample.ID == options.SampleID {
				selected = append(selected, sample)
				break
			}
		}
		if len(selected) == 0 {
			return Manifest{}, fmt.Errorf("sample %s not found", options.SampleID)
		}
		samples = selected
	}
	if options.OutDir == "" {
		return Manifest{}, errors.New("export directory is required")
	}
	parent := filepath.Dir(options.OutDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return Manifest{}, err
	}
	if _, err := os.Stat(options.OutDir); err == nil {
		return Manifest{}, fmt.Errorf("export directory already exists: %s", options.OutDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, err
	}
	tempDir, err := os.MkdirTemp(parent, ".apiskew-export-")
	if err != nil {
		return Manifest{}, err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(tempDir)
		}
	}()
	manifest, err := writeBundle(ctx, st, session, samples, tempDir)
	if err != nil {
		return Manifest{}, err
	}
	if err := os.Rename(tempDir, options.OutDir); err != nil {
		return Manifest{}, err
	}
	success = true
	return manifest, nil
}

func writeBundle(ctx context.Context, st *store.Store, session store.Session, samples []store.Sample, dir string) (Manifest, error) {
	for _, subdir := range []string{"evidence"} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0o755); err != nil {
			return Manifest{}, err
		}
	}
	scenarioJSON, err := session.Scenario.JSON()
	if err != nil {
		return Manifest{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "scenario.json"), scenarioJSON, 0o644); err != nil {
		return Manifest{}, err
	}
	records := make([]Record, 0, len(samples))
	attempts := make([]AttemptRecord, 0)
	fuzzerSHA := ""
	var fuzzerCommand []string
	evidenceFiles := make([]string, 0)
	for _, sample := range samples {
		runs, err := st.ListRuns(ctx, session.ID, sample.ID)
		if err != nil {
			return Manifest{}, err
		}
		if len(runs) == 0 {
			return Manifest{}, fmt.Errorf("sample %s has no replay evidence", sample.ID)
		}
		latest := runs[len(runs)-1]
		latestEvidence, err := decodeEvidence(latest.EvidenceJSON)
		if err != nil {
			return Manifest{}, fmt.Errorf("sample %s evidence: %w", sample.ID, err)
		}
		fresh, err := domain.Evaluate(session.Scenario, sample.Input, "go-export-check")
		if err != nil {
			return Manifest{}, err
		}
		drift := domain.CompareFingerprints(latestEvidence, fresh.Evidence)
		if len(drift) > 0 {
			return Manifest{}, fmt.Errorf("sample %s stored evidence drifted: %s", sample.ID, domain.JoinFields(drift))
		}
		if latestEvidence.SampleSHA256 != domain.SHA256Hex(sample.Input) {
			return Manifest{}, fmt.Errorf("sample %s input hash mismatch", sample.ID)
		}
		if fuzzerSHA == "" && latestEvidence.FuzzerSHA256 != "" {
			fuzzerSHA = latestEvidence.FuzzerSHA256
			fuzzerCommand = latestEvidence.FuzzerCommand
		}
		for _, run := range runs {
			evidence, err := decodeEvidence(run.EvidenceJSON)
			if err != nil {
				return Manifest{}, fmt.Errorf("sample %s attempt %d evidence: %w", sample.ID, run.Attempt, err)
			}
			if evidence.SampleSHA256 != sample.InputSHA256 {
				return Manifest{}, fmt.Errorf("sample %s attempt %d evidence input mismatch", sample.ID, run.Attempt)
			}
			if got := domain.SHA256Hex([]byte(run.EvidenceJSON)); got != run.EvidenceSHA256 {
				return Manifest{}, fmt.Errorf("sample %s attempt %d evidence hash mismatch", sample.ID, run.Attempt)
			}
			path := evidenceName(sample.ID, run.Attempt)
			absolute := filepath.Join(dir, path)
			if err := os.WriteFile(absolute, []byte(run.EvidenceJSON), 0o644); err != nil {
				return Manifest{}, err
			}
			evidenceFiles = append(evidenceFiles, path)
			attempts = append(attempts, AttemptRecord{
				SampleID:             sample.ID,
				Attempt:              run.Attempt,
				Engine:               run.Engine,
				Status:               run.Status,
				Comparable:           run.Comparable,
				V1Allow:              run.V1Allow,
				V2Allow:              run.V2Allow,
				PermissionDifference: run.PermissionDifference,
				EvidencePath:         path,
				EvidenceSHA256:       run.EvidenceSHA256,
				StartedAt:            run.StartedAt,
				CompletedAt:          run.CompletedAt,
			})
		}
		record := Record{
			Ordinal:              sample.Ordinal,
			SampleID:             sample.ID,
			Source:               sample.Source,
			SampleSHA256:         sample.InputSHA256,
			ScenarioSHA256:       fresh.Evidence.ScenarioSHA256,
			ObjectKey:            session.Scenario.Object.Key,
			ObjectCanonicalID:    session.Scenario.Object.CanonicalID,
			InputHex:             domain.Hex(sample.Input),
			InputBytes:           len(sample.Input),
			ActorRole:            sample.Attack.ActorRole.String(),
			Action:               sample.Attack.Action.String(),
			TenantMatch:          sample.Attack.TenantMatch,
			RequestDevice:        sample.Attack.RequestDevice,
			DeviceASkewMS:        sample.Attack.SkewAMS,
			DeviceBSkewMS:        sample.Attack.SkewBMS,
			V1Allow:              latestEvidence.V1.Allow,
			V1Reason:             latestEvidence.V1.Reason,
			V1SelectedReplica:    latestEvidence.V1.SelectedReplica,
			V2Allow:              latestEvidence.V2.Allow,
			V2Reason:             latestEvidence.V2.Reason,
			V2SelectedReplica:    latestEvidence.V2.SelectedReplica,
			PermissionDifference: latestEvidence.Comparison.PermissionDifference,
			DifferentFields:      domain.JoinFields(latestEvidence.Comparison.DifferentFields),
			RootCause:            fresh.FixPlan.RootCause,
			FixRuleID:            fresh.FixPlan.RuleID,
			FixSummary:           fresh.FixPlan.Summary,
			FixVerified:          fresh.FixPlan.Verified,
			Attempts:             len(runs),
			LatestAttempt:        latest.Attempt,
			EvidencePath:         evidenceName(sample.ID, latest.Attempt),
			EvidenceSHA256:       latest.EvidenceSHA256,
			ReplayCommand:        fmt.Sprintf("apiskew verify-bundle . --sample %s", sample.ID),
		}
		records = append(records, record)
	}
	if err := writeJSONL(filepath.Join(dir, "records.jsonl"), records); err != nil {
		return Manifest{}, err
	}
	if err := writeCSV(filepath.Join(dir, "records.csv"), RecordFields, records); err != nil {
		return Manifest{}, err
	}
	if err := writeAttempts(filepath.Join(dir, "attempts.jsonl"), attempts); err != nil {
		return Manifest{}, err
	}
	if err := writeSQLite(filepath.Join(dir, "records.db"), session.Scenario, records, attempts); err != nil {
		return Manifest{}, err
	}
	if err := writeReview(filepath.Join(dir, "REVIEW.md"), session, len(records)); err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{
		Schema:      Schema,
		ToolVersion: ToolVersion,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Session: SessionSummary{
			ID:             session.ID,
			Name:           session.Name,
			Status:         session.Status,
			ObjectKey:      session.Scenario.Object.Key,
			ObjectID:       session.Scenario.Object.CanonicalID,
			ScenarioSHA256: session.ScenarioSHA,
			CreatedAt:      session.CreatedAt,
		},
		RecordCount:   len(records),
		RecordFields:  append([]string{}, RecordFields...),
		AttemptFields: append([]string{}, AttemptFields...),
		FuzzerSHA256:  fuzzerSHA,
		FuzzerCommand: fuzzerCommand,
		VerifyCommand: "apiskew verify-bundle .",
	}
	paths, err := bundleFilePaths(dir)
	if err != nil {
		return Manifest{}, err
	}
	for _, path := range paths {
		info, err := fileInfo(dir, path)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Files = append(manifest.Files, info)
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	manifestJSON = append(manifestJSON, '\n')
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifestJSON, 0o644); err != nil {
		return Manifest{}, err
	}
	if err := writeChecksums(dir); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func decodeEvidence(raw string) (domain.Evidence, error) {
	var evidence domain.Evidence
	if err := json.Unmarshal([]byte(raw), &evidence); err != nil {
		return domain.Evidence{}, err
	}
	return evidence, nil
}

func writeJSONL(path string, records []Record) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return err
		}
	}
	return file.Sync()
}

func writeAttempts(path string, attempts []AttemptRecord) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	for _, attempt := range attempts {
		if err := encoder.Encode(attempt); err != nil {
			return err
		}
	}
	return file.Sync()
}

func writeCSV(path string, header []string, records []Record) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	if err := writer.Write(header); err != nil {
		return err
	}
	for _, record := range records {
		if err := writer.Write(record.row()); err != nil {
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}
	return file.Sync()
}

func writeSQLite(path string, scenario domain.Scenario, records []Record, attempts []AttemptRecord) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	schema := `CREATE TABLE records (
		ordinal INTEGER PRIMARY KEY,
		sample_id TEXT NOT NULL UNIQUE,
		source TEXT NOT NULL,
		sample_sha256 TEXT NOT NULL,
		scenario_sha256 TEXT NOT NULL,
		object_key TEXT NOT NULL,
		object_canonical_id TEXT NOT NULL,
		input_hex TEXT NOT NULL,
		input_bytes INTEGER NOT NULL,
		actor_role TEXT NOT NULL,
		action TEXT NOT NULL,
		tenant_match INTEGER NOT NULL,
		request_device TEXT NOT NULL,
		device_a_skew_ms INTEGER NOT NULL,
		device_b_skew_ms INTEGER NOT NULL,
		v1_allow INTEGER NOT NULL,
		v1_reason TEXT NOT NULL,
		v1_selected_replica TEXT NOT NULL,
		v2_allow INTEGER NOT NULL,
		v2_reason TEXT NOT NULL,
		v2_selected_replica TEXT NOT NULL,
		permission_difference INTEGER NOT NULL,
		different_fields TEXT NOT NULL,
		root_cause TEXT NOT NULL,
		fix_rule_id TEXT NOT NULL,
		fix_summary TEXT NOT NULL,
		fix_verified INTEGER NOT NULL,
		attempts INTEGER NOT NULL,
		latest_attempt INTEGER NOT NULL,
		evidence_path TEXT NOT NULL,
		evidence_sha256 TEXT NOT NULL,
		replay_command TEXT NOT NULL,
		record_json TEXT NOT NULL
	);
	CREATE TABLE attempts (
		sample_id TEXT NOT NULL,
		attempt INTEGER NOT NULL,
		engine TEXT NOT NULL,
		status TEXT NOT NULL,
		comparable INTEGER NOT NULL,
		v1_allow INTEGER NOT NULL,
		v2_allow INTEGER NOT NULL,
		permission_difference INTEGER NOT NULL,
		evidence_path TEXT NOT NULL,
		evidence_sha256 TEXT NOT NULL,
		started_at TEXT NOT NULL,
		completed_at TEXT NOT NULL,
		PRIMARY KEY(sample_id, attempt)
	);`
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	scenarioJSON, err := scenario.CanonicalJSON()
	if err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE TABLE scenario (scenario_json TEXT NOT NULL)`); err != nil {
		return err
	}
	if _, err := db.Exec(`INSERT INTO scenario(scenario_json) VALUES(?)`, string(scenarioJSON)); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, record := range records {
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO records VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			record.Ordinal, record.SampleID, record.Source, record.SampleSHA256, record.ScenarioSHA256,
			record.ObjectKey, record.ObjectCanonicalID, record.InputHex, record.InputBytes,
			record.ActorRole, record.Action, record.TenantMatch, record.RequestDevice,
			record.DeviceASkewMS, record.DeviceBSkewMS, record.V1Allow, record.V1Reason,
			record.V1SelectedReplica, record.V2Allow, record.V2Reason, record.V2SelectedReplica,
			record.PermissionDifference, record.DifferentFields, record.RootCause, record.FixRuleID,
			record.FixSummary, record.FixVerified, record.Attempts, record.LatestAttempt,
			record.EvidencePath, record.EvidenceSHA256, record.ReplayCommand, string(raw),
		); err != nil {
			return err
		}
	}
	for _, attempt := range attempts {
		if _, err := tx.Exec(`INSERT INTO attempts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
			attempt.SampleID, attempt.Attempt, attempt.Engine, attempt.Status, attempt.Comparable,
			attempt.V1Allow, attempt.V2Allow, attempt.PermissionDifference, attempt.EvidencePath,
			attempt.EvidenceSHA256, attempt.StartedAt, attempt.CompletedAt,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func bundleFilePaths(dir string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if relative == "manifest.json" || relative == "SHA256SUMS" {
			return nil
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

func fileInfo(dir, relative string) (FileInfo, error) {
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(relative)))
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{Path: relative, SHA256: domain.SHA256Hex(data), Bytes: int64(len(data))}, nil
}

func writeChecksums(dir string) error {
	paths, err := bundleFilePaths(dir)
	if err != nil {
		return err
	}
	paths = append(paths, "manifest.json")
	sort.Strings(paths)
	var builder strings.Builder
	for _, path := range paths {
		info, err := fileInfo(dir, path)
		if err != nil {
			return err
		}
		fmt.Fprintf(&builder, "%s  %s\n", info.SHA256, path)
	}
	return os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(builder.String()), 0o644)
}
