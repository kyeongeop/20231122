package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"pathaliaslab/internal/experiment"
	"pathaliaslab/internal/ledger"
)

type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type ManifestRun struct {
	RunID            string `json:"run_id"`
	Status           string `json:"status"`
	InputSHA256      string `json:"input_sha256"`
	FinalStateSHA256 string `json:"final_state_sha256"`
	EventSHA256      string `json:"event_sha256"`
}

type Manifest struct {
	Schema         string         `json:"schema"`
	GeneratedAtUTC string         `json:"generated_at_utc"`
	ArtifactDir    string         `json:"artifact_dir"`
	Database       ManifestFile   `json:"database"`
	Runs           []ManifestRun  `json:"runs"`
	Files          []ManifestFile `json:"files"`
}

func Generate(l *ledger.Ledger, dbPath, artifactDir string) (Report, error) {
	evidenceDir := filepath.Join(artifactDir, "evidence")
	if err := os.MkdirAll(filepath.Join(evidenceDir, "runs"), 0o755); err != nil {
		return Report{}, err
	}
	exported, err := exportEvidence(l, evidenceDir)
	if err != nil {
		return Report{}, err
	}
	for _, path := range exported {
		if _, err := l.AttachArtifact(path); err != nil {
			return Report{}, fmt.Errorf("attach artifact %s: %w", path, err)
		}
	}
	if err := l.Checkpoint(); err != nil {
		return Report{}, err
	}

	report, err := Build(l, dbPath, artifactDir)
	if err != nil {
		return Report{}, err
	}
	report.Evidence.DatabaseSHA256, err = fileSHA256(dbPath)
	if err != nil {
		return Report{}, err
	}
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return Report{}, err
	}
	reportJSON = append(reportJSON, '\n')
	reportPath := filepath.Join(artifactDir, "report.json")
	if err := os.WriteFile(reportPath, reportJSON, 0o644); err != nil {
		return Report{}, err
	}
	markdown := renderMarkdown(report)
	reportMD := filepath.Join(artifactDir, "report.md")
	if err := os.WriteFile(reportMD, []byte(markdown), 0o644); err != nil {
		return Report{}, err
	}
	if err := writeManifest(l, dbPath, artifactDir, evidenceDir); err != nil {
		return Report{}, err
	}
	return report, nil
}

func exportEvidence(l *ledger.Ledger, evidenceDir string) ([]string, error) {
	paths := make([]string, 0)
	scenarioPath := filepath.Join(evidenceDir, "scenarios.json")
	if err := os.WriteFile(scenarioPath, experiment.ScenarioSource(), 0o644); err != nil {
		return nil, err
	}
	paths = append(paths, scenarioPath)

	runs, err := l.Runs()
	if err != nil {
		return nil, err
	}
	runSummaries := make([]RunSummary, 0, len(runs))
	for _, run := range runs {
		steps, err := l.Steps(run.RunID)
		if err != nil {
			return nil, err
		}
		summary := RunSummary{
			RunID: run.RunID, Scenario: run.ScenarioName, Role: run.Role,
			Status: run.Status, StepCount: run.StepCount, InputSHA256: run.InputSHA256,
			FinalStateSHA256: run.FinalStateSHA256, ResolutionSHA256: run.ResolutionSHA256,
			EventSHA256: run.EventSHA256,
		}
		jsonlPath := filepath.Join(evidenceDir, "runs", run.RunID+".jsonl")
		file, err := os.Create(jsonlPath)
		if err != nil {
			return nil, err
		}
		encoder := json.NewEncoder(file)
		for _, step := range steps {
			evidence := StepEvidence{
				StepNo: step.StepNo, OpID: step.OpID, Kind: step.Kind,
				Input: step.InputJSON, StateBefore: step.StateBeforeJSON,
				RecordedResult: step.ResultJSON, StateAfter: step.StateAfterJSON,
				StateBeforeSHA256: step.StateBeforeSHA256, ResultSHA256: step.ResultSHA256,
				StateAfterSHA256: step.StateAfterSHA256, EvidenceSHA256: step.EvidenceSHA256,
			}
			summary.Steps = append(summary.Steps, evidence)
			if err := encoder.Encode(evidence); err != nil {
				file.Close()
				return nil, err
			}
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		paths = append(paths, jsonlPath)
		runSummaries = append(runSummaries, summary)
	}
	runsPath := filepath.Join(evidenceDir, "runs.json")
	if err := writeJSON(runsPath, runSummaries); err != nil {
		return nil, err
	}
	paths = append(paths, runsPath)

	checks, err := l.Checks()
	if err != nil {
		return nil, err
	}
	checkSummaries := make([]CheckSummary, 0, len(checks))
	for _, check := range checks {
		checkSummaries = append(checkSummaries, CheckSummary{
			RunID: check.RunID, Name: check.CheckName, Scope: check.Scope,
			Expected: check.Expected, Actual: check.Actual, Passed: check.Passed,
			Detail: check.Detail,
		})
	}
	checksPath := filepath.Join(evidenceDir, "checks.json")
	if err := writeJSON(checksPath, checkSummaries); err != nil {
		return nil, err
	}
	paths = append(paths, checksPath)

	replays, err := l.Replays()
	if err != nil {
		return nil, err
	}
	replaySummaries := make([]ReplaySummary, 0, len(replays))
	for _, replay := range replays {
		replaySummaries = append(replaySummaries, ReplaySummary{
			SourceRunID: replay.SourceRunID, ReplayRunID: replay.ReplayRunID,
			InputMatch: replay.InputMatch, StateMatch: replay.StateMatch,
			ResultMatch: replay.ResultMatch, Passed: replay.Passed, Detail: replay.Detail,
		})
	}
	replaysPath := filepath.Join(evidenceDir, "replays.json")
	if err := writeJSON(replaysPath, replaySummaries); err != nil {
		return nil, err
	}
	paths = append(paths, replaysPath)
	return paths, nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func writeManifest(l *ledger.Ledger, dbPath, artifactDir, evidenceDir string) error {
	manifest := Manifest{
		Schema:         "pathalias-evidence-manifest/v1",
		GeneratedAtUTC: time.Now().UTC().Format(time.RFC3339),
		ArtifactDir:    filepath.ToSlash(artifactDir),
		Files:          make([]ManifestFile, 0),
		Runs:           make([]ManifestRun, 0),
	}
	manifestPath := filepath.Join(evidenceDir, "manifest.json")
	databaseFile, err := manifestFileFor(dbPath, artifactDir)
	if err != nil {
		return err
	}
	manifest.Database = databaseFile
	runs, err := l.Runs()
	if err != nil {
		return err
	}
	for _, run := range runs {
		manifest.Runs = append(manifest.Runs, ManifestRun{
			RunID: run.RunID, Status: run.Status, InputSHA256: run.InputSHA256,
			FinalStateSHA256: run.FinalStateSHA256, EventSHA256: run.EventSHA256,
		})
	}
	err = filepath.WalkDir(artifactDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Clean(path) == filepath.Clean(manifestPath) {
			return nil
		}
		if filepath.Ext(path) == "-wal" || filepath.Ext(path) == "-shm" {
			return nil
		}
		file, err := manifestFileFor(path, artifactDir)
		if err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, file)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(manifest.Files, func(i, j int) bool {
		return manifest.Files[i].Path < manifest.Files[j].Path
	})
	return writeJSON(manifestPath, manifest)
}

func manifestFileFor(path, artifactDir string) (ManifestFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ManifestFile{}, err
	}
	relative, err := filepath.Rel(artifactDir, path)
	if err != nil {
		return ManifestFile{}, err
	}
	return ManifestFile{
		Path: filepath.ToSlash(relative), SHA256: ledger.SHA256(data), Bytes: int64(len(data)),
	}, nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return ledger.SHA256(data), nil
}
