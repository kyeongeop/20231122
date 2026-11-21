package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kyeongeop/20231122/internal/store"
)

// Report summarizes one full audit pass.
type Report struct {
	GeneratedAt string       `json:"generated_at"`
	DBPath      string       `json:"db_path"`
	Cases       []CaseReport `json:"cases"`
	LogPath     string       `json:"log_path"`
}

// CaseReport ties one scenario to its on-disk evidence.
type CaseReport struct {
	CaseID      string            `json:"case_id"`
	Title       string            `json:"title"`
	Anchor      string            `json:"anchor"`
	InputPath   string            `json:"input_path"`
	InputSize   int               `json:"input_size"`
	SHA256      string            `json:"sha256"`
	RawOffset   uint32            `json:"raw_offset"`
	AnchorHits  map[string]uint32 `json:"anchor_hits"`
	VulnErr     string            `json:"vulnerable_error"`
	VulnWrapped string            `json:"vulnerable_wrapped"`
	HardenedErr string            `json:"hardened_error"`
	Permission  string            `json:"permission"`
	EventTimes  []string          `json:"event_times"`
}

type logger struct {
	f *os.File
}

func (l *logger) log(v map[string]any) error {
	v["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	line, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = l.f.Write(append(line, '\n'))
	return err
}

// Run executes every scenario under both parser modes and persists evidence.
func Run(baseDir string, st *store.Store) (*Report, error) {
	corpusDir := filepath.Join(baseDir, "evidence", "corpus")
	reportDir := filepath.Join(baseDir, "evidence", "reports")
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return nil, err
	}
	logPath := filepath.Join(reportDir, "audit.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}
	defer logFile.Close()
	lg := &logger{f: logFile}

	report := &Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		DBPath:      filepath.Join(baseDir, "evidence", "audit.db"),
		LogPath:     logPath,
	}

	for _, tc := range BuildCases() {
		cr, err := runCase(tc, corpusDir, st, lg)
		if err != nil {
			return nil, fmt.Errorf("case %s: %w", tc.ID, err)
		}
		report.Cases = append(report.Cases, cr)
	}
	return report, nil
}
