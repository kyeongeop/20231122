package review

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"example.com/replay-review/internal/export"
	"example.com/replay-review/internal/model"
)

// LoadJSONL reads one JSON object per line into typed rows. It preserves the
// on-disk order exactly, which is required for field/order round-trip checks.
func LoadJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rows []T
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		var row T
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, line, err)
		}
		rows = append(rows, row)
	}
	return rows, scanner.Err()
}

// VerifyBundle re-hashes every file listed in the manifest and checks line
// counts. A colleague can run this without the original database.
func VerifyBundle(dir string) (export.Manifest, error) {
	manifestRaw, err := os.ReadFile(filepath.Join(dir, export.FileManifest))
	if err != nil {
		return export.Manifest{}, err
	}
	var manifest export.Manifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return export.Manifest{}, fmt.Errorf("manifest parse: %w", err)
	}
	for _, fc := range manifest.Files {
		path := filepath.Join(dir, fc.Name)
		raw, err := os.ReadFile(path)
		if err != nil {
			return manifest, fmt.Errorf("%s: %w", fc.Name, err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != fc.SHA256 {
			return manifest, fmt.Errorf(
				"%s checksum mismatch: manifest=%s actual=%s",
				fc.Name, fc.SHA256, got)
		}
		lines := 0
		for _, b := range raw {
			if b == '\n' {
				lines++
			}
		}
		if lines != fc.Lines {
			return manifest, fmt.Errorf(
				"%s line count mismatch: manifest=%d actual=%d",
				fc.Name, fc.Lines, lines)
		}
	}
	return manifest, nil
}

// ReplayRow is the decision projection used for before/after comparison.
type ReplayRow struct {
	Sequence     int64  `json:"sequence"`
	DeviceID     string `json:"device_id"`
	Code         string `json:"code"`
	UserID       string `json:"user_id"`
	Outcome      string `json:"outcome"`
	Severity     string `json:"severity"`
	Reason       string `json:"reason"`
	MatchedIssue int64  `json:"matched_issue_sequence"`
	AgeMs        int64  `json:"age_ms"`
	WindowMs     int64  `json:"window_ms"`
}

// CompareDecisions verifies two runs produced identical verdicts in identical
// order. It returns the first mismatch found, or nil when runs are equivalent.
func CompareDecisions(a, b []ReplayRow) error {
	if len(a) != len(b) {
		return fmt.Errorf("decision count differs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			return fmt.Errorf("decision %d differs:\n  before=%+v\n  after =%+v",
				i, a[i], b[i])
		}
	}
	return nil
}

// CompareGaps verifies missing-fragment evidence in order.
func CompareGaps(a, b []model.Gap) error {
	if len(a) != len(b) {
		return fmt.Errorf("gap count differs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			return fmt.Errorf("gap %d differs:\n  before=%+v\n  after =%+v",
				i, a[i], b[i])
		}
	}
	return nil
}
