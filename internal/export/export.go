package export

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// File names inside an export bundle. They are part of the review contract.
const (
	FileManifest    = "manifest.json"
	FileEvents      = "events.jsonl"
	FileDecisions   = "decisions.jsonl"
	FileGaps        = "gaps.jsonl"
	FileCheckpoints = "checkpoints.jsonl"
)

// Manifest is the entry point a colleague opens first. Every field has a
// stable position; append-only changes only.
type Manifest struct {
	SchemaVersion   string          `json:"schema_version"`
	Tool            string          `json:"tool"`
	CreatedAtMs     int64           `json:"created_at_ms"`
	EventCount      int             `json:"event_count"`
	DecisionCount   int             `json:"decision_count"`
	GapCount        int             `json:"gap_count"`
	CheckpointCount int             `json:"checkpoint_count"`
	ReplayCount     int             `json:"replay_count"`
	Degraded        bool            `json:"degraded"`
	Files           []FileChecksum  `json:"files"`
	Config          json.RawMessage `json:"config"`
}

// FileChecksum binds a bundle file to its SHA-256 content hash.
type FileChecksum struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Lines  int    `json:"lines"`
}

// writeJSONL writes one compact JSON object per line in the given order.
func writeJSONL(path string, rows []any) (lines int, err error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, row := range rows {
		if err := enc.Encode(row); err != nil {
			return lines, err
		}
		lines++
	}
	return lines, nil
}

// hashFile returns the checksum record for an exported file.
func hashFile(name string) (FileChecksum, error) {
	raw, err := os.ReadFile(name)
	if err != nil {
		return FileChecksum{}, err
	}
	sum := sha256.Sum256(raw)
	lines := 0
	for _, b := range raw {
		if b == '\n' {
			lines++
		}
	}
	return FileChecksum{
		Name:   filepath.Base(name),
		SHA256: hex.EncodeToString(sum[:]),
		Bytes:  int64(len(raw)),
		Lines:  lines,
	}, nil
}

// Bundle is the in-memory view of everything a reviewer needs.
type Bundle struct {
	Config      json.RawMessage
	Events      []any
	Decisions   []any
	Gaps        []any
	Checkpoints []any
	ReplayCount int
	Degraded    bool
	CreatedAtMs int64
}

// Write renders a self-contained review bundle into outDir.
func Write(outDir string, b Bundle) (Manifest, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return Manifest{}, err
	}
	paths := map[string]string{
		FileEvents:      filepath.Join(outDir, FileEvents),
		FileDecisions:   filepath.Join(outDir, FileDecisions),
		FileGaps:        filepath.Join(outDir, FileGaps),
		FileCheckpoints: filepath.Join(outDir, FileCheckpoints),
	}
	type fileRows struct {
		rows  []any
		lines int
	}
	written := map[string]fileRows{}
	for name, path := range paths {
		var rows []any
		switch name {
		case FileEvents:
			rows = b.Events
		case FileDecisions:
			rows = b.Decisions
		case FileGaps:
			rows = b.Gaps
		case FileCheckpoints:
			rows = b.Checkpoints
		}
		lines, err := writeJSONL(path, rows)
		if err != nil {
			return Manifest{}, fmt.Errorf("write %s: %w", name, err)
		}
		written[name] = fileRows{rows: rows, lines: lines}
	}

	// Checksum files in a fixed order so the manifest itself is deterministic.
	ordered := []string{FileEvents, FileDecisions, FileGaps, FileCheckpoints}
	checksums := make([]FileChecksum, 0, len(ordered))
	for _, name := range ordered {
		fc, err := hashFile(paths[name])
		if err != nil {
			return Manifest{}, err
		}
		checksums = append(checksums, fc)
	}

	manifest := Manifest{
		SchemaVersion:   "1",
		Tool:            "replayctl",
		CreatedAtMs:     b.CreatedAtMs,
		EventCount:      written[FileEvents].lines,
		DecisionCount:   written[FileDecisions].lines,
		GapCount:        written[FileGaps].lines,
		CheckpointCount: written[FileCheckpoints].lines,
		ReplayCount:     b.ReplayCount,
		Degraded:        b.Degraded,
		Files:           checksums,
		Config:          b.Config,
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	if err := os.WriteFile(filepath.Join(outDir, FileManifest),
		append(raw, '\n'), 0o644); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}
