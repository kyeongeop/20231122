package exchange

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"idorfix/internal/detect"
	"idorfix/internal/domain"
)

// ToolVersion stamps every export so reviewers know which binary produced it.
const ToolVersion = "idorfix-1.0.0"

// Manifest is the machine-verifiable index inside an export directory.
type Manifest struct {
	SchemaVersion    int            `json:"schema_version"`
	BundleID         string         `json:"bundle_id"`
	ToolVersion      string         `json:"tool_version"`
	RuleVersion      string         `json:"rule_version"`
	ExportedAt       time.Time      `json:"exported_at"`
	SampleID         string         `json:"sample_id"`
	RunID            string         `json:"run_id"`
	InputSHA256      string         `json:"input_sha256"`
	Files            []ManifestFile `json:"files"`
	ManifestChecksum string         `json:"manifest_checksum"`
}

// ManifestFile records one exported artefact and its digest.
type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Export writes a self-contained, reviewable bundle directory:
//
//	bundle.json        full record, fixed field order
//	sample.json        re-runnable sample input
//	verdict.json       engine output
//	review.md          human-readable review sheet
//	manifest.json      checksums for independent verification
func Export(outputDir string, sample *domain.Sample, run *domain.Run, verdict *domain.Verdict) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}
	// Re-normalize so the exported evidence chain carries the adjusted
	// timestamps and authoritative cross-device ordering.
	orderedEvents, _, err := detect.NormalizeClocks(sample)
	if err != nil {
		return "", err
	}
	verdict.EvidenceIDs = make([]string, 0, len(orderedEvents))
	for _, event := range orderedEvents {
		verdict.EvidenceIDs = append(verdict.EvidenceIDs, event.EventID)
	}

	bundle := domain.ExportBundle{
		SchemaVersion: domain.SchemaVersion,
		BundleID:      run.RunID,
		ToolVersion:   ToolVersion,
		RuleVersion:   detect.RuleVersion,
		ExportedAt:    time.Now().UTC(),
		Sample:        *sample,
		Run:           *run,
		Verdict:       *verdict,
		Evidence:      orderedEvents,
	}

	bundleJSON, err := CanonicalJSON(bundle)
	if err != nil {
		return "", err
	}
	sampleJSON, err := CanonicalJSON(sample)
	if err != nil {
		return "", err
	}
	verdictJSON, err := CanonicalJSON(verdict)
	if err != nil {
		return "", err
	}

	files := []struct {
		name string
		data []byte
	}{
		{"bundle.json", bundleJSON},
		{"sample.json", sampleJSON},
		{"verdict.json", verdictJSON},
		{"review.md", renderReview(sample, run, verdict, orderedEvents)},
	}

	manifest := Manifest{
		SchemaVersion: domain.SchemaVersion,
		BundleID:      run.RunID,
		ToolVersion:   ToolVersion,
		RuleVersion:   detect.RuleVersion,
		ExportedAt:    time.Now().UTC(),
		SampleID:      sample.SampleID,
		RunID:         run.RunID,
		InputSHA256:   sample.InputSHA256,
	}
	for _, file := range files {
		path := filepath.Join(outputDir, file.name)
		if err := os.WriteFile(path, file.data, 0o644); err != nil {
			return "", err
		}
		manifest.Files = append(manifest.Files, ManifestFile{
			Path:   file.name,
			SHA256: SHA256Hex(file.data),
			Bytes:  int64(len(file.data)),
		})
	}

	manifestJSON, err := canonicalManifest(manifest)
	if err != nil {
		return "", err
	}
	checksum := SHA256Hex(manifestJSON)
	manifest.ManifestChecksum = checksum
	// Re-serialize so the self-checksum is part of the signed record.
	signedJSON, err := CanonicalJSON(manifest)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "manifest.json"), signedJSON, 0o644); err != nil {
		return "", err
	}
	return filepath.Join(outputDir, "bundle.json"), nil
}

func canonicalManifest(manifest Manifest) ([]byte, error) {
	manifest.ManifestChecksum = ""
	return CanonicalJSON(manifest)
}

// VerifyBundle re-checks every checksum of an exported directory and enforces
// the field-order contract. It is safe for a colleague to run on any machine.
func VerifyBundle(dir string) (*domain.ExportBundle, error) {
	manifestRaw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	storedChecksum := manifest.ManifestChecksum
	manifest.ManifestChecksum = ""
	recomputedRaw, err := CanonicalJSON(manifest)
	if err != nil {
		return nil, err
	}
	if SHA256Hex(recomputedRaw) != storedChecksum {
		return nil, fmt.Errorf("manifest self-checksum mismatch")
	}

	for _, file := range manifest.Files {
		data, err := os.ReadFile(filepath.Join(dir, file.Path))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", file.Path, err)
		}
		if SHA256Hex(data) != file.SHA256 {
			return nil, fmt.Errorf("checksum mismatch for %s", file.Path)
		}
	}

	bundleRaw, err := os.ReadFile(filepath.Join(dir, "bundle.json"))
	if err != nil {
		return nil, err
	}
	if err := AssertFieldOrder(bundleRaw, domain.ExportBundle{}); err != nil {
		return nil, fmt.Errorf("field-order contract: %w", err)
	}
	var bundle domain.ExportBundle
	if err := json.Unmarshal(bundleRaw, &bundle); err != nil {
		return nil, err
	}
	if bundle.Sample.InputSHA256 != manifest.InputSHA256 {
		return nil, fmt.Errorf("input hash drift between manifest and sample")
	}
	// Recompute the content hash over the sample with its hash field blanked;
	// this proves the sample bytes themselves match the recorded digest.
	embedded := bundle.Sample
	embedded.InputSHA256 = ""
	contentCanonical, err := CanonicalJSON(embedded)
	if err != nil {
		return nil, err
	}
	if SHA256Hex(contentCanonical) != bundle.Sample.InputSHA256 {
		return nil, fmt.Errorf("sample content hash does not match recorded input_sha256")
	}
	return &bundle, nil
}
