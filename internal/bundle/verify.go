package bundle

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"auditfix/internal/model"
)

type VerifyOptions struct {
	Rerun       bool
	HarnessPath string
	Timeout     time.Duration
}

type RerunResult struct {
	SampleIndex    int    `json:"sample_index"`
	Name           string `json:"name"`
	Classification string `json:"classification"`
	OK             bool   `json:"ok"`
	Detail         string `json:"detail"`
}

type VerifyReport struct {
	Schema       string        `json:"schema"`
	Bundle       string        `json:"bundle"`
	CaseID       string        `json:"case_id"`
	RunID        string        `json:"run_id"`
	FilesChecked int           `json:"files_checked"`
	RowsChecked  int           `json:"rows_checked"`
	RerunChecked int           `json:"rerun_checked"`
	Warnings     []string      `json:"warnings"`
	Rerun        []RerunResult `json:"rerun"`
}

type loadedBundle struct {
	root        string
	manifest    Manifest
	caseRow     model.Case
	run         model.Run
	events      []model.Event
	corrections []model.Correction
	evidence    []EvidenceRow
	samples     []SampleRow
	attempts    []AttemptRow
}

func Verify(ctx context.Context, bundleDir string, options VerifyOptions) (VerifyReport, error) {
	root, err := filepath.Abs(bundleDir)
	if err != nil {
		return VerifyReport{}, err
	}
	report := VerifyReport{
		Schema: "auditfix.verify.v1", Bundle: root,
		Warnings: []string{}, Rerun: []RerunResult{},
	}
	manifest, err := readManifest(root)
	if err != nil {
		return report, err
	}
	report.CaseID, report.RunID = manifest.CaseID, manifest.RunID
	if err := verifyManifestFiles(root, manifest); err != nil {
		return report, err
	}
	report.FilesChecked = len(manifest.Files) + 1
	loaded, err := loadArtifacts(root, manifest)
	if err != nil {
		return report, err
	}
	if err := verifySnapshot(ctx, root, loaded); err != nil {
		return report, err
	}
	report.RowsChecked = len(loaded.events) + len(loaded.corrections) +
		len(loaded.evidence) + len(loaded.samples) + len(loaded.attempts)
	warnings, err := verifyCrossReferences(loaded)
	if err != nil {
		return report, err
	}
	report.Warnings = warnings
	if options.Rerun {
		rerun, err := rerunSamples(ctx, root, loaded, options)
		if err != nil {
			return report, err
		}
		report.Rerun = rerun
		report.RerunChecked = len(rerun)
		for _, item := range rerun {
			if !item.OK {
				return report, fmt.Errorf("rerun mismatch for sample %q: %s", item.Name, item.Detail)
			}
		}
	}
	return report, nil
}

func readManifest(root string) (Manifest, error) {
	manifestPath := filepath.Join(root, ManifestName)
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	canonical, err := canonicalJSON(manifest, true)
	if err != nil {
		return Manifest{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return Manifest{}, errors.New("manifest is not canonical JSON with the documented field order")
	}
	if manifest.Schema != FormatSchema {
		return Manifest{}, fmt.Errorf("unsupported bundle schema %q", manifest.Schema)
	}
	if manifest.Database.Path != DatabaseName {
		return Manifest{}, fmt.Errorf("unsupported database path %q", manifest.Database.Path)
	}
	if !reflect.DeepEqual(manifest.FieldOrders, expectedFieldOrders()) {
		return Manifest{}, errors.New("manifest field_orders differ from supported schema")
	}
	digestRaw, err := os.ReadFile(filepath.Join(root, DigestName))
	if err != nil {
		return Manifest{}, err
	}
	fields := strings.Fields(string(digestRaw))
	if len(fields) != 2 || fields[1] != ManifestName || len(fields[0]) != 64 {
		return Manifest{}, errors.New("manifest.sha256 must contain '<sha256>  manifest.json'")
	}
	if _, err := hex.DecodeString(fields[0]); err != nil {
		return Manifest{}, errors.New("manifest.sha256 digest is not hex")
	}
	actual := sha256Hex(raw)
	if fields[0] != actual {
		return Manifest{}, fmt.Errorf("manifest digest mismatch: expected %s, got %s", fields[0], actual)
	}
	return manifest, nil
}

func verifyManifestFiles(root string, manifest Manifest) error {
	listed := make(map[string]FileEntry)
	required := map[string]bool{
		"case.json": true, "run.json": true, "events.jsonl": true,
		"corrections.jsonl": true, "evidence.jsonl": true,
		"samples.jsonl": true, "attempts.jsonl": true, "review.md": true,
	}
	lastPath := ""
	for _, entry := range manifest.Files {
		if err := validateBundlePath(entry.Path); err != nil {
			return err
		}
		if lastPath != "" && entry.Path <= lastPath {
			return fmt.Errorf("manifest files are not strictly ordered at %q", entry.Path)
		}
		lastPath = entry.Path
		if _, exists := listed[entry.Path]; exists {
			return fmt.Errorf("duplicate manifest file entry %q", entry.Path)
		}
		listed[entry.Path] = entry
		delete(required, entry.Path)
		sum, size, err := sha256File(filepath.Join(root, filepath.FromSlash(entry.Path)))
		if err != nil {
			return fmt.Errorf("verify %s: %w", entry.Path, err)
		}
		if sum != entry.SHA256 || size != entry.Size {
			return fmt.Errorf("file digest mismatch for %s", entry.Path)
		}
	}
	if err := validateBundlePath(manifest.Database.Path); err != nil {
		return err
	}
	dbSum, dbSize, err := sha256File(filepath.Join(root, filepath.FromSlash(manifest.Database.Path)))
	if err != nil {
		return fmt.Errorf("verify database: %w", err)
	}
	if dbSum != manifest.Database.SHA256 || dbSize != manifest.Database.Size {
		return errors.New("database digest mismatch")
	}
	for path := range required {
		return fmt.Errorf("manifest is missing required file %q", path)
	}
	allowed := map[string]bool{
		ManifestName: true, DigestName: true, manifest.Database.Path: true,
	}
	for path := range listed {
		allowed[path] = true
	}
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("bundle contains symlink: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !allowed[rel] {
			return fmt.Errorf("bundle contains unlisted file %q", rel)
		}
		return nil
	})
}

func validateBundlePath(path string) error {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") {
		return fmt.Errorf("unsafe bundle path %q", path)
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if clean != path || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("unsafe bundle path %q", path)
	}
	return nil
}
