package artifact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"corpusd/internal/model"
)

func LoadExport(dir string) (Export, error) {
	return loadExport(dir)
}

func VerifyExport(dir string) (VerifyReport, error) {
	var report VerifyReport
	ex, err := loadExport(dir)
	if err != nil {
		return report, err
	}
	for _, c := range ex.Comparisons {
		switch c.Phase {
		case "resume_restore":
			report.RestoreCompared = true
		case "final_recompute":
			report.FinalCompared = c.Match
		}
	}
	report = VerifyReport{
		RunID: ex.Manifest.RunID, Status: ex.Manifest.Status,
		Records: len(ex.Records), Inputs: len(ex.Manifest.Inputs),
		Checkpoints: len(ex.Checkpoints), Events: len(ex.Events),
		Comparisons: len(ex.Comparisons), RestoreCompared: report.RestoreCompared,
		FinalCompared: report.FinalCompared, ResultDigest: ex.Manifest.ResultDigest,
		FilesVerified: len(ex.Manifest.Files) + 2,
	}
	return report, nil
}

func loadExport(dir string) (Export, error) {
	var ex Export
	ex.Dir = dir
	manifestData, err := os.ReadFile(filepath.Join(dir, manifestFile))
	if err != nil {
		return ex, fmt.Errorf("read manifest: %w", err)
	}
	if err := CheckOrder(manifestData, ManifestFields); err != nil {
		return ex, fmt.Errorf("manifest field order: %w", err)
	}
	if err := json.Unmarshal(manifestData, &ex.Manifest); err != nil {
		return ex, fmt.Errorf("decode manifest: %w", err)
	}
	m := &ex.Manifest
	if m.Schema != model.ExportSchema || m.RecordType != "corpus_export" || m.Generator != Generator {
		return ex, fmt.Errorf("unexpected export identity: %s/%s/%s",
			m.Schema, m.RecordType, m.Generator)
	}
	if err := checkFieldContract(m); err != nil {
		return ex, err
	}
	if err := checkManifestNestedOrder(manifestData); err != nil {
		return ex, err
	}
	if err := checkManifestFiles(dir, m); err != nil {
		return ex, err
	}
	recordData, err := readLines(filepath.Join(dir, recordsFile))
	if err != nil {
		return ex, err
	}
	if len(recordData) != m.RecordCount {
		return ex, fmt.Errorf("record count: manifest=%d file=%d", m.RecordCount, len(recordData))
	}
	for i, line := range recordData {
		if err := CheckOrder(line, model.RecordFields); err != nil {
			return ex, fmt.Errorf("record %d field order: %w", i+1, err)
		}
		var rec model.Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return ex, fmt.Errorf("decode record %d: %w", i+1, err)
		}
		if err := checkNestedOrder(line); err != nil {
			return ex, fmt.Errorf("record %d: %w", i+1, err)
		}
		again, err := model.MarshalRecord(rec)
		if err != nil {
			return ex, fmt.Errorf("re-encode record %d: %w", i+1, err)
		}
		if !bytes.Equal(again, line) {
			return ex, fmt.Errorf("record %d changed after reload", i+1)
		}
		ex.Records = append(ex.Records, rec)
	}
	if m.ResultDigest != model.ResultDigest(ex.Records) {
		return ex, fmt.Errorf("result digest mismatch: manifest=%s computed=%s",
			m.ResultDigest, model.ResultDigest(ex.Records))
	}
	if m.RecordCount != len(ex.Records) || m.InputCount != len(m.Inputs) {
		return ex, fmt.Errorf("manifest count/input length mismatch")
	}
	if err := verifyRecords(dir, m, ex.Records); err != nil {
		return ex, err
	}
	if err := decodeCheckpoints(dir, &ex); err != nil {
		return ex, err
	}
	if err := decodeEvents(dir, &ex); err != nil {
		return ex, err
	}
	if err := decodeComparisons(dir, &ex); err != nil {
		return ex, err
	}
	if err := verifyFlow(m, ex.Records, ex.Checkpoints, ex.Events, ex.Comparisons); err != nil {
		return ex, err
	}
	if err := checkSums(dir); err != nil {
		return ex, err
	}
	return ex, nil
}

func checkFieldContract(m *Manifest) error {
	contracts := []struct {
		name string
		got  []string
		want []string
	}{
		{"record_fields", m.RecordFields, model.RecordFields},
		{"observation_fields", m.ObservationFields, model.ObservationFields},
		{"analysis_fields", m.AnalysisFields, model.AnalysisFields},
		{"evidence_fields", m.EvidenceFields, model.EvidenceFields},
	}
	for _, c := range contracts {
		if len(c.got) != len(c.want) {
			return fmt.Errorf("%s length mismatch", c.name)
		}
		for i := range c.want {
			if c.got[i] != c.want[i] {
				return fmt.Errorf("%s[%d]: want %q got %q", c.name, i, c.want[i], c.got[i])
			}
		}
	}
	return nil
}

func checkNestedOrder(line []byte) error {
	var shape struct {
		Observations []json.RawMessage `json:"observations"`
		Analysis     json.RawMessage   `json:"analysis"`
		Evidence     json.RawMessage   `json:"evidence"`
	}
	if err := json.Unmarshal(line, &shape); err != nil {
		return err
	}
	if len(shape.Observations) != 2 {
		return fmt.Errorf("expected two device observations, got %d", len(shape.Observations))
	}
	for i, obs := range shape.Observations {
		if err := CheckOrder(obs, model.ObservationFields); err != nil {
			return fmt.Errorf("observation %d order: %w", i, err)
		}
	}
	if err := CheckOrder(shape.Analysis, model.AnalysisFields); err != nil {
		return fmt.Errorf("analysis order: %w", err)
	}
	if err := CheckOrder(shape.Evidence, model.EvidenceFields); err != nil {
		return fmt.Errorf("evidence order: %w", err)
	}
	return nil
}

func checkManifestNestedOrder(data []byte) error {
	var shape struct {
		Files  []json.RawMessage `json:"files"`
		Inputs []json.RawMessage `json:"inputs"`
	}
	if err := json.Unmarshal(data, &shape); err != nil {
		return err
	}
	for i, f := range shape.Files {
		if err := CheckOrder(f, FileEntryFields); err != nil {
			return fmt.Errorf("manifest files[%d]: %w", i, err)
		}
	}
	for i, in := range shape.Inputs {
		if err := CheckOrder(in, InputFileFields); err != nil {
			return fmt.Errorf("manifest inputs[%d]: %w", i, err)
		}
	}
	return nil
}

func checkManifestFiles(dir string, m *Manifest) error {
	seen := make(map[string]bool)
	for i, f := range m.Files {
		if i > 0 && m.Files[i-1].Name > f.Name {
			return fmt.Errorf("manifest files are not in stable name order")
		}
		rel, err := safeRel(f.Name)
		if err != nil {
			return err
		}
		if seen[rel] {
			return fmt.Errorf("duplicate manifest file %q", rel)
		}
		seen[rel] = true
		sha, size, err := hashFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return fmt.Errorf("verify file %s: %w", rel, err)
		}
		if sha != f.SHA256 || size != f.Bytes {
			return fmt.Errorf("file %s mismatch: manifest=%s/%d got=%s/%d",
				rel, f.SHA256, f.Bytes, sha, size)
		}
	}
	for _, required := range []string{recordsFile, checkpointsFile, eventsFile, comparisonsFile, readmeFile} {
		if !seen[required] {
			return fmt.Errorf("manifest missing required file %s", required)
		}
	}
	recordHash, _, err := hashFile(filepath.Join(dir, recordsFile))
	if err != nil {
		return err
	}
	if recordHash != m.RecordsSHA256 {
		return fmt.Errorf("records sha256 mismatch: manifest=%s computed=%s",
			m.RecordsSHA256, recordHash)
	}
	return nil
}

func readLines(path string) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = []byte(strings.TrimSuffix(string(data), "\n"))
	if len(data) == 0 {
		return nil, nil
	}
	parts := strings.Split(string(data), "\n")
	out := make([][]byte, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		out = append(out, []byte(part))
	}
	return out, nil
}

func checkSums(dir string) error {
	data, err := os.ReadFile(filepath.Join(dir, sumsFile))
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	foundManifest := false
	seen := make(map[string]bool)
	for _, line := range lines {
		fields := strings.SplitN(line, "  ", 2)
		if len(fields) != 2 || len(fields[0]) != 64 {
			return fmt.Errorf("bad SHA256SUMS line %q", line)
		}
		rel, err := safeRel(fields[1])
		if err != nil {
			return err
		}
		sha, _, err := hashFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		if sha != fields[0] {
			return fmt.Errorf("SHA256SUMS mismatch for %s", rel)
		}
		if rel == manifestFile {
			foundManifest = true
		}
		seen[rel] = true
	}
	if !foundManifest {
		return fmt.Errorf("SHA256SUMS does not cover manifest.json")
	}
	manifestData, err := os.ReadFile(filepath.Join(dir, manifestFile))
	if err != nil {
		return err
	}
	var m Manifest
	if err := json.Unmarshal(manifestData, &m); err != nil {
		return err
	}
	for _, f := range m.Files {
		if !seen[f.Name] {
			return fmt.Errorf("SHA256SUMS missing %s", f.Name)
		}
	}
	return nil
}
