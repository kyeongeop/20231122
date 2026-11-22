package app

import (
	"archive/zip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"serrfix/internal/model"
	"serrfix/internal/store"
	"serrfix/internal/workspace"
)

type ExportOptions struct {
	SampleID string
	OutPath  string
}

type ExportResult struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	SampleID   string `json:"sample_id"`
	Runs       int    `json:"runs"`
	ExportedAt string `json:"exported_at"`
}

type ExportRun struct {
	RunID          string `json:"run_id"`
	Attempt        int    `json:"attempt"`
	Repetition     int    `json:"repetition"`
	State          string `json:"state"`
	StartedAt      string `json:"started_at"`
	FinishedAt     string `json:"finished_at"`
	DurationNS     int64  `json:"duration_ns"`
	BeforeLeaks    int    `json:"before_leaks"`
	AfterLeaks     int    `json:"after_leaks"`
	RedactedSHA256 string `json:"redacted_sha256"`
	EvidencePath   string `json:"evidence_path"`
	EvidenceSHA256 string `json:"evidence_sha256"`
	Error          string `json:"error,omitempty"`
}

type ExportManifest struct {
	Schema       string             `json:"schema"`
	ExportedAt   string             `json:"exported_at"`
	Workspace    string             `json:"workspace"`
	Material     store.Material     `json:"material"`
	SampleID     string             `json:"sample_id"`
	Label        string             `json:"label"`
	Origin       string             `json:"origin"`
	SourceOffset int64              `json:"source_offset"`
	SourceLength int64              `json:"source_length"`
	SourceSHA256 string             `json:"source_sha256"`
	Params       json.RawMessage    `json:"params"`
	Case         json.RawMessage    `json:"case"`
	Runs         []ExportRun        `json:"runs"`
	Comparisons  []store.Comparison `json:"comparisons"`
	Acceptance   struct {
		OriginalCapturedAt string `json:"original_captured_at"`
		OriginalSHA256     string `json:"original_sha256"`
		SampleOffset       int64  `json:"sample_offset"`
		SampleLength       int64  `json:"sample_length"`
		FirstRunStartedAt  string `json:"first_run_started_at,omitempty"`
		LastRunFinishedAt  string `json:"last_run_finished_at,omitempty"`
	} `json:"acceptance"`
}

func (a *App) Export(opts ExportOptions) (ExportResult, error) {
	if err := a.requireInitialized(); err != nil {
		return ExportResult{}, err
	}
	if opts.SampleID == "" {
		return ExportResult{}, fmt.Errorf("--sample is required")
	}
	sample, err := a.DB.GetSample(opts.SampleID)
	if err != nil {
		return ExportResult{}, err
	}
	material, err := a.DB.GetMaterial(sample.MaterialID)
	if err != nil {
		return ExportResult{}, err
	}
	if err := workspace.CheckMaterial(a.WS.Root, material); err != nil {
		return ExportResult{}, err
	}
	runs, err := a.DB.ListRuns(sample.ID)
	if err != nil {
		return ExportResult{}, err
	}
	comparisons, err := a.DB.ListComparisons(sample.ID)
	if err != nil {
		return ExportResult{}, err
	}
	sampleBytes, err := a.readSample(sample, material)
	if err != nil {
		return ExportResult{}, err
	}
	originalBytes, err := os.ReadFile(a.WS.Resolve(material.SnapshotPath))
	if err != nil {
		return ExportResult{}, err
	}
	exportedAt := a.now()
	manifest := ExportManifest{
		Schema: "serrfix.export/v1", ExportedAt: model.Timestamp(exportedAt),
		Workspace: a.WS.Root, Material: material, SampleID: sample.ID,
		Label: sample.Label, Origin: sample.Origin, SourceOffset: sample.Offset,
		SourceLength: sample.Length, SourceSHA256: sample.SHA256,
		Params: json.RawMessage(sample.ParamsJSON), Case: json.RawMessage(sample.CaseJSON),
		Comparisons: comparisons,
	}
	manifest.Acceptance.OriginalCapturedAt = material.CapturedAt
	manifest.Acceptance.OriginalSHA256 = material.SHA256
	manifest.Acceptance.SampleOffset = sample.Offset
	manifest.Acceptance.SampleLength = sample.Length
	for i, run := range runs {
		if i == 0 {
			manifest.Acceptance.FirstRunStartedAt = model.Timestamp(run.StartedAt)
		}
		manifest.Acceptance.LastRunFinishedAt = model.Timestamp(run.FinishedAt)
		manifest.Runs = append(manifest.Runs, ExportRun{
			RunID: run.ID, Attempt: run.Attempt, Repetition: run.Repetition,
			State: run.State, StartedAt: model.Timestamp(run.StartedAt),
			FinishedAt: model.Timestamp(run.FinishedAt), DurationNS: run.DurationNS,
			BeforeLeaks: run.BeforeLeaks, AfterLeaks: run.AfterLeaks,
			RedactedSHA256: run.RedactedSHA256, EvidencePath: run.EvidencePath,
			EvidenceSHA256: run.EvidenceSHA256, Error: run.Error,
		})
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	manifestJSON = append(manifestJSON, '\n')
	summary := a.exportSummary(manifest)

	out := opts.OutPath
	if out == "" {
		name := fmt.Sprintf("%s-%s.zip", sample.ID, exportedAt.Format("20060102T150405.000000000Z"))
		out = filepath.Join(a.WS.ExportsDir(), name)
	} else if !filepath.IsAbs(out) {
		out = filepath.Join(a.WS.ExportsDir(), out)
	}
	if !strings.HasSuffix(strings.ToLower(out), ".zip") {
		out += ".zip"
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return ExportResult{}, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(out), ".export-*.zip")
	if err != nil {
		return ExportResult{}, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	sums := map[string]string{}
	zw := zip.NewWriter(tmp)
	add := func(name string, data []byte, mod time.Time) error {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: mod.UTC()}
		h.SetMode(0o444)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
		sums[name] = model.SHA256(data)
		return nil
	}
	if err := add("manifest.json", manifestJSON, exportedAt); err != nil {
		return ExportResult{}, err
	}
	if err := add("summary.md", []byte(summary), exportedAt); err != nil {
		return ExportResult{}, err
	}
	if err := add("original/material.bin", originalBytes, exportedAt); err != nil {
		return ExportResult{}, err
	}
	if err := add("source/sample.bin", sampleBytes, exportedAt); err != nil {
		return ExportResult{}, err
	}
	for _, run := range runs {
		evidencePath := a.WS.Resolve(run.EvidencePath)
		evidence, err := os.ReadFile(evidencePath)
		if err != nil {
			return ExportResult{}, fmt.Errorf("read evidence %s: %w", run.EvidencePath, err)
		}
		if got := model.SHA256(evidence); got != run.EvidenceSHA256 {
			return ExportResult{}, fmt.Errorf("evidence hash mismatch for %s", run.ID)
		}
		if err := add("runs/"+run.ID+".json", evidence, run.StartedAt); err != nil {
			return ExportResult{}, err
		}
		ev, err := readEvidence(evidencePath)
		if err != nil {
			return ExportResult{}, err
		}
		redacted, err := base64.StdEncoding.DecodeString(ev.RedactedBase64)
		if err != nil {
			return ExportResult{}, err
		}
		if err := add("runs/"+run.ID+".redacted.bin", redacted, run.FinishedAt); err != nil {
			return ExportResult{}, err
		}
		spans, err := a.DB.ListSpans(run.ID)
		if err != nil {
			return ExportResult{}, err
		}
		spanJSON, err := json.MarshalIndent(spans, "", "  ")
		if err != nil {
			return ExportResult{}, err
		}
		spanJSON = append(spanJSON, '\n')
		if err := add("runs/"+run.ID+".spans.json", spanJSON, run.FinishedAt); err != nil {
			return ExportResult{}, err
		}
	}
	for _, cmp := range comparisons {
		if err := add("comparisons/"+cmp.ID+".json", []byte(cmp.SummaryJSON), exportedAt); err != nil {
			return ExportResult{}, err
		}
	}
	names := make([]string, 0, len(sums))
	for name := range sums {
		names = append(names, name)
	}
	sort.Strings(names)
	var checksumList strings.Builder
	for _, name := range names {
		fmt.Fprintf(&checksumList, "%s  %s\n", sums[name], name)
	}
	if err := add("SHA256SUMS", []byte(checksumList.String()), exportedAt); err != nil {
		return ExportResult{}, err
	}
	if err := zw.Close(); err != nil {
		tmp.Close()
		return ExportResult{}, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return ExportResult{}, err
	}
	if err := tmp.Close(); err != nil {
		return ExportResult{}, err
	}
	if err := os.Chmod(tmpName, 0o444); err != nil {
		return ExportResult{}, err
	}
	if err := os.Rename(tmpName, out); err != nil {
		return ExportResult{}, err
	}
	info, err := os.Stat(out)
	if err != nil {
		return ExportResult{}, err
	}
	zipBytes, err := os.ReadFile(out)
	if err != nil {
		return ExportResult{}, err
	}
	return ExportResult{
		Path: out, SHA256: model.SHA256(zipBytes), Size: info.Size(),
		SampleID: sample.ID, Runs: len(runs), ExportedAt: model.Timestamp(exportedAt),
	}, nil
}

func (a *App) exportSummary(m ExportManifest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Sensitive error evidence: %s\n\n", m.SampleID)
	fmt.Fprintf(&b, "- Exported at: `%s`\n", m.ExportedAt)
	fmt.Fprintf(&b, "- Original material: `%s`, %d bytes, SHA-256 `%s`\n",
		m.Material.SnapshotPath, m.Material.Size, m.Material.SHA256)
	fmt.Fprintf(&b, "- Sample byte range: offset `%d`, length `%d`, SHA-256 `%s`\n",
		m.SourceOffset, m.SourceLength, m.SourceSHA256)
	fmt.Fprintf(&b, "- First run started: `%s`\n", m.Acceptance.FirstRunStartedAt)
	fmt.Fprintf(&b, "- Last run finished: `%s`\n\n", m.Acceptance.LastRunFinishedAt)
	b.WriteString("| Run | Attempt | State | Started (UTC) | Finished (UTC) | Leaks before/after |\n")
	b.WriteString("|---|---:|---|---|---|---:|\n")
	for _, run := range m.Runs {
		fmt.Fprintf(&b, "| `%s` | %d | %s | %s | %s | %d/%d |\n",
			run.RunID, run.Attempt, run.State, run.StartedAt, run.FinishedAt,
			run.BeforeLeaks, run.AfterLeaks)
	}
	b.WriteString("\nOffsets are zero-based bytes in the named material. Timestamps are UTC RFC3339Nano.\n")
	return b.String()
}
