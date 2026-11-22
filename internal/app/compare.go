package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"serrfix/internal/model"
	"serrfix/internal/redact"
	"serrfix/internal/store"
)

type CompareOptions struct {
	SampleID string
	RunA     string
	RunB     string
}

type RunBrief struct {
	RunID          string `json:"run_id"`
	Attempt        int    `json:"attempt"`
	Repetition     int    `json:"repetition"`
	State          string `json:"state"`
	StartedAt      string `json:"started_at"`
	FinishedAt     string `json:"finished_at"`
	SourceOffset   int64  `json:"source_offset"`
	SourceLength   int64  `json:"source_length"`
	BeforeLeaks    int    `json:"before_leaks"`
	AfterLeaks     int    `json:"after_leaks"`
	RedactedSHA256 string `json:"redacted_sha256"`
}

type ByteChange struct {
	OldOffset  int    `json:"old_offset"`
	OldLength  int    `json:"old_length"`
	NewOffset  int    `json:"new_offset"`
	NewLength  int    `json:"new_length"`
	OldSHA256  string `json:"old_sha256"`
	NewSHA256  string `json:"new_sha256"`
	OldPreview string `json:"old_preview"`
	NewPreview string `json:"new_preview"`
}

type CompareReport struct {
	Schema         string     `json:"schema"`
	ComparisonID   string     `json:"comparison_id"`
	ComparedAt     string     `json:"compared_at"`
	SampleID       string     `json:"sample_id"`
	MaterialID     string     `json:"material_id"`
	SourceOffset   int64      `json:"source_offset"`
	SourceLength   int64      `json:"source_length"`
	RunA           RunBrief   `json:"run_a"`
	RunB           RunBrief   `json:"run_b"`
	SameOriginal   bool       `json:"same_original"`
	SameRedacted   bool       `json:"same_redacted"`
	SameSpanLayout bool       `json:"same_span_layout"`
	ByteChange     ByteChange `json:"byte_change"`
	EvidencePath   string     `json:"evidence_path"`
	Note           string     `json:"note"`
}

func (a *App) Compare(opts CompareOptions) (CompareReport, error) {
	if err := a.requireInitialized(); err != nil {
		return CompareReport{}, err
	}
	if opts.SampleID == "" {
		return CompareReport{}, fmt.Errorf("--sample is required")
	}
	sample, err := a.DB.GetSample(opts.SampleID)
	if err != nil {
		return CompareReport{}, err
	}
	runs, err := a.DB.ListRuns(sample.ID)
	if err != nil {
		return CompareReport{}, err
	}
	if opts.RunA == "" || opts.RunB == "" {
		if len(runs) < 2 {
			return CompareReport{}, fmt.Errorf("sample %s needs at least two runs; found %d", sample.ID, len(runs))
		}
		if opts.RunA == "" {
			opts.RunA = runs[len(runs)-2].ID
		}
		if opts.RunB == "" {
			opts.RunB = runs[len(runs)-1].ID
		}
	}
	runA, err := a.DB.GetRun(opts.RunA)
	if err != nil {
		return CompareReport{}, err
	}
	runB, err := a.DB.GetRun(opts.RunB)
	if err != nil {
		return CompareReport{}, err
	}
	if runA.SampleID != sample.ID || runB.SampleID != sample.ID {
		return CompareReport{}, fmt.Errorf("both runs must belong to sample %s", sample.ID)
	}
	evA, redA, err := a.loadRunEvidence(runA)
	if err != nil {
		return CompareReport{}, err
	}
	evB, redB, err := a.loadRunEvidence(runB)
	if err != nil {
		return CompareReport{}, err
	}
	spansA, err := a.DB.ListSpans(runA.ID)
	if err != nil {
		return CompareReport{}, err
	}
	spansB, err := a.DB.ListSpans(runB.ID)
	if err != nil {
		return CompareReport{}, err
	}
	comparedAt := a.now()
	change := diffBytes(redA, redB)
	report := CompareReport{
		Schema: "serrfix.compare/v1", ComparedAt: model.Timestamp(comparedAt),
		SampleID: sample.ID, MaterialID: sample.MaterialID,
		SourceOffset: sample.Offset, SourceLength: sample.Length,
		RunA: briefRun(runA, evA), RunB: briefRun(runB, evB),
		SameOriginal: sample.SHA256 == evA.Run.OriginalSHA256 &&
			sample.SHA256 == evB.Run.OriginalSHA256,
		SameRedacted:   bytes.Equal(redA, redB),
		SameSpanLayout: spanSignature(spansA) == spanSignature(spansB),
		ByteChange:     change,
		Note:           "offsets are zero-based bytes; redacted previews contain no known sensitive values",
	}
	idSum := model.SHA256([]byte(sample.ID + "|" + runA.ID + "|" + runB.ID + "|" +
		model.Timestamp(comparedAt)))
	report.ComparisonID = "cmp-" + idSum[:16]
	path := filepath.Join(a.WS.RunsDir(), sample.ID, report.ComparisonID+".json")
	rel, err := a.WS.Rel(path)
	if err != nil {
		return CompareReport{}, err
	}
	report.EvidencePath = rel
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return CompareReport{}, err
	}
	data = append(data, '\n')
	if err := a.atomicWrite(path, data, 0o444); err != nil {
		return CompareReport{}, err
	}
	if err := a.DB.AddComparison(store.Comparison{
		ID: report.ComparisonID, SampleID: sample.ID, RunA: runA.ID, RunB: runB.ID,
		ComparedAt: model.Timestamp(comparedAt), Equal: report.SameRedacted,
		SummaryJSON: string(data),
	}); err != nil {
		return CompareReport{}, err
	}
	return report, nil
}

func (a *App) loadRunEvidence(run model.Run) (Evidence, []byte, error) {
	ev, err := readEvidence(a.WS.Resolve(run.EvidencePath))
	if err != nil {
		return ev, nil, err
	}
	data, err := os.ReadFile(a.WS.Resolve(run.EvidencePath))
	if err != nil {
		return ev, nil, err
	}
	if got := model.SHA256(data); got != run.EvidenceSHA256 {
		return ev, nil, fmt.Errorf("evidence hash mismatch for %s: got %s want %s",
			run.ID, got, run.EvidenceSHA256)
	}
	redacted, err := base64.StdEncoding.DecodeString(ev.RedactedBase64)
	if err != nil {
		return ev, nil, fmt.Errorf("decode redacted output for %s: %w", run.ID, err)
	}
	if got := model.SHA256(redacted); got != run.RedactedSHA256 {
		return ev, nil, fmt.Errorf("redacted hash mismatch for %s: got %s want %s",
			run.ID, got, run.RedactedSHA256)
	}
	return ev, redacted, nil
}

func briefRun(run model.Run, ev Evidence) RunBrief {
	return RunBrief{
		RunID: run.ID, Attempt: run.Attempt, Repetition: run.Repetition,
		State: run.State, StartedAt: model.Timestamp(run.StartedAt),
		FinishedAt:   model.Timestamp(run.FinishedAt),
		SourceOffset: ev.SampleOffset, SourceLength: ev.SampleLength,
		BeforeLeaks: run.BeforeLeaks, AfterLeaks: run.AfterLeaks,
		RedactedSHA256: run.RedactedSHA256,
	}
}

func spanSignature(spans []model.Span) string {
	var b strings.Builder
	for _, s := range spans {
		fmt.Fprintf(&b, "%s:%d:%d:%s;", s.Kind, s.SourceOffset, s.SourceLength, s.OriginalSHA256)
	}
	return b.String()
}

func diffBytes(a, b []byte) ByteChange {
	if bytes.Equal(a, b) {
		return ByteChange{OldSHA256: model.SHA256(a), NewSHA256: model.SHA256(b)}
	}
	prefix := 0
	for prefix < len(a) && prefix < len(b) && a[prefix] == b[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(a)-prefix && suffix < len(b)-prefix &&
		a[len(a)-1-suffix] == b[len(b)-1-suffix] {
		suffix++
	}
	oldEnd := len(a) - suffix
	newEnd := len(b) - suffix
	return ByteChange{
		OldOffset: prefix, OldLength: oldEnd - prefix,
		NewOffset: prefix, NewLength: newEnd - prefix,
		OldSHA256:  model.SHA256(a[prefix:oldEnd]),
		NewSHA256:  model.SHA256(b[prefix:newEnd]),
		OldPreview: redact.Preview(a[prefix:oldEnd], 240),
		NewPreview: redact.Preview(b[prefix:newEnd], 240),
	}
}
