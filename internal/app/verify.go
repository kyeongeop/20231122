package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"serrfix/internal/model"
	"serrfix/internal/store"
	"serrfix/internal/workspace"
)

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type OffsetRange struct {
	SampleID     string `json:"sample_id"`
	MaterialID   string `json:"material_id"`
	SourceOffset int64  `json:"source_offset"`
	SourceLength int64  `json:"source_length"`
	SourceSHA256 string `json:"source_sha256"`
}

type VerifyReport struct {
	Schema        string        `json:"schema"`
	AcceptedAt    string        `json:"accepted_at"`
	OK            bool          `json:"ok"`
	Workspace     string        `json:"workspace"`
	MaterialCount int           `json:"material_count"`
	SampleCount   int           `json:"sample_count"`
	RunCount      int           `json:"run_count"`
	FirstRunAt    string        `json:"first_run_started_at,omitempty"`
	LastRunAt     string        `json:"last_run_finished_at,omitempty"`
	Checks        []Check       `json:"checks"`
	OffsetRanges  []OffsetRange `json:"offset_ranges"`
}

func (a *App) Verify() (VerifyReport, error) {
	if err := a.requireInitialized(); err != nil {
		return VerifyReport{}, err
	}
	report := VerifyReport{
		Schema: "serrfix.verify/v1", Workspace: a.WS.Root,
		AcceptedAt: model.Timestamp(a.now()),
	}
	add := func(name string, ok bool, detail string) {
		report.Checks = append(report.Checks, Check{Name: name, OK: ok, Detail: detail})
	}

	materials, err := a.DB.ListMaterials()
	if err != nil {
		return report, err
	}
	report.MaterialCount = len(materials)
	materialByID := map[string]store.Material{}
	for _, material := range materials {
		materialByID[material.ID] = material
		err := workspace.CheckMaterial(a.WS.Root, material)
		add("material:"+material.ID, err == nil,
			detail(err, fmt.Sprintf("%s size=%d sha256=%s captured_at=%s",
				material.SnapshotPath, material.Size, material.SHA256, material.CapturedAt)))
	}

	samples, err := a.DB.ListSamples()
	if err != nil {
		return report, err
	}
	report.SampleCount = len(samples)
	for _, sample := range samples {
		material, ok := materialByID[sample.MaterialID]
		if !ok {
			add("sample:"+sample.ID, false, "referenced material does not exist")
			continue
		}
		data, readErr := a.readSample(sample, material)
		ok = readErr == nil
		add("sample_source:"+sample.ID, ok, detail(readErr, fmt.Sprintf(
			"material=%s offset=%d length=%d sha256=%s",
			material.ID, sample.Offset, sample.Length, sample.SHA256)))
		report.OffsetRanges = append(report.OffsetRanges, OffsetRange{
			SampleID: sample.ID, MaterialID: material.ID,
			SourceOffset: sample.Offset, SourceLength: sample.Length,
			SourceSHA256: sample.SHA256,
		})
		if readErr == nil {
			var c model.Case
			if err := json.Unmarshal([]byte(sample.CaseJSON), &c); err != nil {
				add("sample_case:"+sample.ID, false, err.Error())
			} else {
				match := c.Source.Offset == sample.Offset &&
					c.Source.Length == sample.Length &&
					c.Source.SHA256 == sample.SHA256 &&
					c.Source.MaterialID == sample.MaterialID
				add("sample_case:"+sample.ID, match, fmt.Sprintf(
					"case source offset=%d length=%d sha256=%s",
					c.Source.Offset, c.Source.Length, c.Source.SHA256))
			}
			_ = data
		}
	}

	runs, err := a.DB.ListRuns("")
	if err != nil {
		return report, err
	}
	report.RunCount = len(runs)
	if len(runs) > 0 {
		report.FirstRunAt = model.Timestamp(runs[0].StartedAt)
		report.LastRunAt = model.Timestamp(runs[len(runs)-1].FinishedAt)
	}
	sampleByID := map[string]model.Sample{}
	for _, sample := range samples {
		sampleByID[sample.ID] = sample
	}
	for _, run := range runs {
		a.checkRun(&report, run, sampleByID[run.SampleID], materialByID, add)
	}

	comparisons, err := a.DB.ListComparisons("")
	if err != nil {
		return report, err
	}
	for _, cmp := range comparisons {
		ok := json.Valid([]byte(cmp.SummaryJSON))
		_, timeErr := model.ParseTimestamp(cmp.ComparedAt)
		_, runAErr := a.DB.GetRun(cmp.RunA)
		_, runBErr := a.DB.GetRun(cmp.RunB)
		ok = ok && timeErr == nil && runAErr == nil && runBErr == nil
		add("comparison:"+cmp.ID, ok, fmt.Sprintf(
			"sample=%s run_a=%s run_b=%s compared_at=%s",
			cmp.SampleID, cmp.RunA, cmp.RunB, cmp.ComparedAt))
	}
	events, err := a.DB.ListEvents(1000)
	if err != nil {
		return report, err
	}
	eventsOK := true
	for _, event := range events {
		if _, err := model.ParseTimestamp(event.At); err != nil {
			eventsOK = false
			break
		}
	}
	add("event_timestamps", eventsOK, fmt.Sprintf("%d event(s) checked as UTC RFC3339Nano", len(events)))
	report.OK = true
	for _, check := range report.Checks {
		if !check.OK {
			report.OK = false
			break
		}
	}
	return report, nil
}

func (a *App) checkRun(report *VerifyReport, run model.Run, sample model.Sample,
	materials map[string]store.Material, add func(string, bool, string)) {
	prefix := "run:" + run.ID + ":"
	timeOK := !run.FinishedAt.Before(run.StartedAt) && run.DurationNS >= 0 &&
		run.StartedAt.Location() == time.UTC && run.FinishedAt.Location() == time.UTC
	add(prefix+"time", timeOK, fmt.Sprintf("started=%s finished=%s duration_ns=%d",
		model.Timestamp(run.StartedAt), model.Timestamp(run.FinishedAt), run.DurationNS))
	material, materialOK := materials[sample.MaterialID]
	add(prefix+"sample_ref", sample.ID != "" && materialOK,
		fmt.Sprintf("sample=%s material=%s", run.SampleID, sample.MaterialID))
	if !materialOK {
		return
	}
	evidencePath := a.WS.Resolve(run.EvidencePath)
	raw, err := os.ReadFile(evidencePath)
	hashOK := err == nil && model.SHA256(raw) == run.EvidenceSHA256
	add(prefix+"evidence_hash", hashOK, detail(err, fmt.Sprintf("path=%s sha256=%s",
		run.EvidencePath, run.EvidenceSHA256)))
	if err != nil {
		return
	}
	ev, err := readEvidence(evidencePath)
	if err != nil {
		add(prefix+"evidence_json", false, err.Error())
		return
	}
	add(prefix+"evidence_json", true, "decoded serrfix.evidence/v1")
	evTimeOK := ev.Run.StartedAt == model.Timestamp(run.StartedAt) &&
		ev.Run.FinishedAt == model.Timestamp(run.FinishedAt)
	add(prefix+"evidence_time", evTimeOK, fmt.Sprintf("evidence started=%s finished=%s",
		ev.Run.StartedAt, ev.Run.FinishedAt))
	offsetOK := ev.SampleOffset == sample.Offset && ev.SampleLength == sample.Length &&
		ev.SampleSHA256 == sample.SHA256 && ev.Run.Source.Offset == sample.Offset &&
		ev.Run.Source.Length == sample.Length && ev.Run.Source.SHA256 == sample.SHA256
	add(prefix+"evidence_offset", offsetOK, fmt.Sprintf(
		"offset=%d length=%d sha256=%s", ev.SampleOffset, ev.SampleLength, ev.SampleSHA256))
	materialOK = ev.Material.ID == material.ID && ev.Material.SHA256 == material.SHA256 &&
		ev.MaterialPath == material.SnapshotPath
	add(prefix+"evidence_material", materialOK, fmt.Sprintf(
		"material=%s snapshot=%s", ev.Material.ID, ev.MaterialPath))
	redacted, err := base64.StdEncoding.DecodeString(ev.RedactedBase64)
	if err != nil {
		add(prefix+"redacted_decode", false, err.Error())
		return
	}
	redactedOK := model.SHA256(redacted) == run.RedactedSHA256
	add(prefix+"redacted_hash", redactedOK, fmt.Sprintf("sha256=%s size=%d",
		run.RedactedSHA256, len(redacted)))
	add(prefix+"evidence_redacted_hash", ev.Run.RedactedSHA256 == run.RedactedSHA256,
		fmt.Sprintf("evidence sha256=%s", ev.Run.RedactedSHA256))
	if run.State == "passed" {
		add(prefix+"zero_leaks", run.AfterLeaks == 0,
			fmt.Sprintf("before=%d after=%d", run.BeforeLeaks, run.AfterLeaks))
	}
	spans, err := a.DB.ListSpans(run.ID)
	if err != nil {
		add(prefix+"spans", false, err.Error())
		return
	}
	spansOK := true
	sampleData, sampleErr := a.readSample(sample, material)
	for _, span := range spans {
		if span.SourceOffset < 0 || span.SourceLength <= 0 ||
			int64(span.SourceOffset+span.SourceLength) > sample.Length ||
			span.ReplacementOffset < 0 ||
			span.ReplacementOffset+len(span.Replacement) > len(redacted) {
			spansOK = false
			break
		}
		if sampleErr == nil {
			sourceBytes := sampleData[span.SourceOffset : span.SourceOffset+span.SourceLength]
			if model.SHA256(sourceBytes) != span.OriginalSHA256 {
				spansOK = false
				break
			}
		}
	}
	add(prefix+"spans", spansOK, fmt.Sprintf("%d span(s), source and replacement bounds checked", len(spans)))
	add(prefix+"evidence_spans", spanSignature(spans) == spanSignature(ev.Run.Spans),
		fmt.Sprintf("db=%d evidence=%d", len(spans), len(ev.Run.Spans)))
}

func detail(err error, okDetail string) string {
	if err != nil {
		return err.Error()
	}
	return okDetail
}
