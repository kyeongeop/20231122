package app

import (
	"fmt"

	"serrfix/internal/model"
	"serrfix/internal/store"
)

type SampleStatus struct {
	SampleID       string `json:"sample_id"`
	Ordinal        int    `json:"ordinal"`
	Label          string `json:"label"`
	Origin         string `json:"origin"`
	MaterialID     string `json:"material_id"`
	SourceOffset   int64  `json:"source_offset"`
	SourceLength   int64  `json:"source_length"`
	SourceSHA256   string `json:"source_sha256"`
	RunCount       int    `json:"run_count"`
	LatestRunID    string `json:"latest_run_id,omitempty"`
	LatestState    string `json:"latest_state,omitempty"`
	FirstStartedAt string `json:"first_started_at,omitempty"`
	LastFinishedAt string `json:"last_finished_at,omitempty"`
	BeforeLeaks    int    `json:"before_leaks,omitempty"`
	AfterLeaks     int    `json:"after_leaks,omitempty"`
}

type TimelineEvent struct {
	At     string `json:"at"`
	Kind   string `json:"kind"`
	Sample string `json:"sample_id,omitempty"`
	Run    string `json:"run_id,omitempty"`
	Detail string `json:"detail_json"`
}

type TimelineReport struct {
	Schema      string          `json:"schema"`
	GeneratedAt string          `json:"generated_at"`
	Workspace   string          `json:"workspace"`
	Material    store.Material  `json:"original_material"`
	Samples     []SampleStatus  `json:"samples"`
	Events      []TimelineEvent `json:"events"`
	Totals      struct {
		Samples     int `json:"samples"`
		Runs        int `json:"runs"`
		Passed      int `json:"passed"`
		Failed      int `json:"failed"`
		Interrupted int `json:"interrupted"`
		Comparisons int `json:"comparisons"`
	} `json:"totals"`
}

func (a *App) Report() (TimelineReport, error) {
	if err := a.requireInitialized(); err != nil {
		return TimelineReport{}, err
	}
	materialID, err := a.DB.GetMeta("original_material_id")
	if err != nil {
		return TimelineReport{}, err
	}
	material, err := a.DB.GetMaterial(materialID)
	if err != nil {
		return TimelineReport{}, err
	}
	samples, err := a.DB.ListSamples()
	if err != nil {
		return TimelineReport{}, err
	}
	report := TimelineReport{
		Schema: "serrfix.timeline/v1", GeneratedAt: model.Timestamp(a.now()),
		Workspace: a.WS.Root, Material: material,
	}
	for _, sample := range samples {
		status := SampleStatus{
			SampleID: sample.ID, Ordinal: sample.Ordinal, Label: sample.Label,
			Origin: sample.Origin, MaterialID: sample.MaterialID,
			SourceOffset: sample.Offset, SourceLength: sample.Length,
			SourceSHA256: sample.SHA256,
		}
		runs, err := a.DB.ListRuns(sample.ID)
		if err != nil {
			return report, err
		}
		status.RunCount = len(runs)
		if len(runs) > 0 {
			status.FirstStartedAt = model.Timestamp(runs[0].StartedAt)
			status.LastFinishedAt = model.Timestamp(runs[len(runs)-1].FinishedAt)
			last := runs[len(runs)-1]
			status.LatestRunID = last.ID
			status.LatestState = last.State
			status.BeforeLeaks = last.BeforeLeaks
			status.AfterLeaks = last.AfterLeaks
		}
		for _, run := range runs {
			report.Totals.Runs++
			switch run.State {
			case "passed":
				report.Totals.Passed++
			case "failed":
				report.Totals.Failed++
			case "interrupted", "abandoned":
				report.Totals.Interrupted++
			}
		}
		report.Samples = append(report.Samples, status)
	}
	report.Totals.Samples = len(report.Samples)
	comparisons, err := a.DB.ListComparisons("")
	if err != nil {
		return report, err
	}
	report.Totals.Comparisons = len(comparisons)
	events, err := a.DB.ListEvents(500)
	if err != nil {
		return report, err
	}
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		report.Events = append(report.Events, TimelineEvent{
			At: event.At, Kind: event.Kind, Sample: event.SampleID,
			Run: event.RunID, Detail: event.DetailJSON,
		})
	}
	return report, nil
}

func (r TimelineReport) EventLine(e TimelineEvent) string {
	return fmt.Sprintf("%s  %-18s sample=%s run=%s %s",
		e.At, e.Kind, e.Sample, e.Run, e.Detail)
}
