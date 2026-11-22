package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"serrfix/internal/model"
	"serrfix/internal/redact"
	"serrfix/internal/store"
)

type RunOptions struct {
	SampleID    string
	Resume      bool
	RetryFailed bool
	StopAfter   int
	Repeat      int
}

type RunSummary struct {
	StartedAt     string   `json:"started_at"`
	FinishedAt    string   `json:"finished_at"`
	Paused        bool     `json:"paused"`
	PauseReason   string   `json:"pause_reason,omitempty"`
	CompletedRuns int      `json:"completed_runs"`
	Passed        int      `json:"passed"`
	Failed        int      `json:"failed"`
	Pending       int      `json:"pending_samples"`
	RunIDs        []string `json:"run_ids"`
}

func (a *App) Run(ctx context.Context, opts RunOptions) (RunSummary, error) {
	if err := a.requireInitialized(); err != nil {
		return RunSummary{}, err
	}
	summary := RunSummary{StartedAt: model.Timestamp(a.now())}
	if err := a.recoverOrphans(summary.StartedAt); err != nil {
		return summary, err
	}

	samples, err := a.selectSamples(opts)
	if err != nil {
		return summary, err
	}
	stopped := false
	for _, sample := range samples {
		if err := ctx.Err(); err != nil {
			summary.Paused = true
			summary.PauseReason = "signal"
			stopped = true
			break
		}
		repeat, err := a.repetitions(sample, opts.Repeat)
		if err != nil {
			return summary, err
		}
		for rep := 1; rep <= repeat; rep++ {
			if opts.StopAfter > 0 && summary.CompletedRuns >= opts.StopAfter {
				summary.Paused = true
				summary.PauseReason = "stop-after"
				stopped = true
				break
			}
			if err := ctx.Err(); err != nil {
				summary.Paused = true
				summary.PauseReason = "signal"
				stopped = true
				break
			}
			run, err := a.runOne(ctx, sample, rep)
			if err != nil {
				return summary, err
			}
			summary.RunIDs = append(summary.RunIDs, run.ID)
			summary.CompletedRuns++
			if run.State == "passed" {
				summary.Passed++
			} else {
				summary.Failed++
			}
		}
		if stopped {
			break
		}
	}
	pending, err := a.pendingCount(opts)
	if err != nil {
		return summary, err
	}
	summary.Pending = pending
	if summary.Pending > 0 && !summary.Paused {
		summary.Paused = true
		summary.PauseReason = "pending"
	}
	summary.FinishedAt = model.Timestamp(a.now())
	if summary.Paused {
		_ = a.DB.AddEvent(summary.FinishedAt, "run_paused", "", "",
			fmt.Sprintf(`{"reason":%q,"pending":%d,"completed_runs":%d}`,
				summary.PauseReason, summary.Pending, summary.CompletedRuns))
	}
	return summary, nil
}

func (a *App) selectSamples(opts RunOptions) ([]model.Sample, error) {
	if opts.SampleID != "" {
		s, err := a.DB.GetSample(opts.SampleID)
		if err != nil {
			return nil, fmt.Errorf("sample %s: %w", opts.SampleID, err)
		}
		return []model.Sample{s}, nil
	}
	all, err := a.DB.ListSamples()
	if err != nil {
		return nil, err
	}
	if !opts.Resume {
		return all, nil
	}
	var out []model.Sample
	for _, sample := range all {
		runs, err := a.DB.ListRuns(sample.ID)
		if err != nil {
			return nil, err
		}
		if len(runs) == 0 {
			out = append(out, sample)
			continue
		}
		last := runs[len(runs)-1]
		switch last.State {
		case "passed":
			continue
		case "failed":
			if opts.RetryFailed {
				out = append(out, sample)
			}
		default:
			out = append(out, sample)
		}
	}
	return out, nil
}

func (a *App) pendingCount(opts RunOptions) (int, error) {
	clone := opts
	clone.SampleID = ""
	clone.Resume = true
	if opts.SampleID != "" {
		runs, err := a.DB.ListRuns(opts.SampleID)
		if err != nil {
			return 0, err
		}
		if len(runs) == 0 || runs[len(runs)-1].State != "passed" {
			return 1, nil
		}
		return 0, nil
	}
	samples, err := a.selectSamples(clone)
	if err != nil {
		return 0, err
	}
	return len(samples), nil
}

func (a *App) repetitions(sample model.Sample, override int) (int, error) {
	if override > 0 {
		return override, nil
	}
	var params model.Params
	if err := json.Unmarshal([]byte(sample.ParamsJSON), &params); err != nil {
		return 0, err
	}
	if params.Repetitions <= 0 {
		return 1, nil
	}
	return params.Repetitions, nil
}

func (a *App) runOne(ctx context.Context, sample model.Sample, repetition int) (model.Run, error) {
	started := a.now()
	attempt, err := a.DB.NextAttempt(sample.ID)
	if err != nil {
		return model.Run{}, err
	}
	runID := fmt.Sprintf("run-%d-%s-a%d-r%d", started.UnixNano(), sample.ID, attempt, repetition)
	evidenceAbs := filepath.Join(a.WS.RunsDir(), sample.ID, runID+".json")
	evidenceRel, err := a.WS.Rel(evidenceAbs)
	if err != nil {
		return model.Run{}, err
	}
	material, err := a.DB.GetMaterial(sample.MaterialID)
	if err != nil {
		return model.Run{}, err
	}
	run := model.Run{
		ID: runID, SampleID: sample.ID, Attempt: attempt, Repetition: repetition,
		State: "running", StartedAt: started, FinishedAt: started,
		EvidencePath: evidenceRel, CreatedAt: started,
	}
	evidenceSHA, err := a.writeRequest(evidenceAbs, run, sample, material)
	if err != nil {
		return model.Run{}, err
	}
	run.EvidenceSHA256 = evidenceSHA
	if err := a.DB.AddRun(&run); err != nil {
		return model.Run{}, err
	}
	if err := a.DB.AddEvent(model.Timestamp(started), "run_started", sample.ID, run.ID,
		fmt.Sprintf(`{"attempt":%d,"repetition":%d,"offset":%d,"length":%d}`,
			attempt, repetition, sample.Offset, sample.Length)); err != nil {
		return model.Run{}, err
	}

	data, readErr := a.readSample(sample, material)
	var result redact.Result
	if readErr == nil {
		result = redact.Redact(data)
	}
	finished := a.now()
	if finished.Before(started) {
		finished = started
	}
	run.FinishedAt = finished
	run.DurationNS = finished.Sub(started).Nanoseconds()
	run.BeforeLeaks = len(result.Spans)
	run.AfterLeaks = len(result.Remaining)
	run.RedactedSHA256 = model.SHA256(result.Redacted)
	if readErr != nil {
		run.State = "failed"
		run.Error = readErr.Error()
	} else if run.AfterLeaks > 0 {
		run.State = "failed"
		run.Error = fmt.Sprintf("%d sensitive span(s) remain after redaction", run.AfterLeaks)
	} else {
		run.State = "passed"
	}
	if err := ctx.Err(); err != nil && run.State == "passed" {
		run.State = "interrupted"
		run.Error = "cancelled after sample execution"
	}
	ev := buildEvidence(sample, material, run, result, material.SnapshotPath)
	run.EvidenceSHA256, err = a.writeEvidence(evidenceAbs, ev)
	if err != nil {
		return run, err
	}
	if err := a.DB.FinishRun(&run, result.Spans); err != nil {
		return run, err
	}
	return run, nil
}

func (a *App) readSample(sample model.Sample, material store.Material) ([]byte, error) {
	data, err := a.WS.ReadSlice(material, sample.Offset, sample.Length)
	if err != nil {
		return nil, err
	}
	if got := model.SHA256(data); got != sample.SHA256 {
		return nil, fmt.Errorf("sample source hash mismatch at material %s offset %d: got %s want %s",
			material.ID, sample.Offset, got, sample.SHA256)
	}
	return data, nil
}

func (a *App) recoverOrphans(at string) error {
	orphans, err := a.DB.ListInterrupted()
	if err != nil {
		return err
	}
	for _, run := range orphans {
		note := "process exited before the run committed; request evidence retained at " + run.EvidencePath
		if _, statErr := os.Stat(a.WS.Resolve(run.EvidencePath)); statErr != nil {
			note = "process exited before evidence was written: " + statErr.Error()
		}
		if err := a.DB.AbandonRun(run.ID, at, note); err != nil {
			return err
		}
	}
	return nil
}
