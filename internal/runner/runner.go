package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"idorfix/internal/detect"
	"idorfix/internal/domain"
	"idorfix/internal/exchange"
	"idorfix/internal/store"
)

// Runner executes one sample at a time and persists enough state for the run
// to be resumed or re-audited after a crash or operator exit.
type Runner struct {
	store           *store.Store
	preAnalysisHook func() error
}

func New(workspace *store.Store) *Runner {
	return &Runner{store: workspace}
}

// SetPreAnalysisHook installs a callback invoked after the run is marked
// RUNNING but before analysis. It exists primarily to make interruption
// handling testable without weakening the write-ahead state machine.
func (runner *Runner) SetPreAnalysisHook(hook func() error) {
	runner.preAnalysisHook = hook
}

// Result is returned to the CLI after a single sample execution.
type Result struct {
	Run     domain.Run
	Verdict domain.Verdict
	Sample  domain.Sample
}

// RunSample performs one fresh attempt. The run row exists in PENDING state
// before any analysis work begins, which guarantees recoverability.
func (runner *Runner) RunSample(ctx context.Context, sample *domain.Sample) (*Result, error) {
	attempt, err := runner.store.NextAttempt(ctx, sample.SampleID)
	if err != nil {
		return nil, err
	}
	runSeq, err := runner.store.NextRunSeq(ctx)
	if err != nil {
		return nil, err
	}

	run := domain.Run{
		RunID:       fmt.Sprintf("run-%s-a%d", sample.SampleID, attempt),
		SampleID:    sample.SampleID,
		Attempt:     attempt,
		Status:      domain.StatusPending,
		StartedAt:   time.Now().UTC(),
		PID:         os.Getpid(),
		InputSHA256: sample.InputSHA256,
		RuleVersion: detect.RuleVersion,
	}
	if err := runner.store.InsertPendingRun(ctx, &run, runSeq); err != nil {
		return nil, fmt.Errorf("persist pending run: %w", err)
	}

	if err := runner.store.MarkRunning(ctx, run.RunID); err != nil {
		return nil, err
	}
	if runner.preAnalysisHook != nil {
		if err := runner.preAnalysisHook(); err != nil {
			_ = runner.markInterrupted(ctx, run.RunID, err)
			return nil, err
		}
	}

	// A signal-aware context turns Ctrl-C into an INTERRUPTED row rather than
	// a silent disappearance. The caller installs the signal handler.
	if err := ctx.Err(); err != nil {
		return nil, runner.markInterrupted(ctx, run.RunID, err)
	}

	verdict, err := detect.Analyse(sample)
	if err != nil {
		_ = runner.store.FailRun(ctx, run.RunID, err.Error(), nowRFC3339Nano())
		return nil, err
	}

	findingsJSON, err := json.Marshal(verdict.Findings)
	if err != nil {
		return nil, err
	}
	fragmentsJSON, err := json.Marshal(verdict.MissingFragments)
	if err != nil {
		return nil, err
	}
	if err := runner.store.CompleteRun(ctx, run.RunID, verdict.Outcome,
		string(findingsJSON), string(fragmentsJSON), nowRFC3339Nano()); err != nil {
		return nil, err
	}

	run.Status = domain.StatusCompleted
	run.Outcome = verdict.Outcome
	return &Result{Run: run, Verdict: verdict, Sample: *sample}, nil
}

func (runner *Runner) markInterrupted(ctx context.Context, runID string, cause error) error {
	// Context cancellation means the database context may be dead; use a
	// short fresh context for the final status write.
	writeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return runner.store.MarkInterrupted(writeCtx, runID, "interrupted: "+cause.Error(), nowRFC3339Nano())
}

// VerifyDeterminism runs the engine twice in-process and compares canonical
// verdicts. It is used by the replay command and by fuzzing regression tests.
func VerifyDeterminism(sample *domain.Sample) error {
	first, err := detect.Analyse(sample)
	if err != nil {
		return err
	}
	second, err := detect.Analyse(sample)
	if err != nil {
		return err
	}
	firstJSON, err := exchange.CanonicalJSON(first)
	if err != nil {
		return err
	}
	secondJSON, err := exchange.CanonicalJSON(second)
	if err != nil {
		return err
	}
	if string(firstJSON) != string(secondJSON) {
		return fmt.Errorf("non-deterministic verdict for sample %s", sample.SampleID)
	}
	return nil
}

func nowRFC3339Nano() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
