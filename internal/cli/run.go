package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"auditfix/internal/db"
	"auditfix/internal/model"
	"auditfix/internal/runner"
)

const defaultFuzzArgs = "-runs=1 -verbosity=0 -print_final_stats=0 -detect_leaks=0"

func (a *App) runSamples(ctx context.Context, args []string, resume bool) error {
	name := "run"
	if resume {
		name = "resume"
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	dbPath := flags.String("db", "", "SQLite database path")
	caseID := flags.String("case-id", "", "case identifier")
	runID := flags.String("run-id", "", "run identifier")
	harness := flags.String("harness", "", "libFuzzer harness executable")
	limit := flags.Int("limit", 0, "maximum new attempts in this invocation (0 = all)")
	timeout := flags.Duration("timeout", 0, "per-sample harness timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	timeoutSet := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "timeout" {
			timeoutSet = true
		}
	})
	if err := a.requireDB(flags, *dbPath); err != nil {
		return err
	}
	if !cleanID(*runID) {
		return errors.New("--run-id must use letters, digits, '-', '_' or '.'")
	}
	if *limit < 0 {
		return errors.New("--limit cannot be negative")
	}
	if timeoutSet && *timeout <= 0 {
		return errors.New("--timeout must be positive")
	}
	store, err := db.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	var run model.Run
	if resume {
		run, err = store.GetRun(ctx, *runID)
		if err != nil {
			return err
		}
		if *caseID != "" && *caseID != run.CaseID {
			return fmt.Errorf("run %q belongs to case %q", *runID, run.CaseID)
		}
	} else {
		if !cleanID(*caseID) {
			return errors.New("--case-id is required")
		}
		if _, err := store.GetCase(ctx, *caseID); err != nil {
			return err
		}
		count, err := store.SampleCount(ctx, *caseID)
		if err != nil {
			return err
		}
		if count == 0 {
			return fmt.Errorf("case %q has no samples", *caseID)
		}
		if exists, err := store.CaseExists(ctx, *caseID); err != nil || !exists {
			return fmt.Errorf("case %q is unavailable", *caseID)
		}
		if _, err := store.GetRun(ctx, *runID); err == nil {
			return fmt.Errorf("run %q already exists; use resume", *runID)
		} else if !errors.Is(err, db.ErrNotFound) {
			return err
		}
	}
	if !timeoutSet {
		if resume {
			*timeout = time.Duration(run.TimeoutMS) * time.Millisecond
		} else {
			*timeout = 5 * time.Second
		}
	}
	if *timeout <= 0 {
		*timeout = 5 * time.Second
	}

	harnessPath := *harness
	if harnessPath == "" && resume {
		harnessPath = run.HarnessPath
	}
	if err := requirePath("harness", harnessPath); err != nil {
		return err
	}
	harnessPath = absPath(harnessPath)
	harnessSHA, _, err := sha256File(harnessPath)
	if err != nil {
		return fmt.Errorf("hash harness: %w", err)
	}
	info, err := os.Stat(harnessPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("harness %q is not executable", harnessPath)
	}
	if resume && harnessSHA != run.HarnessSHA256 {
		return fmt.Errorf("harness hash changed: run uses %s, supplied %s",
			run.HarnessSHA256, harnessSHA)
	}

	now := nowText()
	if !resume {
		run = model.Run{
			RunID:          *runID,
			CaseID:         *caseID,
			HarnessSHA256:  harnessSHA,
			HarnessPath:    harnessPath,
			TimeoutMS:      timeout.Milliseconds(),
			FuzzArgs:       defaultFuzzArgs,
			Status:         "running",
			CreatedAt:      now,
			StartedAt:      now,
			RequestedLimit: *limit,
			SchemaVersion:  model.SchemaVersion,
		}
		if err := store.InsertRun(ctx, run); err != nil {
			return err
		}
	}
	if run.Status == "complete" {
		fmt.Fprintf(a.Stdout, "run=%s already complete\n", run.RunID)
		return nil
	}

	interrupted, err := store.MarkRunningAttemptsInterrupted(context.Background(), run.RunID, now)
	if err != nil {
		return err
	}
	if interrupted > 0 {
		run.ResumedCount++
		fmt.Fprintf(a.Stdout, "recovered %d interrupted attempt(s)\n", interrupted)
	}
	samples, err := store.ListSamples(ctx, run.CaseID)
	if err != nil {
		return err
	}
	attempts, err := store.ListAttempts(ctx, run.RunID)
	if err != nil {
		return err
	}
	terminal := terminalAttempts(attempts)
	newAttempts := 0
	for _, sample := range samples {
		if _, done := terminal[sample.SampleID]; done {
			continue
		}
		if *limit > 0 && newAttempts >= *limit {
			break
		}
		if ctx.Err() != nil {
			a.pauseRun(store, run, "interrupted")
			return ctx.Err()
		}
		_, data, err := store.FindSample(context.Background(), run.CaseID, sample.SampleID)
		if err != nil {
			return err
		}
		attempt, err := a.executeAttempt(ctx, store, run, sample, data, *timeout)
		if err != nil {
			if ctx.Err() != nil {
				a.pauseRun(store, run, "interrupted")
				return ctx.Err()
			}
			return err
		}
		newAttempts++
		fmt.Fprintf(a.Stdout, "%d\t%s\tattempt=%d\t%s\t%s\n",
			sample.SampleIndex, sample.Name, attempt.AttemptNo,
			attempt.Status, classificationOf(attempt.ResultJSON))
		if attempt.Status == "complete" || attempt.Status == "crash" || attempt.Status == "timeout" {
			terminal[sample.SampleID] = attempt
		}
	}

	remaining := false
	for _, sample := range samples {
		if _, done := terminal[sample.SampleID]; !done {
			remaining = true
			break
		}
	}
	status := "complete"
	if remaining {
		status = "paused"
	}
	if ctx.Err() != nil {
		status = "paused"
	}
	if err := a.updateRunCounts(store, run, status); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "run=%s status=%s new_attempts=%d\n",
		run.RunID, status, newAttempts)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func (a *App) replaySample(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("replay", flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	dbPath := flags.String("db", "", "SQLite database path")
	runID := flags.String("run-id", "", "run identifier")
	sampleRef := flags.String("sample", "", "sample id, index, name, or sha prefix")
	harness := flags.String("harness", "", "optional replacement harness")
	timeout := flags.Duration("timeout", 0, "per-sample harness timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	timeoutSet := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "timeout" {
			timeoutSet = true
		}
	})
	if err := a.requireDB(flags, *dbPath); err != nil {
		return err
	}
	if err := requirePath("run-id", *runID); err != nil {
		return err
	}
	if err := requirePath("sample", *sampleRef); err != nil {
		return err
	}
	store, err := db.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	run, err := store.GetRun(ctx, *runID)
	if err != nil {
		return err
	}
	if !timeoutSet {
		*timeout = time.Duration(run.TimeoutMS) * time.Millisecond
	}
	if *timeout <= 0 {
		return errors.New("--timeout must be positive")
	}
	harnessPath := run.HarnessPath
	harnessSHA := run.HarnessSHA256
	if *harness != "" {
		harnessPath = absPath(*harness)
		harnessSHA, _, err = sha256File(harnessPath)
		if err != nil {
			return err
		}
		if harnessSHA != run.HarnessSHA256 {
			return fmt.Errorf("replay harness differs from run harness (%s)", run.HarnessSHA256)
		}
	}
	run.HarnessPath = harnessPath
	sample, data, err := store.FindSample(ctx, run.CaseID, *sampleRef)
	if err != nil {
		return err
	}
	attempt, err := a.executeAttempt(ctx, store, run, sample, data, *timeout)
	if err != nil {
		_ = a.updateRunCounts(store, run, run.Status)
		return err
	}
	if err := a.updateRunCounts(store, run, run.Status); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "run=%s sample=%s attempt=%d status=%s result=%s\n",
		run.RunID, sample.Name, attempt.AttemptNo, attempt.Status,
		classificationOf(attempt.ResultJSON))
	return nil
}

func (a *App) executeAttempt(ctx context.Context, store *db.Store, run model.Run,
	sample model.Sample, data []byte, timeout time.Duration) (model.Attempt, error) {
	attemptNo, err := store.NextAttemptNo(context.Background(), run.RunID, sample.SampleID)
	if err != nil {
		return model.Attempt{}, err
	}
	startedAt := nowText()
	attempt := model.Attempt{
		RunID:       run.RunID,
		SampleID:    sample.SampleID,
		SampleIndex: sample.SampleIndex,
		AttemptNo:   attemptNo,
		Status:      "running",
		StartedAt:   startedAt,
		EvidenceSHA256: sha256Hex([]byte(strings.Join([]string{
			"auditfix.pending.v1", sample.SHA256, run.HarnessSHA256,
		}, "\n"))),
	}
	attemptID, err := store.InsertRunningAttempt(context.Background(), attempt)
	if err != nil {
		return model.Attempt{}, err
	}
	attempt.AttemptID = attemptID

	outcome, runErr := runner.RunSample(ctx, runner.Config{
		HarnessPath: run.HarnessPath,
		Timeout:     timeout,
	}, data)
	if ctx.Err() != nil {
		attempt.Status = "interrupted"
		attempt.FinishedAt = nowText()
		attempt.ExitCode = outcome.ExitCode
		attempt.Signal = outcome.Signal
		attempt.Stdout = []byte(outcome.Stdout)
		attempt.Stderr = []byte(outcome.Stderr)
		attempt.StdoutSHA256 = sha256Hex([]byte(outcome.Stdout))
		attempt.StderrSHA256 = sha256Hex([]byte(outcome.Stderr))
		attempt.HarnessOutput = extractMarker(outcome.Stdout)
		attempt.Error = "interrupted by operator"
		if err := store.FinishAttempt(context.Background(), attempt); err != nil {
			return model.Attempt{}, err
		}
		return attempt, ctx.Err()
	}

	var parsed *runner.HarnessResult
	if result, err := runner.ParseHarnessOutput(outcome.Stdout); err == nil {
		parsed = &result
	} else if outcome.TimedOut {
		parsed = nil
	} else if outcome.Err == nil {
		runErr = err
	}
	resultJSON, evidenceSHA, err := runner.NormalizeResult(sample.SHA256,
		run.HarnessSHA256, outcome.Stdout, outcome.Stderr,
		outcome.ExitCode, outcome.Signal, outcome.TimedOut, parsed)
	if err != nil {
		return model.Attempt{}, err
	}
	attempt.Status = "complete"
	if outcome.TimedOut {
		attempt.Status = "timeout"
	} else if outcome.Signal != 0 || outcome.ExitCode != 0 {
		attempt.Status = "crash"
	} else if parsed == nil {
		attempt.Status = "error"
	}
	attempt.FinishedAt = nowText()
	attempt.ExitCode = outcome.ExitCode
	attempt.Signal = outcome.Signal
	attempt.TimedOut = outcome.TimedOut
	attempt.Stdout = []byte(outcome.Stdout)
	attempt.Stderr = []byte(outcome.Stderr)
	attempt.StdoutSHA256 = sha256Hex([]byte(outcome.Stdout))
	attempt.StderrSHA256 = sha256Hex([]byte(outcome.Stderr))
	attempt.HarnessOutput = extractMarker(outcome.Stdout)
	attempt.ResultJSON = resultJSON
	attempt.EvidenceSHA256 = evidenceSHA
	if outcome.Err != nil {
		attempt.Error = outcome.Err.Error()
	} else if runErr != nil {
		attempt.Error = runErr.Error()
	}
	if err := store.FinishAttempt(context.Background(), attempt); err != nil {
		return model.Attempt{}, err
	}
	return attempt, nil
}

func (a *App) updateRunCounts(store *db.Store, run model.Run, status string) error {
	completed, err := store.CountCompletedSamples(context.Background(), run.RunID)
	if err != nil {
		return err
	}
	attempts, err := store.CountAttempts(context.Background(), run.RunID)
	if err != nil {
		return err
	}
	finishedAt := ""
	if status == "complete" {
		finishedAt = run.FinishedAt
		if finishedAt == "" {
			finishedAt = nowText()
		}
	}
	return store.UpdateRunStatus(context.Background(), run.RunID, status, finishedAt,
		completed, attempts, run.ResumedCount)
}

func (a *App) pauseRun(store *db.Store, run model.Run, reason string) {
	if err := a.updateRunCounts(store, run, "paused"); err != nil {
		fmt.Fprintf(a.Stderr, "auditfix: record paused run: %v\n", err)
	}
	fmt.Fprintf(a.Stdout, "run=%s status=paused reason=%s\n", run.RunID, reason)
}

func terminalAttempts(attempts []model.Attempt) map[string]model.Attempt {
	out := make(map[string]model.Attempt)
	for _, attempt := range attempts {
		switch attempt.Status {
		case "complete", "crash", "timeout":
			out[attempt.SampleID] = attempt
		}
	}
	return out
}

func classificationOf(resultJSON string) string {
	var value struct {
		Classification string `json:"classification"`
	}
	if err := jsonUnmarshal(resultJSON, &value); err != nil {
		return "UNKNOWN"
	}
	if value.Classification == "" {
		return "UNKNOWN"
	}
	return value.Classification
}

func extractMarker(stdout string) string {
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "AUDITFIX_RESULT ") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}
