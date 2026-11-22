package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"time"

	"tve/internal/runner"
	"tve/internal/store"
)

func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}

func cmdRun(args []string) error {
	fs := newFlagSet("run")
	db := fs.String("db", defDB, "SQLite database path")
	dir := fs.String("dir", defDir, "artifact directory")
	var p runner.Params
	fs.Int64Var(&p.Seed, "seed", 7, "material seed")
	fs.IntVar(&p.Repeat, "repeat", 2000, "record count (repetitions)")
	fs.IntVar(&p.TemplatePad, "template-pad", 1<<20, "template padding bytes (extreme)")
	fs.IntVar(&p.ValueLen, "value-len", 4096, "value bytes sliced from material")
	fs.IntVar(&p.BatchSize, "batch", 100, "records per batch")
	fs.IntVar(&p.MaxValueBytes, "max-value", 1024, "value length limit (degrades)")
	fs.IntVar(&p.MaxOutputBytes, "max-output", 1<<20, "per-record output budget")
	fs.IntVar(&p.PauseAfter, "pause-after", 0, "pause after N records (0=never)")
	fs.Int64Var(&p.OutputBudget, "budget", 0, "session output budget bytes (0=unlimited)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	mat, sum, err := loadMaterial(*dir, p.Seed)
	if err != nil {
		return err
	}
	st, err := store.OpenStore(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	pj, _ := json.Marshal(p)
	jobID, err := st.CreateJob(time.Now().UTC().Format(time.RFC3339Nano), string(pj), sum, "running")
	if err != nil {
		return err
	}
	if err := st.SaveMaterial(jobID, sum, mat); err != nil {
		return err
	}
	fmt.Printf("job=%d created material-sha=%s repeat=%d\n", jobID, sum, p.Repeat)
	return runLoop(st, jobID, p, mat)
}

func cmdResume(args []string) error {
	fs := newFlagSet("resume")
	db := fs.String("db", defDB, "SQLite database path")
	dir := fs.String("dir", defDir, "artifact directory")
	jobID := fs.Int64("job", 0, "job id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.OpenStore(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	job, err := st.GetJob(*jobID)
	if err != nil {
		return err
	}
	var p runner.Params
	if err := json.Unmarshal([]byte(job.ParamsJSON), &p); err != nil {
		return err
	}
	mat, sum, err := loadMaterial(*dir, p.Seed)
	if err != nil {
		return err
	}
	if sum != job.MaterialSHA {
		return fmt.Errorf("material hash mismatch: disk=%s job=%s (original modified?)", sum, job.MaterialSHA)
	}
	return runLoop(st, *jobID, p, mat)
}

// runLoop runs/resumes until the job completes, reporting pauses and
// resource exhaustion. It does not auto-resume: the operator (or test)
// decides when to continue, which is the point of a pausable pipeline.
func runLoop(st *store.Store, jobID int64, p runner.Params, mat []byte) error {
	r, err := runner.ResumeRunner(st, jobID, p, mat)
	if err != nil {
		return err
	}
	err = r.Run()
	switch {
	case err == nil:
		fmt.Printf("job=%d COMPLETED final-hash=%s\n", jobID, r.FinalHash())
		return nil
	case errors.Is(err, runner.ErrPaused):
		fmt.Printf("job=%d PAUSED (checkpoint saved; resume with: tve resume -job %d)\n", jobID, jobID)
		return nil
	case errors.Is(err, runner.ErrResourceExhausted):
		fmt.Printf("job=%d RESOURCE-EXHAUSTED (checkpoint saved; resume continues in degraded mode)\n", jobID)
		return nil
	}
	return err
}
