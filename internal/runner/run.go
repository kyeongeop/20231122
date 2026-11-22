package runner

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ckaudit/internal/store"
)

type ProgressFunc func(done, total int, smp store.Sample)

func RunCampaign(ctx context.Context, workDir string, runID int64, progress ProgressFunc) error {
	if err := acquireLock(workDir); err != nil {
		return err
	}
	defer releaseLock(workDir)

	st, tc, err := Prepare(workDir)
	if err != nil {
		return err
	}
	defer st.Close()

	run, err := st.GetRun(runID)
	if err != nil {
		return err
	}
	if run.Status == "done" {
		return fmt.Errorf("run %d already done; create a new run", runID)
	}
	if err := st.TouchRun(runID, "running", nil, ""); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	hbDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = st.Heartbeat(runID)
			case <-hbDone:
				return
			case <-ctx.Done():
				_ = st.Heartbeat(runID)
				return
			}
		}
	}()

	if n, err := st.RequeueRunning(runID); err != nil {
		close(hbDone)
		return err
	} else if n > 0 {
		fmt.Fprintf(os.Stderr, "requeued %d sample(s) left in running state\n", n)
	}
	pending, err := st.PendingSamples(runID)
	if err != nil {
		close(hbDone)
		return err
	}
	total := len(pending)
	done := 0
	interrupted := false

	for _, smp := range pending {
		if ctx.Err() != nil {
			interrupted = true
			break
		}
		if err := st.SetSampleStatus(smp.ID, "running"); err != nil {
			close(hbDone)
			return err
		}
		outcome, oerr := tc.RerunSample(ctx, workDir, smp)
		if oerr != nil {
			_ = st.SetSampleStatus(smp.ID, "error")
			close(hbDone)
			return oerr
		}
		if err := st.ClearFindings(smp.ID); err != nil {
			close(hbDone)
			return err
		}
		if err := st.AddFindings(smp.ID, outcome.Findings); err != nil {
			close(hbDone)
			return err
		}
		for _, ev := range outcome.Evidence {
			if err := st.AddEvidence(smp.ID, ev); err != nil {
				close(hbDone)
				return err
			}
		}
		if err := st.SetSampleStatus(smp.ID, outcome.Status); err != nil {
			close(hbDone)
			return err
		}
		smp.Status = outcome.Status
		done++
		if progress != nil {
			progress(done, total, smp)
		}
	}
	close(hbDone)

	remaining, err := st.PendingSamples(runID)
	if err != nil {
		return err
	}
	if interrupted || len(remaining) > 0 {
		return st.TouchRun(runID, "interrupted", nil,
			fmt.Sprintf("paused with %d samples pending", len(remaining)))
	}
	return st.TouchRun(runID, "done", nil, "all samples processed")
}
