package main

import (
	"context"
	"fmt"

	"ckaudit/internal/runner"
	"ckaudit/internal/store"
)

func openStore(workDir string) (*store.Store, error) {
	return store.Open(workDir + "/audit.db")
}

func resolveRunID(workDir string, args []string) (int64, error) {
	if v := flagValue(args, "--run", ""); v != "" {
		var id int64
		if _, err := fmt.Sscanf(v, "%d", &id); err != nil {
			return 0, fmt.Errorf("bad --run value %q", v)
		}
		return id, nil
	}
	st, err := openStore(workDir)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	r, err := st.LatestRun()
	if err != nil {
		return 0, err
	}
	return r.ID, nil
}

func cmdInit(ctx context.Context, workDir string, args []string) error {
	cfg := runner.CampaignConfig{
		WorkDir: workDir,
		Name:    flagValue(args, "--name", "cookie-audit-campaign"),
		MaxRuns: flagInt(args, "--runs", 50000),
		MaxLen:  int(flagInt(args, "--max-len", 4096)),
		Seed:    flagInt(args, "--seed", 1),
		Jobs:    int(flagInt(args, "--jobs", 2)),
	}
	id, err := runner.Init(ctx, cfg)
	if err != nil {
		return err
	}
	fmt.Printf("initialized run #%d in %s (samples generated, nothing executed yet)\n", id, workDir)
	return nil
}

func cmdRun(ctx context.Context, workDir string, args []string) error {
	id, err := resolveRunID(workDir, args)
	if err != nil {
		return err
	}
	return runner.RunCampaign(ctx, workDir, id, progressPrinter)
}

func cmdResume(ctx context.Context, workDir string) error {
	st, err := openStore(workDir)
	if err != nil {
		return err
	}
	r, err := st.LatestRun()
	st.Close()
	if err != nil {
		return err
	}
	if r.Status == "done" {
		return fmt.Errorf("latest run #%d is already done", r.ID)
	}
	fmt.Printf("resuming run #%d (status=%s)\n", r.ID, r.Status)
	return runner.RunCampaign(ctx, workDir, r.ID, progressPrinter)
}

func cmdBuild(workDir string) error {
	tc, err := runner.BuildFromWorkDir(workDir)
	if err != nil {
		return err
	}
	fmt.Printf("built %s and %s\n", tc.FuzzBin, tc.PlainBin)
	return nil
}

func cmdStop(workDir string) error {
	if err := runner.ReleaseStaleLock(workDir); err != nil {
		return err
	}
	fmt.Printf("cleared lock in %s; running campaigns finish their current sample\n", workDir)
	return nil
}

func progressPrinter(done, total int, smp store.Sample) {
	fmt.Printf("[%3d/%d] %-40s %s\n", done, total, smp.SampleKey, smp.Status)
}
