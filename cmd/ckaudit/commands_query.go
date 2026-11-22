package main

import (
	"context"
	"fmt"
	"strings"

	"ckaudit/internal/runner"
)

func cmdFuzz(ctx context.Context, workDir string, args []string) error {
	runID, err := resolveRunID(workDir, args)
	if err != nil {
		return err
	}
	tc, err := runner.Locate(repoRoot())
	if err != nil {
		return err
	}
	if err := tc.Build(); err != nil {
		return err
	}
	cfg := runner.FuzzConfig{
		WorkDir: workDir, RunID: runID,
		Runs:   flagInt(args, "--runs", 50000),
		MaxLen: int(flagInt(args, "--max-len", 4096)),
		Seed:   flagInt(args, "--seed", 1),
		Jobs:   int(flagInt(args, "--jobs", 2)),
	}
	res, err := tc.Fuzz(ctx, cfg)
	if err != nil {
		return err
	}
	st, err := openStore(workDir)
	if err != nil {
		return err
	}
	defer st.Close()
	status := "done"
	paths := make([]string, 0, len(res.Artifacts))
	for _, ev := range res.Artifacts {
		paths = append(paths, ev.Path)
	}
	note := fmt.Sprintf("libFuzzer exit=%d, artifacts=%d, evidence=%s",
		res.ExitCode, len(res.Artifacts), strings.Join(paths, ","))
	if res.ExitCode != 0 {
		status = "interrupted"
	}
	if err := st.TouchRun(runID, status, &res.ExitCode, note); err != nil {
		return err
	}
	fmt.Println(note)
	fmt.Printf("crash artifacts: %s\n", res.CrashDir)
	return nil
}

func cmdRerun(ctx context.Context, workDir string, args []string) error {
	key := flagValue(args, "--sample", "")
	if key == "" {
		return fmt.Errorf("--sample is required")
	}
	runID, err := resolveRunID(workDir, args)
	if err != nil {
		return err
	}
	st, err := openStore(workDir)
	if err != nil {
		return err
	}
	smp, err := st.SampleByKey(runID, key)
	st.Close()
	if err != nil {
		return err
	}
	tc, err := runner.Locate(repoRoot())
	if err != nil {
		return err
	}
	if err := tc.Build(); err != nil {
		return err
	}
	out, err := tc.RerunSample(ctx, workDir, *smp)
	if err != nil {
		return err
	}
	fmt.Printf("sample=%s status=%s exit=%d findings=%d\n",
		smp.SampleKey, out.Status, out.ExitCode, len(out.Findings))
	for _, f := range out.Findings {
		fmt.Printf("  %-5s %-24s %s\n", f.Severity, f.Code, f.Message)
	}
	return nil
}

func cmdList(workDir string) error {
	st, err := openStore(workDir)
	if err != nil {
		return err
	}
	defer st.Close()
	runs, err := st.ListRuns()
	if err != nil {
		return err
	}
	if len(runs) == 0 {
		fmt.Println("no runs; run 'ckaudit init' first")
		return nil
	}
	for _, r := range runs {
		fmt.Printf("#%d %-24s %-11s mode=%s samples=%d ok=%d crash=%d pending=%d\n",
			r.ID, r.Name, r.Status, r.Mode, r.Total, r.OK, r.Crash, r.Pending)
	}
	return nil
}

func cmdShow(workDir string, args []string) error {
	key := flagValue(args, "--sample", "")
	if key == "" {
		return fmt.Errorf("--sample is required")
	}
	runID, err := resolveRunID(workDir, args)
	if err != nil {
		return err
	}
	st, err := openStore(workDir)
	if err != nil {
		return err
	}
	defer st.Close()
	smp, err := st.SampleByKey(runID, key)
	if err != nil {
		return err
	}
	findings, _ := st.Findings(smp.ID)
	evidence, _ := st.Evidence(smp.ID)
	fmt.Printf("key: %s\nscenario: %s boundary: %s side: %s param: %s\nstatus: %s attempts: %d\n",
		smp.SampleKey, smp.Scenario, smp.Boundary, smp.Side, smp.ParamValue,
		smp.Status, smp.Attempts)
	fmt.Printf("input: %q\n", smp.Input)
	fmt.Println("findings:")
	if len(findings) == 0 {
		fmt.Println("  (none)")
	}
	for _, f := range findings {
		fmt.Printf("  %-5s %-24s %s\n", f.Severity, f.Code, f.Message)
	}
	fmt.Println("evidence:")
	if len(evidence) == 0 {
		fmt.Println("  (none)")
	}
	for _, ev := range evidence {
		fmt.Printf("  %-16s %s sha256=%s\n", ev.Kind, ev.Path, ev.SHA256[:12])
	}
	return nil
}
