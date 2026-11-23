package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"idorfix/internal/detect"
	"idorfix/internal/domain"
	"idorfix/internal/exchange"
	"idorfix/internal/runner"
)

func cmdInit(ctx context.Context, args []string) error {
	flags := parseFlags(args)
	workspace, err := openStore(ctx, flags["db"])
	if err != nil {
		return err
	}
	defer workspace.Close()
	if err := workspace.SetMeta(ctx, "tool_version", exchange.ToolVersion); err != nil {
		return err
	}
	fmt.Println("initialised workspace", flags["db"])
	return nil
}

func cmdImport(ctx context.Context, args []string) error {
	flags := parseFlags(args)
	if flags["file"] == "" {
		return fmt.Errorf("import requires --file")
	}
	raw, err := os.ReadFile(flags["file"])
	if err != nil {
		return err
	}
	workspace, err := openStore(ctx, flags["db"])
	if err != nil {
		return err
	}
	defer workspace.Close()

	result, err := runner.ImportSample(ctx, workspace, raw)
	if err != nil {
		return err
	}
	if result.Skipped {
		fmt.Printf("skipped %s: %s\n", result.Sample.SampleID, result.Reason)
		return nil
	}
	fmt.Printf("imported %s sha256=%s\n", result.Sample.SampleID, result.Sample.InputSHA256)
	return nil
}

func cmdList(ctx context.Context, args []string) error {
	flags := parseFlags(args)
	workspace, err := openStore(ctx, flags["db"])
	if err != nil {
		return err
	}
	defer workspace.Close()

	rows, err := workspace.ListSamples(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("%-4s %-24s %-18s %-16s %s\n", "SEQ", "SAMPLE_ID", "ATTACK_CLASS", "STATUS", "INPUT_SHA256")
	for _, row := range rows {
		latest, err := workspace.LatestCompletedRun(ctx, row.SampleID)
		if err != nil {
			return err
		}
		status := "NEVER_RUN"
		if latest != nil {
			status = latest.Outcome
		}
		fmt.Printf("%-4d %-24s %-18s %-16s %s\n", row.Seq, row.SampleID, row.AttackClass, status, shortHash(row.InputSHA256))
	}
	return nil
}

func cmdRun(ctx context.Context, args []string) error {
	return executeSample(ctx, args, false)
}

func cmdReplay(ctx context.Context, args []string) error {
	return executeSample(ctx, args, true)
}

func executeSample(ctx context.Context, args []string, replay bool) error {
	flags := parseFlags(args)
	sampleID := flags["sample"]
	if sampleID == "" {
		return fmt.Errorf("run requires --sample")
	}
	workspace, err := openStore(ctx, flags["db"])
	if err != nil {
		return err
	}
	defer workspace.Close()

	sample, err := loadStoredSample(ctx, workspace, sampleID)
	if err != nil {
		return err
	}
	if err := runner.VerifyDeterminism(sample); err != nil {
		return err
	}
	executor := runner.New(workspace)
	if delayMS := flags["sleep-ms"]; delayMS != "" {
		delay, err := strconv.Atoi(delayMS)
		if err != nil {
			return fmt.Errorf("invalid --sleep-ms: %w", err)
		}
		executor.SetPreAnalysisHook(func() error {
			select {
			case <-time.After(time.Duration(delay) * time.Millisecond):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}
	result, err := executor.RunSample(ctx, sample)
	if err != nil {
		return err
	}

	fmt.Printf("run=%s attempt=%d outcome=%s rule=%s\n",
		result.Run.RunID, result.Run.Attempt, result.Verdict.Outcome, result.Verdict.RuleVersion)
	printFindings(result.Verdict)
	printFragments(result.Verdict)

	if replay {
		if err := compareWithPrevious(ctx, workspace, sampleID, result); err != nil {
			return err
		}
	}
	return nil
}

func compareWithPrevious(ctx context.Context, workspace storeLike, sampleID string, latest *runner.Result) error {
	runs, err := workspace.ListRuns(ctx, sampleID)
	if err != nil {
		return err
	}
	var previous *domain.Run
	for index := len(runs) - 2; index >= 0; index-- {
		if runs[index].Status == domain.StatusCompleted {
			previous = &runs[index]
			break
		}
	}
	if previous == nil {
		fmt.Println("no earlier completed run to compare against")
		return nil
	}
	match := "MATCH"
	if previous.Outcome != latest.Verdict.Outcome {
		match = "DRIFT"
	}
	fmt.Printf("compare: previous=%s latest=%s -> %s\n", previous.Outcome, latest.Verdict.Outcome, match)
	return nil
}

func cmdRuns(ctx context.Context, args []string) error {
	flags := parseFlags(args)
	if flags["sample"] == "" {
		return fmt.Errorf("runs requires --sample")
	}
	workspace, err := openStore(ctx, flags["db"])
	if err != nil {
		return err
	}
	defer workspace.Close()

	runs, err := workspace.ListRuns(ctx, flags["sample"])
	if err != nil {
		return err
	}
	fmt.Printf("%-4s %-30s %-12s %-18s %s\n", "ATT", "RUN_ID", "STATUS", "OUTCOME", "RULE")
	for _, run := range runs {
		fmt.Printf("%-4d %-30s %-12s %-18s %s\n",
			run.Attempt, run.RunID, run.Status, run.Outcome, run.RuleVersion)
	}
	return nil
}

func cmdCompare(ctx context.Context, args []string) error {
	flags := parseFlags(args)
	if flags["a"] == "" || flags["b"] == "" {
		return fmt.Errorf("compare requires --a and --b run IDs")
	}
	workspace, err := openStore(ctx, flags["db"])
	if err != nil {
		return err
	}
	defer workspace.Close()

	runA, err := workspace.GetRun(ctx, flags["a"])
	if err != nil {
		return err
	}
	runB, err := workspace.GetRun(ctx, flags["b"])
	if err != nil {
		return err
	}

	equalOutcome := runA.Outcome == runB.Outcome
	equalFindings := runA.FindingsJSON == runB.FindingsJSON
	equalFragments := runA.FragmentsJSON == runB.FragmentsJSON
	fmt.Printf("run A: %s (%s)\n", runA.RunID, runA.Outcome)
	fmt.Printf("run B: %s (%s)\n", runB.RunID, runB.Outcome)
	fmt.Printf("outcome match:   %v\n", equalOutcome)
	fmt.Printf("findings match:  %v\n", equalFindings)
	fmt.Printf("fragments match: %v\n", equalFragments)
	if !equalOutcome || !equalFindings || !equalFragments {
		return fmt.Errorf("comparison detected a difference")
	}
	return nil
}

func cmdExport(ctx context.Context, args []string) error {
	flags := parseFlags(args)
	if flags["sample"] == "" || flags["run"] == "" || flags["out"] == "" {
		return fmt.Errorf("export requires --sample, --run and --out")
	}
	workspace, err := openStore(ctx, flags["db"])
	if err != nil {
		return err
	}
	defer workspace.Close()

	sample, err := loadStoredSample(ctx, workspace, flags["sample"])
	if err != nil {
		return err
	}
	run, err := workspace.GetRun(ctx, flags["run"])
	if err != nil {
		return err
	}
	verdict, err := verdictFromRun(run)
	if err != nil {
		return err
	}
	path, err := exchange.Export(flags["out"], sample, run, verdict)
	if err != nil {
		return err
	}
	fmt.Println("exported", path)
	return nil
}

func cmdVerify(ctx context.Context, args []string) error {
	flags := parseFlags(args)
	if flags["bundle"] == "" {
		return fmt.Errorf("verify requires --bundle")
	}
	bundle, err := exchange.VerifyBundle(flags["bundle"])
	if err != nil {
		return err
	}
	// Independent re-analysis from the embedded sample proves the stored
	// verdict is reproducible with the stated rule version.
	verdict, err := detect.Analyse(&bundle.Sample)
	if err != nil {
		return err
	}
	if verdict.Outcome != bundle.Verdict.Outcome {
		return fmt.Errorf("re-analysis outcome %s differs from exported %s",
			verdict.Outcome, bundle.Verdict.Outcome)
	}
	fmt.Printf("bundle %s verified; outcome=%s rule=%s\n",
		bundle.BundleID, verdict.Outcome, verdict.RuleVersion)
	return nil
}

func cmdReload(ctx context.Context, args []string) error {
	flags := parseFlags(args)
	if flags["bundle"] == "" {
		return fmt.Errorf("reload requires --bundle")
	}
	if _, err := exchange.VerifyBundle(flags["bundle"]); err != nil {
		return err
	}
	workspace, err := openStore(ctx, flags["db"])
	if err != nil {
		return err
	}
	defer workspace.Close()

	// Re-load the exported sample file rather than the in-memory bundle: the
	// file's content hash is already recorded, and ImportSample performs the
	// canonical, idempotent comparison against stored rows.
	raw, err := os.ReadFile(filepath.Join(flags["bundle"], "sample.json"))
	if err != nil {
		return err
	}
	result, err := runner.ImportSample(ctx, workspace, raw)
	if err != nil {
		return err
	}
	fmt.Printf("reloaded %s (skipped=%v) with original field order preserved\n",
		result.Sample.SampleID, result.Skipped)
	return nil
}

func loadStoredSample(ctx context.Context, workspace storeLike, sampleID string) (*domain.Sample, error) {
	payload, err := workspace.SamplePayload(ctx, sampleID)
	if err != nil {
		return nil, err
	}
	return exchange.LoadSampleFile([]byte(payload))
}

func verdictFromRun(run *domain.Run) (*domain.Verdict, error) {
	verdict := &domain.Verdict{RuleVersion: run.RuleVersion, Outcome: run.Outcome}
	if run.FindingsJSON != "" {
		if err := json.Unmarshal([]byte(run.FindingsJSON), &verdict.Findings); err != nil {
			return nil, fmt.Errorf("decode findings: %w", err)
		}
	}
	if run.FragmentsJSON != "" {
		if err := json.Unmarshal([]byte(run.FragmentsJSON), &verdict.MissingFragments); err != nil {
			return nil, fmt.Errorf("decode fragments: %w", err)
		}
	}
	return verdict, nil
}

func printFindings(verdict domain.Verdict) {
	for _, finding := range verdict.Findings {
		fmt.Printf("  [%s] %s event=%s %s\n", finding.Severity, finding.RuleID, finding.EventID, finding.Message)
	}
}

func printFragments(verdict domain.Verdict) {
	for _, fragment := range verdict.MissingFragments {
		fmt.Printf("  [GAP] %s %d..%d anchor=%s\n",
			fragment.FragmentID, fragment.StartNS, fragment.EndNS, fragment.AnchorEventID)
	}
}

func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}
