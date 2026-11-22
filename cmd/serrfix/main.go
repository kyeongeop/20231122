package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"serrfix/internal/app"
	"serrfix/internal/model"
)

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage(out)
		return 0
	}
	cmd, args := args[0], args[1:]
	switch cmd {
	case "init":
		return cmdInit(args, out, errOut)
	case "run":
		return cmdRun(args, out, errOut, false)
	case "rerun":
		return cmdRun(args, out, errOut, true)
	case "list":
		return cmdList(args, out, errOut)
	case "show":
		return cmdShow(args, out, errOut)
	case "compare":
		return cmdCompare(args, out, errOut)
	case "export":
		return cmdExport(args, out, errOut)
	case "verify":
		return cmdVerify(args, out, errOut)
	case "report":
		return cmdReport(args, out, errOut)
	case "accept":
		return cmdAccept(args, out, errOut)
	case "fuzz":
		return cmdFuzz(args, out, errOut)
	default:
		fmt.Fprintf(errOut, "unknown command %q\n\n", cmd)
		printUsage(errOut)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `serrfix - localized remediation for sensitive data in error messages

Usage:
  serrfix init    --workspace .serrfix --original testdata/original/incident-errors.txt
  serrfix run     --workspace .serrfix --resume [--stop-after N] [--retry-failed]
  serrfix rerun   --workspace .serrfix --sample SAMPLE_ID [--repeat N]
  serrfix list    --workspace .serrfix [--json]
  serrfix show    --workspace .serrfix --sample SAMPLE_ID [--json]
  serrfix compare --workspace .serrfix --sample SAMPLE_ID [--a RUN_ID --b RUN_ID] [--json]
  serrfix export  --workspace .serrfix --sample SAMPLE_ID [--out FILE.zip] [--json]
  serrfix verify  --workspace .serrfix [--json]
  serrfix report  --workspace .serrfix [--json]
  serrfix accept  --workspace .serrfix [--json]
  serrfix fuzz    --workspace .serrfix [--runs N] [--max-seconds N]

The original material is copied byte-for-byte to a read-only snapshot. Samples,
runs, byte offsets, UTC timestamps, redaction spans and comparisons are stored
in SQLite. Use "run --resume" after an interruption to continue pending samples.`)
}

func cmdInit(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(errOut)
	ws := fs.String("workspace", ".serrfix", "workspace directory")
	original := fs.String("original", "", "immutable original material file")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	a, err := app.Open(*ws, out, errOut)
	if err != nil {
		return fail(errOut, err)
	}
	defer a.Close()
	result, err := a.Init(app.InitOptions{OriginalPath: *original})
	if err != nil {
		return fail(errOut, err)
	}
	if *asJSON {
		printJSON(out, result)
		return 0
	}
	status := "initialized"
	if result.AlreadyInitialized {
		status = "already initialized"
	}
	fmt.Fprintf(out, "%s workspace=%s\n", status, result.Workspace)
	fmt.Fprintf(out, "  material=%s size=%d sha256=%s\n",
		result.MaterialID, result.OriginalSize, result.OriginalSHA256)
	fmt.Fprintf(out, "  snapshot=%s\n", result.SnapshotPath)
	fmt.Fprintf(out, "  captured_at=%s samples=%d\n", result.CapturedAt, result.Samples)
	return 0
}

func cmdRun(args []string, out, errOut io.Writer, rerun bool) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(errOut)
	ws := fs.String("workspace", ".serrfix", "workspace directory")
	sample := fs.String("sample", "", "single sample id")
	resume := fs.Bool("resume", false, "run pending/interrupted samples only")
	retryFailed := fs.Bool("retry-failed", false, "with --resume, retry failed samples")
	stopAfter := fs.Int("stop-after", 0, "pause after N completed runs")
	repeat := fs.Int("repeat", 0, "repetition count; overrides the case object")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if rerun && *sample == "" {
		fmt.Fprintln(errOut, "rerun requires --sample")
		return 2
	}
	a, err := app.Open(*ws, out, errOut)
	if err != nil {
		return fail(errOut, err)
	}
	defer a.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	summary, err := a.Run(ctx, app.RunOptions{
		SampleID: *sample, Resume: *resume, RetryFailed: *retryFailed,
		StopAfter: *stopAfter, Repeat: *repeat,
	})
	if err != nil {
		return fail(errOut, err)
	}
	if *asJSON {
		printJSON(out, summary)
	} else {
		printRunSummary(out, summary)
	}
	if summary.Failed > 0 {
		return 1
	}
	return 0
}

func cmdList(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(errOut)
	ws := fs.String("workspace", ".serrfix", "workspace directory")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	a, err := app.Open(*ws, out, errOut)
	if err != nil {
		return fail(errOut, err)
	}
	defer a.Close()
	report, err := a.Report()
	if err != nil {
		return fail(errOut, err)
	}
	if *asJSON {
		printJSON(out, report.Samples)
		return 0
	}
	fmt.Fprintf(out, "%-24s %-10s %-10s %-10s %8s %s\n",
		"SAMPLE", "STATE", "OFFSET", "LENGTH", "RUNS", "LABEL")
	for _, sample := range report.Samples {
		state := sample.LatestState
		if state == "" {
			state = "pending"
		}
		fmt.Fprintf(out, "%-24s %-10s %-10d %-10d %8d %s\n",
			sample.SampleID, state, sample.SourceOffset, sample.SourceLength,
			sample.RunCount, sample.Label)
	}
	return 0
}

func cmdShow(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.SetOutput(errOut)
	ws := fs.String("workspace", ".serrfix", "workspace directory")
	sampleID := fs.String("sample", "", "sample id")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sampleID == "" {
		fmt.Fprintln(errOut, "show requires --sample")
		return 2
	}
	a, err := app.Open(*ws, out, errOut)
	if err != nil {
		return fail(errOut, err)
	}
	defer a.Close()
	sample, err := a.DB.GetSample(*sampleID)
	if err != nil {
		return fail(errOut, err)
	}
	runs, err := a.DB.ListRuns(sample.ID)
	if err != nil {
		return fail(errOut, err)
	}
	spans := map[string][]model.Span{}
	for _, run := range runs {
		s, err := a.DB.ListSpans(run.ID)
		if err != nil {
			return fail(errOut, err)
		}
		spans[run.ID] = s
	}
	payload := map[string]any{
		"sample": sample, "case": json.RawMessage(sample.CaseJSON),
		"params": json.RawMessage(sample.ParamsJSON),
		"runs":   runs, "spans": spans,
	}
	if *asJSON {
		printJSON(out, payload)
		return 0
	}
	fmt.Fprintf(out, "sample=%s label=%s origin=%s\n", sample.ID, sample.Label, sample.Origin)
	fmt.Fprintf(out, "source material=%s offset=%d length=%d sha256=%s\n",
		sample.MaterialID, sample.Offset, sample.Length, sample.SHA256)
	fmt.Fprintf(out, "created_at=%s runs=%d\n", model.Timestamp(sample.CreatedAt), len(runs))
	for _, run := range runs {
		fmt.Fprintf(out, "  %s attempt=%d state=%s started=%s finished=%s leaks=%d/%d\n",
			run.ID, run.Attempt, run.State, model.Timestamp(run.StartedAt),
			model.Timestamp(run.FinishedAt), run.BeforeLeaks, run.AfterLeaks)
		for _, span := range spans[run.ID] {
			fmt.Fprintf(out, "    %s offset=%d+%d line=%d col=%d replacement=%s\n",
				span.Kind, span.SourceOffset, span.SourceLength, span.Line, span.Column,
				span.Replacement)
		}
	}
	return 0
}

func cmdCompare(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(errOut)
	ws := fs.String("workspace", ".serrfix", "workspace directory")
	sample := fs.String("sample", "", "sample id")
	runA := fs.String("a", "", "first run id (default: second-to-last)")
	runB := fs.String("b", "", "second run id (default: last)")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	a, err := app.Open(*ws, out, errOut)
	if err != nil {
		return fail(errOut, err)
	}
	defer a.Close()
	report, err := a.Compare(app.CompareOptions{SampleID: *sample, RunA: *runA, RunB: *runB})
	if err != nil {
		return fail(errOut, err)
	}
	if *asJSON {
		printJSON(out, report)
		return 0
	}
	fmt.Fprintf(out, "comparison=%s at=%s\n", report.ComparisonID, report.ComparedAt)
	fmt.Fprintf(out, "  run_a=%s attempt=%d state=%s\n",
		report.RunA.RunID, report.RunA.Attempt, report.RunA.State)
	fmt.Fprintf(out, "  run_b=%s attempt=%d state=%s\n",
		report.RunB.RunID, report.RunB.Attempt, report.RunB.State)
	fmt.Fprintf(out, "  same_original=%t same_redacted=%t same_spans=%t\n",
		report.SameOriginal, report.SameRedacted, report.SameSpanLayout)
	fmt.Fprintf(out, "  byte_change old=%d+%d new=%d+%d\n",
		report.ByteChange.OldOffset, report.ByteChange.OldLength,
		report.ByteChange.NewOffset, report.ByteChange.NewLength)
	fmt.Fprintf(out, "  evidence=%s\n", report.EvidencePath)
	return 0
}

func cmdExport(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(errOut)
	ws := fs.String("workspace", ".serrfix", "workspace directory")
	sample := fs.String("sample", "", "sample id")
	outPath := fs.String("out", "", "output zip path")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	a, err := app.Open(*ws, out, errOut)
	if err != nil {
		return fail(errOut, err)
	}
	defer a.Close()
	result, err := a.Export(app.ExportOptions{SampleID: *sample, OutPath: *outPath})
	if err != nil {
		return fail(errOut, err)
	}
	if *asJSON {
		printJSON(out, result)
		return 0
	}
	fmt.Fprintf(out, "exported=%s size=%d sha256=%s runs=%d at=%s\n",
		result.Path, result.Size, result.SHA256, result.Runs, result.ExportedAt)
	return 0
}

func cmdVerify(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(errOut)
	ws := fs.String("workspace", ".serrfix", "workspace directory")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	a, err := app.Open(*ws, out, errOut)
	if err != nil {
		return fail(errOut, err)
	}
	defer a.Close()
	report, err := a.Verify()
	if err != nil {
		return fail(errOut, err)
	}
	if *asJSON {
		printJSON(out, report)
	} else {
		printVerify(out, report)
	}
	if !report.OK {
		return 1
	}
	return 0
}

func cmdReport(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(errOut)
	ws := fs.String("workspace", ".serrfix", "workspace directory")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	a, err := app.Open(*ws, out, errOut)
	if err != nil {
		return fail(errOut, err)
	}
	defer a.Close()
	report, err := a.Report()
	if err != nil {
		return fail(errOut, err)
	}
	if *asJSON {
		printJSON(out, report)
	} else {
		printReport(out, report)
	}
	return 0
}

func cmdAccept(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("accept", flag.ContinueOnError)
	fs.SetOutput(errOut)
	ws := fs.String("workspace", ".serrfix", "workspace directory")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	a, err := app.Open(*ws, out, errOut)
	if err != nil {
		return fail(errOut, err)
	}
	defer a.Close()
	verify, err := a.Verify()
	if err != nil {
		return fail(errOut, err)
	}
	timeline, err := a.Report()
	if err != nil {
		return fail(errOut, err)
	}
	payload := struct {
		Schema     string             `json:"schema"`
		AcceptedAt string             `json:"accepted_at"`
		OK         bool               `json:"ok"`
		Verify     app.VerifyReport   `json:"verify"`
		Timeline   app.TimelineReport `json:"timeline"`
	}{"serrfix.accept/v1", verify.AcceptedAt, verify.OK, verify, timeline}
	if *asJSON {
		printJSON(out, payload)
	} else {
		printVerify(out, verify)
		fmt.Fprintln(out)
		printReport(out, timeline)
	}
	if !verify.OK {
		return 1
	}
	return 0
}

func cmdFuzz(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("fuzz", flag.ContinueOnError)
	fs.SetOutput(errOut)
	ws := fs.String("workspace", ".serrfix", "workspace directory")
	runs := fs.Int("runs", 2000, "libFuzzer -runs value")
	maxSeconds := fs.Int("max-seconds", 5, "libFuzzer max_total_time")
	target := fs.String("target", "fuzz/error_target.cpp", "libFuzzer C++ target")
	dict := fs.String("dict", "fuzz/secret.dict", "libFuzzer dictionary")
	clangxx := fs.String("clangxx", "", "clang++ binary (default: $CLANGXX or clang++)")
	build := fs.Bool("build", true, "rebuild target binary")
	maxSeeds := fs.Int("max-seeds", 256, "maximum SQLite samples copied as seed corpus")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	a, err := app.Open(*ws, out, errOut)
	if err != nil {
		return fail(errOut, err)
	}
	defer a.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := a.Fuzz(ctx, app.FuzzOptions{
		Runs: *runs, MaxSeconds: *maxSeconds, TargetPath: *target,
		DictPath: *dict, ClangXX: *clangxx, Build: *build, MaxSeeds: *maxSeeds,
	})
	if err != nil {
		return fail(errOut, err)
	}
	if *asJSON {
		printJSON(out, result)
	}
	if !*asJSON {
		fmt.Fprintf(out, "fuzz corpus captured: files=%d imported=%d seeds=%d\n",
			result.CorpusFiles, result.ImportedSamples, result.SeedCount)
		fmt.Fprintf(out, "  material=%s bundle=%s sha256=%s\n",
			result.MaterialID, result.BundlePath, result.BundleSHA256)
		fmt.Fprintf(out, "  run_dir=%s manifest=%s log=%s\n",
			result.RunDir, result.ManifestPath, result.LogPath)
		if result.CommandExitError != "" {
			fmt.Fprintf(errOut, "warning: libFuzzer exited with %s; corpus was still preserved\n",
				result.CommandExitError)
		}
	}
	return 0
}

func printRunSummary(out io.Writer, s app.RunSummary) {
	fmt.Fprintf(out, "runs completed=%d passed=%d failed=%d pending=%d paused=%t",
		s.CompletedRuns, s.Passed, s.Failed, s.Pending, s.Paused)
	if s.PauseReason != "" {
		fmt.Fprintf(out, " reason=%s", s.PauseReason)
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "window %s .. %s\n", s.StartedAt, s.FinishedAt)
}

func printVerify(out io.Writer, r app.VerifyReport) {
	status := "PASS"
	if !r.OK {
		status = "FAIL"
	}
	fmt.Fprintf(out, "verify %s accepted_at=%s checks=%d materials=%d samples=%d runs=%d\n",
		status, r.AcceptedAt, len(r.Checks), r.MaterialCount, r.SampleCount, r.RunCount)
	fmt.Fprintf(out, "run window %s .. %s\n", r.FirstRunAt, r.LastRunAt)
	for _, check := range r.Checks {
		if !check.OK {
			fmt.Fprintf(out, "  FAIL %-40s %s\n", check.Name, check.Detail)
		}
	}
	for _, rng := range r.OffsetRanges {
		fmt.Fprintf(out, "  offset %-24s material=%s range=%d+%d sha256=%s\n",
			rng.SampleID, rng.MaterialID, rng.SourceOffset, rng.SourceLength, rng.SourceSHA256)
	}
}

func printReport(out io.Writer, r app.TimelineReport) {
	fmt.Fprintf(out, "timeline generated_at=%s workspace=%s\n", r.GeneratedAt, r.Workspace)
	fmt.Fprintf(out, "original material=%s size=%d captured_at=%s\n",
		r.Material.ID, r.Material.Size, r.Material.CapturedAt)
	fmt.Fprintf(out, "original snapshot=%s sha256=%s\n",
		r.Material.SnapshotPath, r.Material.SHA256)
	fmt.Fprintf(out, "totals samples=%d runs=%d passed=%d failed=%d interrupted=%d comparisons=%d\n",
		r.Totals.Samples, r.Totals.Runs, r.Totals.Passed, r.Totals.Failed,
		r.Totals.Interrupted, r.Totals.Comparisons)
	fmt.Fprintln(out, "samples:")
	for _, sample := range r.Samples {
		fmt.Fprintf(out, "  %-24s %-10s offset=%d+%d runs=%d window=%s..%s leaks=%d/%d\n",
			sample.SampleID, sample.LatestState, sample.SourceOffset, sample.SourceLength,
			sample.RunCount, sample.FirstStartedAt, sample.LastFinishedAt,
			sample.BeforeLeaks, sample.AfterLeaks)
	}
	fmt.Fprintln(out, "events:")
	for _, event := range r.Events {
		fmt.Fprintf(out, "  %-32s %-18s sample=%s run=%s %s\n",
			event.At, event.Kind, event.Sample, event.Run, event.Detail)
	}
}

func printJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func fail(w io.Writer, err error) int {
	fmt.Fprintf(w, "error: %v\n", err)
	return 1
}
