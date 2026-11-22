package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"example.com/replay-review/internal/export"
	"example.com/replay-review/internal/model"
	"example.com/replay-review/internal/pipeline"
	"example.com/replay-review/internal/review"
	"example.com/replay-review/internal/store"
)

const deterministicNow = int64(1_700_001_000_000)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "export":
		err = cmdExport(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "compare":
		err = cmdCompare(os.Args[2:])
	case "gen-fixture":
		err = cmdGenFixture(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "replayctl: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `replayctl - verification-code replay detection with pausable processing

Usage:
  replayctl gen-fixture --out FILE
  replayctl run --input FILE --db FILE [--max-events N] [--max-issues N]
                [--pause-segment N]
  replayctl export --db FILE --out DIR [--config FILE]
  replayctl verify --bundle DIR
  replayctl compare --before DIR --after DIR
`)
}

func cmdGenFixture(args []string) error {
	fs := flag.NewFlagSet("gen-fixture", flag.ContinueOnError)
	out := fs.String("out", "testdata/fixture.json", "fixture output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return pipeline.WriteFixture(*out, model.DefaultConfig())
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	input := fs.String("input", "testdata/fixture.json", "input stream JSON")
	dbPath := fs.String("db", "artifacts/evidence.sqlite", "evidence database")
	maxEvents := fs.Int("max-events", 0, "per-segment event budget; 0 = unlimited")
	maxIssues := fs.Int("max-issues", 0, "in-memory issue cache limit; 0 = default")
	pauseSegment := fs.Int64("pause-segment", 0,
		"inject a deterministic pause before this segment id (fault drill)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	in, err := pipeline.LoadInput(*input)
	if err != nil {
		return err
	}
	cfg := resolveConfig(in.Config, *maxEvents, *maxIssues)
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		return err
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	p := pipeline.New(cfg, st, in.Events, func() int64 { return deterministicNow })
	if *pauseSegment > 0 {
		p.WithFaultPlan(pipeline.FaultPlan{
			PauseAfterSegment: *pauseSegment,
			PauseReason:       model.PauseFaultInjected,
		})
	}
	report, err := p.Run()
	if err != nil {
		return err
	}
	printReport(report)
	remaining, err := p.Remaining()
	if err != nil {
		return err
	}
	fmt.Printf("remaining_events=%d degraded=%v db=%s\n",
		remaining, report.Degraded, *dbPath)
	return nil
}

func resolveConfig(in *model.Config, maxEvents, maxIssues int) model.Config {
	cfg := model.DefaultConfig()
	if in != nil {
		cfg = *in
	}
	if maxEvents > 0 {
		cfg.MaxEvents = maxEvents
	}
	if maxIssues > 0 {
		cfg.MaxTrackedIssues = maxIssues
	}
	return cfg
}

func printReport(r pipeline.SegmentReport) {
	fmt.Printf("segment=%d paused=%v reason=%s processed=%d decisions=%d gaps=%d errors=%d\n",
		r.SegmentID, r.Paused, r.Reason, r.Result.Processed,
		len(r.Result.Decisions), len(r.Result.Gaps), len(r.Result.Errors))
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	dbPath := fs.String("db", "artifacts/evidence.sqlite", "evidence database")
	outDir := fs.String("out", "artifacts/review", "bundle output directory")
	configPath := fs.String("config", "", "optional config JSON embedded in manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	events, err := st.LoadEvents()
	if err != nil {
		return err
	}
	decisions, err := st.LoadDecisions()
	if err != nil {
		return err
	}
	gaps, err := st.LoadGaps()
	if err != nil {
		return err
	}
	checkpoints, err := st.LoadCheckpoints()
	if err != nil {
		return err
	}
	replays, err := st.CountReplay()
	if err != nil {
		return err
	}
	degraded, err := st.Degraded()
	if err != nil {
		return err
	}

	toAny := func(n int, at func(i int) any) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = at(i)
		}
		return out
	}
	bundle := export.Bundle{
		Events: toAny(len(events), func(i int) any { return events[i] }),
		Decisions: toAny(len(decisions), func(i int) any {
			return decisions[i]
		}),
		Gaps: toAny(len(gaps), func(i int) any { return gaps[i] }),
		Checkpoints: toAny(len(checkpoints), func(i int) any {
			return checkpoints[i]
		}),
		ReplayCount: replays,
		Degraded:    degraded,
		CreatedAtMs: deterministicNow,
	}
	if *configPath != "" {
		raw, err := os.ReadFile(*configPath)
		if err != nil {
			return err
		}
		bundle.Config = raw
	} else {
		raw, _ := json.Marshal(model.DefaultConfig())
		bundle.Config = raw
	}
	manifest, err := export.Write(*outDir, bundle)
	if err != nil {
		return err
	}
	fmt.Printf("exported bundle: %s (events=%d decisions=%d replays=%d gaps=%d checkpoints=%d)\n",
		*outDir, manifest.EventCount, manifest.DecisionCount,
		manifest.ReplayCount, manifest.GapCount, manifest.CheckpointCount)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	dir := fs.String("bundle", "artifacts/review", "exported bundle directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	manifest, err := review.VerifyBundle(*dir)
	if err != nil {
		return err
	}
	fmt.Printf("bundle OK: %d events, %d decisions (%d replays), %d gaps, %d checkpoints, degraded=%v\n",
		manifest.EventCount, manifest.DecisionCount, manifest.ReplayCount,
		manifest.GapCount, manifest.CheckpointCount, manifest.Degraded)
	return nil
}

func cmdCompare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	before := fs.String("before", "", "bundle directory from the pre-pause run")
	after := fs.String("after", "", "bundle directory from the resumed run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *before == "" || *after == "" {
		return fmt.Errorf("--before and --after are required")
	}
	beforeDec, err := review.LoadJSONL[review.ReplayRow](
		filepath.Join(*before, export.FileDecisions))
	if err != nil {
		return err
	}
	afterDec, err := review.LoadJSONL[review.ReplayRow](
		filepath.Join(*after, export.FileDecisions))
	if err != nil {
		return err
	}
	if err := review.CompareDecisions(beforeDec, afterDec); err != nil {
		return fmt.Errorf("decision mismatch: %w", err)
	}
	beforeGaps, err := review.LoadJSONL[model.Gap](
		filepath.Join(*before, export.FileGaps))
	if err != nil {
		return err
	}
	afterGaps, err := review.LoadJSONL[model.Gap](
		filepath.Join(*after, export.FileGaps))
	if err != nil {
		return err
	}
	if err := review.CompareGaps(beforeGaps, afterGaps); err != nil {
		return fmt.Errorf("gap mismatch: %w", err)
	}
	fmt.Printf("runs equivalent: %d decisions and %d gaps match in field values and order\n",
		len(beforeDec), len(beforeGaps))
	return nil
}
