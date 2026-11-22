package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"cacheleak.local/experiment/internal/audit"
	"cacheleak.local/experiment/internal/experiment"
	"cacheleak.local/experiment/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run", "replay":
		err = runCommand(os.Args[2:])
	case "report":
		err = reportCommand(os.Args[2:])
	case "verify":
		err = verifyCommand(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runCommand(args []string) error {
	defaults := experiment.DefaultOptions()
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	workspace := flags.String("workspace", defaults.Workspace, "workspace containing evidence.db and sealed evidence")
	runID := flags.String("run-id", "", "stable run identifier; generated when omitted")
	fuzzMode := flags.String("fuzz", defaults.FuzzMode, "libFuzzer mode: auto, run, or skip")
	fuzzRuns := flags.Int("fuzz-runs", defaults.FuzzRuns, "libFuzzer mutation budget")
	clangxx := flags.String("clangxx", "", "clang++ executable (defaults to PATH lookup)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	summary, err := experiment.Run(context.Background(), experiment.Options{
		Workspace: *workspace,
		RunID:     *runID,
		FuzzMode:  *fuzzMode,
		FuzzRuns:  *fuzzRuns,
		ClangXX:   *clangxx,
	})
	if err != nil {
		return err
	}
	printJSON(summary)
	return nil
}

func reportCommand(args []string) error {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	workspace := flags.String("workspace", "evidence", "workspace containing evidence.db")
	dbPath := flags.String("db", "", "explicit SQLite database path")
	runID := flags.String("run-id", "", "run identifier; defaults to latest")
	if err := flags.Parse(args); err != nil {
		return err
	}
	st, err := store.Open(context.Background(), audit.ResolveDB(*workspace, *dbPath))
	if err != nil {
		return err
	}
	defer st.Close()
	if *runID == "" {
		*runID, err = st.LatestRunID(context.Background())
		if err != nil {
			return err
		}
	}
	summary, err := st.LoadSummary(context.Background(), *runID)
	if err != nil {
		return err
	}
	printJSON(summary)
	return nil
}

func verifyCommand(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	workspace := flags.String("workspace", "evidence", "workspace containing evidence.db")
	dbPath := flags.String("db", "", "explicit SQLite database path")
	runID := flags.String("run-id", "", "run identifier; defaults to latest")
	if err := flags.Parse(args); err != nil {
		return err
	}
	report, err := audit.Verify(context.Background(), audit.ResolveDB(*workspace, *dbPath), *runID)
	if err != nil {
		return err
	}
	printJSON(report)
	if !report.OK {
		return fmt.Errorf("audit failed for run %s", report.RunID)
	}
	return nil
}

func printJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}

func usage() {
	name := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, `%s - replayable static-file cache leak experiment

Commands:
  run     execute both snapshot controls, order/repeat/error scenarios, libFuzzer, cleanup
  replay  alias for run
  report  print the latest SQLite run summary
  verify  independently re-hash evidence and audit cache invariants

Examples:
  %s run --workspace evidence
  %s report --workspace evidence
  %s verify --workspace evidence
`, name, name, name, name)
}
