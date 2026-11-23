package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"example.com/deserialize-boundary/internal/experiment"
	"example.com/deserialize-boundary/internal/ledger"
	"example.com/deserialize-boundary/internal/report"
)

const (
	defaultDB      = "artifacts/evidence/experiment.db"
	defaultOut     = "artifacts/evidence"
	defaultReport  = "artifacts"
	defaultReplay  = "artifacts/evidence/replay.db"
	defaultCorpus  = "artifacts/evidence/fuzz/corpus"
	defaultFuzzLog = "artifacts/evidence/fuzz/fuzzer.log"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(ctx, os.Args[2:])
	case "seed":
		err = cmdSeed(os.Args[2:])
	case "ingest-fuzz":
		err = cmdIngestFuzz(ctx, os.Args[2:])
	case "fuzz-stats":
		err = cmdFuzzStats(ctx, os.Args[2:])
	case "replay":
		err = cmdReplay(ctx, os.Args[2:])
	case "report":
		err = cmdReport(ctx, os.Args[2:])
	case "manifest":
		err = cmdManifest(os.Args[2:])
	case "verify-manifest":
		err = cmdVerifyManifest(os.Args[2:])
	case "query":
		err = cmdQuery(ctx, os.Args[2:])
	case "record-check":
		err = cmdRecordCheck(ctx, os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: dfexp <run|seed|ingest-fuzz|fuzz-stats|replay|report|manifest|verify-manifest|query|record-check> [flags]`)
}

func cmdRun(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("run", flag.ExitOnError)
	dbPath := flags.String("db", defaultDB, "SQLite experiment database")
	outDir := flags.String("out", defaultOut, "evidence output directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	db, err := ledger.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	runner := &experiment.Runner{Ledger: db, OutDir: *outDir}
	results, runErr := runner.RunCore(ctx)
	checker := &experiment.Checker{Ledger: db}
	checks, checkErr := checker.EvaluateCore(ctx)
	if checkErr != nil {
		return checkErr
	}
	printJSON(map[string]any{"runs": results, "checks": checks})
	return runErr
}

func cmdSeed(args []string) error {
	flags := flag.NewFlagSet("seed", flag.ExitOnError)
	outDir := flags.String("out", defaultCorpus, "seed corpus directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := experiment.SeedCorpus(*outDir); err != nil {
		return err
	}
	fmt.Printf("seed corpus written to %s\n", *outDir)
	return nil
}

func cmdIngestFuzz(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("ingest-fuzz", flag.ExitOnError)
	dbPath := flags.String("db", defaultDB, "SQLite experiment database")
	corpusDir := flags.String("corpus", defaultCorpus, "retained libFuzzer corpus")
	outDir := flags.String("out", defaultOut, "evidence output directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	db, err := ledger.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	summary, err := (&experiment.Checker{Ledger: db}).IngestCorpus(ctx, *corpusDir, *outDir)
	if err != nil {
		return err
	}
	printJSON(summary)
	return nil
}

func cmdFuzzStats(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("fuzz-stats", flag.ExitOnError)
	dbPath := flags.String("db", defaultDB, "SQLite experiment database")
	logPath := flags.String("log", defaultFuzzLog, "libFuzzer log")
	artifactDir := flags.String("artifacts", "artifacts/evidence/fuzz", "libFuzzer artifact directory")
	corpusDir := flags.String("corpus", defaultCorpus, "retained libFuzzer corpus")
	if err := flags.Parse(args); err != nil {
		return err
	}
	db, err := ledger.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	stats, err := (&experiment.Checker{Ledger: db}).IngestFuzzLog(ctx, *logPath, *artifactDir, *corpusDir)
	if err != nil {
		return err
	}
	printJSON(stats)
	return nil
}

func cmdReplay(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("replay", flag.ExitOnError)
	sourcePath := flags.String("source", defaultDB, "source SQLite database")
	destPath := flags.String("dest", defaultReplay, "replay SQLite database")
	outDir := flags.String("out", defaultOut, "evidence output directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	source, err := ledger.Open(*sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	_ = os.Remove(*destPath)
	_ = os.Remove(*destPath + "-wal")
	_ = os.Remove(*destPath + "-shm")
	dest, err := ledger.Open(*destPath)
	if err != nil {
		return err
	}
	defer dest.Close()
	results, err := experiment.ReplayCore(ctx, source, dest, *outDir)
	if err != nil {
		return err
	}
	printJSON(results)
	return nil
}

func cmdReport(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("report", flag.ExitOnError)
	dbPath := flags.String("db", defaultDB, "SQLite experiment database")
	evidenceDir := flags.String("evidence", defaultOut, "evidence directory")
	outDir := flags.String("out", defaultReport, "report output directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	db, err := ledger.OpenReadOnly(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	generated, err := report.Generate(ctx, db, *dbPath, *evidenceDir, *outDir)
	if err != nil {
		return err
	}
	fmt.Printf("report verdict: %s (passed=%d failed=%d)\n",
		generated.Automated.Verdict, generated.Automated.Passed, generated.Automated.Failed)
	if generated.Automated.Verdict != "PASS" {
		return fmt.Errorf("automated checks failed; see %s/report.md", *outDir)
	}
	return nil
}

func cmdManifest(args []string) error {
	flags := flag.NewFlagSet("manifest", flag.ExitOnError)
	dir := flags.String("dir", defaultOut, "evidence directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	entries, err := report.WriteManifest(*dir)
	if err != nil {
		return err
	}
	fmt.Printf("manifest written: %d entries\n", len(entries))
	return nil
}

func cmdVerifyManifest(args []string) error {
	flags := flag.NewFlagSet("verify-manifest", flag.ExitOnError)
	dir := flags.String("dir", defaultOut, "evidence directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	total, problems, err := report.VerifyManifest(*dir)
	if err != nil {
		return err
	}
	if total == 0 || len(problems) > 0 {
		return fmt.Errorf("manifest verification failed: entries=%d problems=%s", total, strings.Join(problems, "; "))
	}
	fmt.Printf("manifest verified: %d entries\n", total)
	return nil
}

func cmdQuery(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("query", flag.ExitOnError)
	dbPath := flags.String("db", defaultDB, "SQLite database")
	query := flags.String("sql", "", "read-only SQL query")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*query) == "" {
		return errors.New("--sql is required")
	}
	db, err := ledger.OpenReadOnly(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	columns, rows, err := db.Query(ctx, *query)
	if err != nil {
		return err
	}
	fmt.Println(strings.Join(columns, "\t"))
	for _, row := range rows {
		fmt.Println(strings.Join(row, "\t"))
	}
	return nil
}

func cmdRecordCheck(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("record-check", flag.ExitOnError)
	dbPath := flags.String("db", defaultDB, "SQLite experiment database")
	id := flags.String("id", "", "check id")
	category := flags.String("category", "external", "check category")
	passed := flags.Bool("passed", false, "check result")
	expected := flags.String("expected", "", "expected condition")
	observed := flags.String("observed", "", "observed result")
	evidence := flags.String("evidence", "", "evidence path")
	detail := flags.String("detail", "", "detail")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return errors.New("--id is required")
	}
	db, err := ledger.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.PutCheck(ctx, ledger.Check{
		ID: *id, Category: *category, Passed: *passed,
		Expected: *expected, Observed: *observed, Evidence: *evidence, Detail: *detail,
	})
}

func printJSON(value any) {
	data, _ := json.MarshalIndent(value, "", "  ")
	fmt.Println(string(data))
}
