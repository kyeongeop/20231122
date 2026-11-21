package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"pathaliaslab/internal/experiment"
	"pathaliaslab/internal/ledger"
	"pathaliaslab/internal/report"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "run":
		return runExperiment(args[1:])
	case "verify":
		return verify(args[1:])
	case "show":
		return show(args[1:])
	case "report":
		return writeReport(args[1:])
	default:
		usage()
		return 2
	}
}

func runExperiment(args []string) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	dbPath := flags.String("db", "artifacts/experiment.db", "SQLite evidence database")
	keep := flags.Bool("keep", false, "append to an existing database")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if !*keep {
		if err := removeDatabase(*dbPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	store, err := ledger.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer store.Close()

	runs, global, err := experiment.ExecuteAll(store)
	if err != nil {
		fmt.Fprintln(os.Stderr, "experiment failed:", err)
		return 1
	}
	passed := true
	for _, outcome := range runs {
		status := "PASS"
		if !outcome.Passed {
			status = "FAIL"
			passed = false
		}
		fmt.Printf("%-4s %-24s steps=%d resolution=%s\n", status, outcome.RunID, len(outcome.Steps), short(outcome.ResolutionDigest))
	}
	for _, check := range global {
		status := "PASS"
		if !check.Passed {
			status = "FAIL"
			passed = false
		}
		fmt.Printf("%-4s %-24s %s\n", status, check.RunID, check.CheckName)
	}
	if !passed {
		fmt.Println("automatic checks failed; inspect with: go run ./cmd/pathaliaslab verify --db " + *dbPath)
		return 1
	}
	fmt.Println("automatic checks passed; run report generation after the libFuzzer smoke test")
	return 0
}

func verify(args []string) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	dbPath := flags.String("db", "artifacts/experiment.db", "SQLite evidence database")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	store, err := ledger.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer store.Close()

	runs, err := store.Runs()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	passed := true
	for _, run := range runs {
		if err := store.VerifyEvidenceChain(run.RunID); err != nil {
			fmt.Printf("FAIL %-24s %v\n", run.RunID, err)
			passed = false
		} else {
			fmt.Printf("PASS %-24s chain=%s\n", run.RunID, short(run.EventSHA256))
		}
	}
	integrity, err := store.IntegrityCheck()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, message := range integrity {
		fmt.Println("sqlite:", message)
		if message != "ok" {
			passed = false
		}
	}
	checks, err := store.Checks()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	failed := 0
	for _, check := range checks {
		if !check.Passed {
			failed++
			fmt.Printf("FAIL check %s/%s expected=%s actual=%s\n",
				check.RunID, check.CheckName, check.Expected, check.Actual)
		}
	}
	if failed > 0 {
		passed = false
	}
	if !passed {
		return 1
	}
	fmt.Printf("verification passed: %d runs, %d checks\n", len(runs), len(checks))
	return 0
}

func show(args []string) int {
	flags := flag.NewFlagSet("show", flag.ContinueOnError)
	dbPath := flags.String("db", "artifacts/experiment.db", "SQLite evidence database")
	runID := flags.String("run", "primary_cancel", "run id")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	store, err := ledger.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer store.Close()
	record, err := store.Run(*runID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	steps, err := store.Steps(*runID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	payload := struct {
		Run   ledger.RunRecord    `json:"run"`
		Steps []ledger.StepRecord `json:"steps"`
	}{Run: record, Steps: steps}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func writeReport(args []string) int {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	dbPath := flags.String("db", "artifacts/experiment.db", "SQLite evidence database")
	artifactDir := flags.String("artifacts", "artifacts", "artifact directory")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	store, err := ledger.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer store.Close()
	result, err := report.Generate(store, *dbPath, *artifactDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("%s report=%s/%s\n", result.OverallStatus,
		*artifactDir, "report.md")
	if result.OverallStatus != "PASS" {
		return 1
	}
	return 0
}

func removeDatabase(path string) error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return nil
}

func short(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pathaliaslab <run|verify|show> [flags]")
}
