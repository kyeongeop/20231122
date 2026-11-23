package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"oauthreview/internal/evidence"
	"oauthreview/internal/report"
	"oauthreview/internal/runner"
)

const defaultDB = "reports/evidence.db"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "replay":
		err = cmdReplay(os.Args[2:])
	case "review":
		err = cmdReview(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: oauthreview <replay|review|report> [flags]")
}

func cmdReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	corpus := fs.String("corpus", "fuzz/seed", "corpus directory")
	dbPath := fs.String("db", defaultDB, "SQLite evidence database path")
	caseID := fs.String("case", "", "replay a single case_id (default: all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	files, err := filepath.Glob(filepath.Join(*corpus, "*.json"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no corpus files under %s", *corpus)
	}
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		return err
	}
	store, err := evidence.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	expect := report.Expectation{}
	var failures []string
	for _, path := range files {
		env, err := runner.LoadEnvelope(path)
		if err != nil {
			return err
		}
		if *caseID != "" && env.CaseID != *caseID {
			continue
		}
		expect[env.CaseID] = env.Expect
		out, err := runner.Replay(store, env)
		if err != nil {
			if strings.Contains(err.Error(), evidence.ErrCaseExists.Error()) {
				fmt.Printf("SKIP  %-24s evidence already retained\n", env.CaseID)
				continue
			}
			if strings.Contains(err.Error(), "parse failed") {
				fmt.Printf("DENY  %-24s parse failure (evidence retained)\n", env.CaseID)
				if env.Expect != "DENY" {
					failures = append(failures, env.CaseID)
				}
				continue
			}
			return err
		}
		match := "ok"
		if env.Expect != "" && env.Expect != string(out.Decision.Verdict) {
			match = "MISMATCH want=" + env.Expect
			failures = append(failures, env.CaseID)
		}
		fmt.Printf("%-5s %-24s stage=%-18s rule=%s %s\n",
			out.Decision.Verdict, env.CaseID, out.TriggerPoint, out.PermissionLog, match)
	}
	if len(failures) > 0 {
		return fmt.Errorf("expectation mismatches: %s", strings.Join(failures, ","))
	}
	return nil
}

func cmdReview(args []string) error {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	dbPath := fs.String("db", defaultDB, "SQLite evidence database path")
	caseID := fs.String("case", "", "case_id to review (required)")
	reviewer := fs.String("reviewer", "", "reviewer name (required)")
	confirm := fs.Bool("confirm", false, "confirm the automatic verdict")
	reject := fs.Bool("reject", false, "reject the automatic verdict")
	notes := fs.String("notes", "", "review notes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caseID == "" || *reviewer == "" || (*confirm == *reject) {
		return fmt.Errorf("require --case, --reviewer and exactly one of --confirm/--reject")
	}
	store, err := evidence.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.SaveReview(*caseID, *reviewer, *confirm, *notes); err != nil {
		return err
	}
	fmt.Printf("review saved: case=%s reviewer=%s confirmed=%v\n", *caseID, *reviewer, *confirm)
	return nil
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	dbPath := fs.String("db", defaultDB, "SQLite evidence database path")
	corpus := fs.String("corpus", "fuzz/seed", "corpus directory (for expectations)")
	outPath := fs.String("out", "reports/review-report.md", "markdown output path")
	fuzzLog := fs.String("fuzz-log", "reports/fuzz-summary.txt", "libFuzzer summary file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := evidence.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	rows, err := store.ListCases()
	if err != nil {
		return err
	}
	expect := report.Expectation{}
	if entries, err := filepath.Glob(filepath.Join(*corpus, "*.json")); err == nil {
		for _, path := range entries {
			if env, err := runner.LoadEnvelope(path); err == nil {
				expect[env.CaseID] = env.Expect
			}
		}
	}
	summary := ""
	if data, err := os.ReadFile(*fuzzLog); err == nil {
		summary = string(data)
	}
	md := report.BuildMarkdown(rows, expect, summary)
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*outPath, []byte(md), 0o644); err != nil {
		return err
	}
	meta, _ := json.Marshal(map[string]int{"cases": len(rows)})
	fmt.Printf("report written: %s %s\n", *outPath, meta)
	return nil
}
