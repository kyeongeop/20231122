package main

import (
	"flag"
	"fmt"
	"os"

	"depthlab/internal/experiment"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		runCommand(os.Args[2:])
	case "verify":
		verifyCommand(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  depthlab run --fuzz-record PATH [--out DIR] [--limit N]
  depthlab verify [--db PATH] [--report PATH] [--manifest PATH]`)
}

func runCommand(args []string) {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	out := flags.String("out", "artifacts", "evidence output directory")
	fuzzRecord := flags.String("fuzz-record", "", "libFuzzer crash artifact to truncate")
	limit := flags.Int("limit", 4, "maximum allowed GraphQL query depth")
	if err := flags.Parse(args); err != nil {
		os.Exit(2)
	}
	report, err := experiment.Execute(experiment.Options{
		OutDir: *out, FuzzRecordPath: *fuzzRecord, Limit: *limit,
	})
	if err != nil {
		fatal(err)
	}
	for _, run := range report.Runs {
		if run.FirstError == nil {
			fmt.Printf("%s: no failure\n", run.RunID)
			continue
		}
		fmt.Printf("%s: first error seq=%d stage=%s code=%s\n", run.RunID,
			run.FirstError.Seq, run.FirstError.Stage, run.FirstError.Code)
	}
	for _, check := range report.Checks {
		first := "none"
		if check.FirstError != nil {
			first = fmt.Sprintf("seq=%d stage=%s code=%s", check.FirstError.Seq,
				check.FirstError.Stage, check.FirstError.Code)
		}
		fmt.Printf("%s: %s (%s)\n", check.CheckID, check.Status, first)
	}
	fmt.Printf("wrote %s\n", *out)
}

func verifyCommand(args []string) {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	db := flags.String("db", "artifacts/evidence.sqlite", "SQLite evidence database")
	report := flags.String("report", "artifacts/report.json", "experiment report")
	manifest := flags.String("manifest", "artifacts/manifest.sha256", "artifact manifest")
	if err := flags.Parse(args); err != nil {
		os.Exit(2)
	}
	message, err := experiment.Verify(*db, *report, *manifest)
	if err != nil {
		fatal(err)
	}
	fmt.Println(message)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "depthlab:", err)
	os.Exit(1)
}
