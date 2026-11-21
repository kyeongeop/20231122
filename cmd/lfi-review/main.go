// Command lfi-review ingests LFI evidence objects from a legacy v1 snapshot
// and a current v2 snapshot, correlates them in SQLite and prints a
// reviewer-friendly report. Truncated records are recovered and flagged;
// malformed objects are reported but never stop the remaining work.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"lfireview/internal/model"
	"lfireview/internal/pipeline"
)

func main() {
	var (
		v1Dir   = flag.String("v1", "snapshots/v1_legacy", "legacy v1 snapshot directory")
		v2Dir   = flag.String("v2", "snapshots/v2_current", "current v2 snapshot directory")
		dbPath  = flag.String("db", "artifacts/review.sqlite", "SQLite output path (empty = temp DB, deleted after run)")
		verbose = flag.Bool("v", false, "print per-object results")
	)
	flag.Parse()

	ctx := context.Background()
	report, err := pipeline.Run(ctx, pipeline.Config{
		SnapshotV1: *v1Dir,
		SnapshotV2: *v2Dir,
		DBPath:     *dbPath,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "lfi-review: fatal: %v\n", err)
		os.Exit(2)
	}

	printReport(report, *verbose)
}

func printReport(r *pipeline.Report, verbose bool) {
	fmt.Printf("run id          : %s\n", r.RunID)
	fmt.Printf("snapshots       : v1=%s v2=%s\n", r.Snapshots["v1"], r.Snapshots["v2"])
	fmt.Printf("database        : %s (temp=%t)\n", r.DBPath, r.TempDB)
	fmt.Printf("objects         : total=%d failed=%d truncated=%d\n",
		r.Total, r.Failed, r.TruncatedN)

	if verbose {
		fmt.Println("\nper-object results:")
		for _, res := range r.Results {
			note := res.Error
			if note == "" {
				note = "-"
			}
			fmt.Printf("  [%s] %-28s %-9s %s\n", res.Version, res.Object, res.Status, note)
		}
	}

	fmt.Println("\ntruncated records (retained for review):")
	if len(r.Truncated) == 0 {
		fmt.Println("  none")
	}
	for _, t := range r.Truncated {
		fmt.Printf("  %s  %s/%s\n", t.CorrelationID, t.Version, t.SourceObject)
		fmt.Printf("    reason   : %s\n", t.ParseError)
		fmt.Printf("    attack   : %s\n", dash(t.Recovered["attack_input"]))
		fmt.Printf("    trigger  : %s:%s\n", dash(t.Recovered["trigger_file"]),
			dash(t.Recovered["trigger_line"]))
		fmt.Printf("    decision : %s\n", dash(t.Recovered["permission_decision"]))
		fmt.Printf("    log      : %s:%s\n", dash(t.Recovered["log_path"]),
			dash(t.Recovered["log_line"]))
	}

	fmt.Println("\ncleanup:")
	if len(r.CleanedUp) == 0 {
		fmt.Println("  no temporary state")
	}
	for _, p := range r.CleanedUp {
		fmt.Printf("  removed %s\n", p)
	}

	status := "OK"
	for _, res := range r.Results {
		if res.Status == model.StatusMalformed {
			status = "COMPLETED_WITH_ERRORS"
			break
		}
	}
	fmt.Printf("\nresult: %s\n", status)
}

func dash(s string) string {
	if s == "" || s == "0" {
		return "-"
	}
	return s
}
