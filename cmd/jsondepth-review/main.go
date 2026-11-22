// Command jsondepth-review runs the reviewable JSON deep-nesting
// workflow: it processes snapshot files (legacy v1 and current v2
// JSONL formats), records evidence for every object into SQLite, and
// prints a report mapping attack input -> trigger location ->
// permission decision -> log evidence. Temporary quarantine state is
// removed when the run ends.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"jsondepth-review/internal/batch"
	"jsondepth-review/internal/evidence"
)

func main() {
	var (
		dbPath   = flag.String("db", "evidence.db", "SQLite evidence database path")
		maxDepth = flag.Int("max-depth", 128, "JSON nesting depth limit")
		keepDB   = flag.Bool("keep-db", true, "keep the evidence database after the run")
	)
	flag.Parse()
	snapshots := flag.Args()
	if len(snapshots) == 0 {
		fmt.Fprintln(os.Stderr, "usage: jsondepth-review [flags] snapshot1.jsonl [snapshot2.jsonl ...]")
		os.Exit(2)
	}
	if err := run(context.Background(), *dbPath, *maxDepth, *keepDB, snapshots); err != nil {
		log.Fatalf("run failed: %v", err)
	}
}

func run(ctx context.Context, dbPath string, maxDepth int, keepDB bool, snapshots []string) error {
	logger := log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)

	store, err := evidence.Open(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	if !keepDB {
		defer os.Remove(dbPath)
	}

	proc, err := batch.New(store, maxDepth, logger)
	if err != nil {
		return err
	}
	quarantineDir := proc.QuarantineDir()
	defer func() {
		// End-of-run cleanup of all temporary state.
		if err := proc.Close(); err != nil {
			logger.Printf("cleanup warning: %v", err)
		}
		if _, statErr := os.Stat(quarantineDir); os.IsNotExist(statErr) {
			logger.Printf("cleanup verified: temp quarantine dir %s removed", quarantineDir)
		}
	}()

	for _, path := range snapshots {
		label := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		sum, err := proc.ProcessFile(ctx, label, path)
		if err != nil {
			return fmt.Errorf("snapshot %s: %w", path, err)
		}
		logger.Printf("snapshot %s done: total=%d allowed=%d denied=%d",
			label, sum.Total, sum.Allowed, sum.Denied)
	}

	entries, err := store.List(ctx)
	if err != nil {
		return err
	}
	printReport(os.Stdout, entries)
	return nil
}

func printReport(w *os.File, entries []evidence.Entry) {
	fmt.Fprintln(w, "=== JSON deep-nesting review report ===")
	fmt.Fprintf(w, "%-14s %-5s %-6s %-18s %-18s %-30s %s\n",
		"snapshot:line", "fmt", "record", "decision", "trigger", "location", "input(sha256)")
	for _, e := range entries {
		rec := e.RecordID
		if rec == "" {
			rec = "-"
		}
		loc := e.Location
		if len(loc) > 30 {
			loc = loc[:27] + "..."
		}
		fmt.Fprintf(w, "%-14s %-5s %-6s %-18s %-18s %-30s %s\n",
			fmt.Sprintf("%s:%d", e.Snapshot, e.LineNo), e.Format, rec,
			e.Decision, e.Trigger, loc, e.InputHash[:12])
	}
	fmt.Fprintln(w)
	for _, e := range entries {
		if e.Decision == "allow" {
			continue
		}
		fmt.Fprintf(w, "--- evidence %s:%d (%s) ---\n", e.Snapshot, e.LineNo, e.Decision)
		fmt.Fprintf(w, "input sha256 : %s (len=%d)\n", e.InputHash, e.InputLen)
		fmt.Fprintf(w, "input head   : %s\n", e.InputHead)
		fmt.Fprintf(w, "trigger      : %s @ %s\n", e.Trigger, e.Location)
		fmt.Fprintf(w, "log evidence :\n")
		for _, line := range strings.Split(e.LogExcerpt, "\n") {
			fmt.Fprintf(w, "  | %s\n", line)
		}
		fmt.Fprintln(w)
	}
}
