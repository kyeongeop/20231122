package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"seedreview/internal/evidence"
	"seedreview/internal/manifest"
	"seedreview/internal/replay"
	"seedreview/internal/report"
	"seedreview/internal/store"
)

func runInit(ctx context.Context, args []string, stdout *os.File) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	dbPath := flags.String("db", "var/seedreview.db", "SQLite database path")
	evidencePath := flags.String("evidence", "var/evidence", "evidence directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	database, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer database.Close()
	evidenceStore, err := evidence.New(*evidencePath)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "database=%s\nevidence=%s\n", *dbPath, evidenceStore.Root())
	return nil
}

func runReplay(ctx context.Context, args []string, stdout *os.File) error {
	flags := flag.NewFlagSet("replay", flag.ContinueOnError)
	dbPath := flags.String("db", "var/seedreview.db", "SQLite database path")
	evidencePath := flags.String("evidence", "var/evidence", "evidence directory")
	manifestPath := flags.String("manifest", "", "recovery manifest (legacy v1 or canonical v2)")
	target := flags.String("target", "", "override fuzz target path")
	artifact := flags.String("artifact", "", "override libFuzzer artifact path")
	timeout := flags.Duration("timeout", 15*time.Second, "replay timeout")
	asJSON := flags.Bool("json", false, "print replay result as JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" {
		return fmt.Errorf("--manifest is required")
	}
	parsed, err := manifest.ParseFile(*manifestPath)
	if err != nil {
		return err
	}
	database, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer database.Close()
	evidenceStore, err := evidence.New(*evidencePath)
	if err != nil {
		return err
	}
	engine := replay.New(replay.Options{
		Store: database, Evidence: evidenceStore, Manifest: parsed,
		TargetOverride: *target, ArtifactOverride: *artifact, Timeout: *timeout,
	})
	result, err := engine.Run(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(stdout, "run=%d status=%s failure=%s\n",
			result.RunID, result.Status, result.FailureCode)
		fmt.Fprintln(stdout, "next: seedreview report --db", *dbPath,
			"--evidence", *evidencePath, "--run", result.RunID)
	}
	if result.Status != "ok" {
		return fmt.Errorf("replay finished with status %s", result.Status)
	}
	return nil
}

func runReport(ctx context.Context, args []string, stdout *os.File) error {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	dbPath := flags.String("db", "var/seedreview.db", "SQLite database path")
	evidencePath := flags.String("evidence", "var/evidence", "evidence directory")
	runID := flags.Int64("run", 0, "run id; 0 selects the latest")
	format := flags.String("format", "markdown", "markdown, json, or legacy-json")
	if err := flags.Parse(args); err != nil {
		return err
	}
	database, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer database.Close()
	evidenceStore, err := evidence.New(*evidencePath)
	if err != nil {
		return err
	}
	if *runID == 0 {
		*runID, err = database.LatestRunID(ctx)
		if err != nil {
			return fmt.Errorf("select latest run: %w", err)
		}
	}
	built, err := report.Build(ctx, database, evidenceStore, *runID)
	if err != nil {
		return err
	}
	switch *format {
	case "markdown":
		fmt.Fprint(stdout, report.Markdown(built))
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(built); err != nil {
			return err
		}
	case "legacy-json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report.Legacy(built)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported report format %q", *format)
	}
	if !built.Automatic.EvidenceIntegrity.OK {
		return fmt.Errorf("evidence integrity check failed")
	}
	return nil
}

func runManual(ctx context.Context, args []string, stdout *os.File) error {
	flags := flag.NewFlagSet("manual", flag.ContinueOnError)
	dbPath := flags.String("db", "var/seedreview.db", "SQLite database path")
	runID := flags.Int64("run", 0, "run id")
	check := flags.String("check", "", "manual check code")
	status := flags.String("status", "", "pending, confirmed, or rejected")
	owner := flags.String("owner", "", "reviewer")
	notes := flags.String("notes", "", "review notes")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *runID == 0 || *check == "" || *status == "" {
		return fmt.Errorf("--run, --check, and --status are required")
	}
	database, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.SetManualCheck(ctx, *runID, *check, *status, *owner, *notes); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "run=%d check=%s status=%s owner=%s\n",
		*runID, *check, *status, *owner)
	return nil
}

func runVerify(ctx context.Context, args []string, stdout *os.File) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	dbPath := flags.String("db", "var/seedreview.db", "SQLite database path")
	evidencePath := flags.String("evidence", "var/evidence", "evidence directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	database, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer database.Close()
	evidenceStore, err := evidence.New(*evidencePath)
	if err != nil {
		return err
	}
	records, err := database.AllEvidence(ctx)
	if err != nil {
		return err
	}
	failures := 0
	for _, record := range records {
		status := "ok"
		if err := evidenceStore.Verify(record); err != nil {
			status = "FAIL " + err.Error()
			failures++
		}
		fmt.Fprintf(stdout, "%s %s %s\n", record.SHA256, record.Kind, status)
	}
	fmt.Fprintf(stdout, "checked=%d failures=%d\n", len(records), failures)
	if failures > 0 {
		return fmt.Errorf("%d evidence records failed verification", failures)
	}
	return nil
}
