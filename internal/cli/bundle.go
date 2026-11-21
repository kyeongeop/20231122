package cli

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"

	"auditfix/internal/bundle"
	"auditfix/internal/db"
)

func (a *App) exportBundle(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("export", flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	dbPath := flags.String("db", "", "SQLite database path")
	runID := flags.String("run-id", "", "run identifier")
	outDir := flags.String("out", "", "bundle output directory")
	force := flags.Bool("force", false, "replace an existing output directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := a.requireDB(flags, *dbPath); err != nil {
		return err
	}
	if err := requirePath("run-id", *runID); err != nil {
		return err
	}
	if err := requirePath("out", *outDir); err != nil {
		return err
	}
	store, err := db.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	manifest, err := bundle.Export(ctx, store, *runID, *outDir, *force)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "exported case=%s run=%s files=%d events=%d samples=%d attempts=%d\n",
		manifest.CaseID, manifest.RunID, len(manifest.Files),
		manifest.RowCounts.Events, manifest.RowCounts.Samples,
		manifest.RowCounts.Attempts)
	digest, _, err := sha256File(filepath.Join(*outDir, bundle.DigestName))
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "manifest_sha256=%s\ndatabase_sha256=%s\n",
		digest, manifest.Database.SHA256)
	return nil
}

func (a *App) verifyBundle(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	bundleDir := flags.String("bundle", "", "bundle directory")
	rerun := flags.Bool("rerun", false, "rerun every embedded sample")
	harness := flags.String("harness", "", "libFuzzer harness for rerun")
	timeout := flags.Duration("timeout", 0, "override per-sample rerun timeout")
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if err := requirePath("bundle", *bundleDir); err != nil {
		return err
	}
	report, err := bundle.Verify(ctx, *bundleDir, bundle.VerifyOptions{
		Rerun: *rerun, HarnessPath: *harness, Timeout: *timeout,
	})
	if err != nil {
		return err
	}
	if *jsonOutput {
		return printJSON(a.Stdout, report)
	}
	fmt.Fprintf(a.Stdout, "verified bundle=%s case=%s run=%s files=%d rows=%d warnings=%d\n",
		report.Bundle, report.CaseID, report.RunID, report.FilesChecked,
		report.RowsChecked, len(report.Warnings))
	for _, warning := range report.Warnings {
		fmt.Fprintf(a.Stdout, "warning: %s\n", warning)
	}
	for _, result := range report.Rerun {
		status := "ok"
		if !result.OK {
			status = "mismatch"
		}
		fmt.Fprintf(a.Stdout, "rerun\t%d\t%s\t%s\t%s\n",
			result.SampleIndex, result.Name, result.Classification, status)
	}
	return nil
}

func (a *App) restoreBundle(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	bundleDir := flags.String("bundle", "", "bundle directory")
	dbPath := flags.String("db", "", "destination SQLite database")
	force := flags.Bool("force", false, "replace an existing destination database")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := a.requireDB(flags, *dbPath); err != nil {
		return err
	}
	if err := requirePath("bundle", *bundleDir); err != nil {
		return err
	}
	if err := bundle.Restore(ctx, *bundleDir, *dbPath, *force); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "restored bundle=%s db=%s\n", *bundleDir, *dbPath)
	return nil
}
