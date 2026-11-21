package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"auditfix/internal/model"
)

type App struct {
	Stdout io.Writer
	Stderr io.Writer
}

func New() *App {
	return &App{Stdout: os.Stdout, Stderr: os.Stderr}
}

func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.printUsage()
		return 2
	}
	var err error
	switch args[0] {
	case "version", "--version":
		fmt.Fprintf(a.Stdout, "auditfix %s schema=%s\n", model.ToolVersion, model.SchemaVersion)
	case "case":
		err = a.runCase(ctx, args[1:])
	case "sample":
		err = a.runSample(ctx, args[1:])
	case "run":
		err = a.runSamples(ctx, args[1:], false)
	case "resume":
		err = a.runSamples(ctx, args[1:], true)
	case "replay":
		err = a.replaySample(ctx, args[1:])
	case "compare":
		err = a.compareRuns(ctx, args[1:])
	case "export":
		err = a.exportBundle(ctx, args[1:])
	case "verify":
		err = a.verifyBundle(ctx, args[1:])
	case "restore":
		err = a.restoreBundle(ctx, args[1:])
	case "demo":
		err = a.demo(ctx, args[1:])
	case "help", "-h", "--help":
		a.printUsage()
	default:
		fmt.Fprintf(a.Stderr, "unknown command %q\n\n", args[0])
		a.printUsage()
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(a.Stderr, "auditfix: %v\n", err)
		return 1
	}
	return 0
}

func (a *App) printUsage() {
	fmt.Fprint(a.Stdout, `auditfix - reusable security audit log integrity review

Usage:
  auditfix case import --db FILE --case-id ID --a LOG_A --b LOG_B [--description TEXT]
  auditfix case show   --db FILE --case-id ID
  auditfix case list   --db FILE
  auditfix sample import --db FILE --case-id ID --dir CORPUS
  auditfix sample list   --db FILE --case-id ID
  auditfix run    --db FILE --case-id ID --harness BIN --run-id ID [--limit N]
  auditfix resume --db FILE --run-id ID [--limit N]
  auditfix replay --db FILE --run-id ID --sample REF
  auditfix compare --db FILE --run-id ID
  auditfix compare --db FILE --left RUN --right RUN
  auditfix export  --db FILE --run-id ID --out DIR
  auditfix verify  --bundle DIR [--rerun --harness BIN]
  auditfix restore --bundle DIR --db FILE
  auditfix demo    --dir DIR

Evidence is append-only: imported logs and samples are copied into SQLite before
analysis, and interrupted sample attempts remain in the audit trail.
`)
}

func (a *App) requireDB(flags *flag.FlagSet, dbPath string) error {
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if strings.TrimSpace(dbPath) == "" {
		return errors.New("--db is required")
	}
	return nil
}

func cleanID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return value != "." && value != ".."
}

func absPath(path string) string {
	if path == "" {
		return ""
	}
	value, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return value
}
