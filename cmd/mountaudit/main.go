package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"mountaudit/internal/audit"
	"mountaudit/internal/engine"
	"mountaudit/internal/report"
	"mountaudit/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mountaudit:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("missing command")
	}
	switch args[0] {
	case "init":
		return runInit(args[1:])
	case "run", "resume":
		return runProcess(args[1:])
	case "status":
		return runStatus(args[1:])
	case "report":
		return runReport(args[1:])
	case "verify":
		return runVerify(args[1:])
	case "extract-original":
		return runExtract(args[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runInit(args []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	dbPath := flags.String("db", "", "SQLite database path")
	inputPath := flags.String("input", "", "unmodified mount capture file")
	artifacts := flags.String("artifacts", "", "artifact directory")
	limits := audit.DefaultLimits()
	flags.Int64Var(&limits.MaxInputBytes, "max-input-bytes", limits.MaxInputBytes, "hard import size limit")
	flags.Int64Var(&limits.MaxScanBytes, "max-scan-bytes", limits.MaxScanBytes, "analysis scan budget")
	flags.IntVar(&limits.MaxRecords, "max-records", limits.MaxRecords, "maximum parsed mount records")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *dbPath == "" || *inputPath == "" {
		return fmt.Errorf("init requires --db and --input")
	}
	if err := ensureParent(*dbPath); err != nil {
		return err
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if *artifacts == "" {
		absoluteDB, _ := filepath.Abs(*dbPath)
		*artifacts = filepath.Join(filepath.Dir(absoluteDB), "mountaudit-artifacts")
	}
	result, err := engine.Init(context.Background(), st, engine.InitOptions{
		InputPath:   *inputPath,
		ArtifactDir: *artifacts,
		Limits:      limits,
	}, nil)
	if err != nil {
		return err
	}
	return printJSON(struct {
		RunID    string         `json:"run_id"`
		Status   string         `json:"status"`
		Original string         `json:"original_sha256"`
		Anchors  []audit.Anchor `json:"anchors"`
	}{
		RunID:    result.Run.ID,
		Status:   result.Run.Status,
		Original: result.Run.SourceSHA256,
		Anchors:  result.Anchors,
	})
}

func runProcess(args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	dbPath := flags.String("db", "", "SQLite database path")
	runID := flags.String("run", "", "run id (default: latest)")
	pauseAfter := flags.Int("pause-after", 0, "commit checkpoint then pause after stage 1, 2, or 3")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *dbPath == "" {
		return fmt.Errorf("run requires --db")
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	resolved, err := st.ResolveRunID(context.Background(), *runID)
	if err != nil {
		return err
	}
	result, err := engine.Process(context.Background(), st, resolved,
		engine.Options{PauseAfter: *pauseAfter}, nil)
	if err != nil {
		return err
	}
	return printJSON(result)
}

func runStatus(args []string) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	dbPath := flags.String("db", "", "SQLite database path")
	runID := flags.String("run", "", "run id (default: latest)")
	asJSON := flags.Bool("json", false, "emit JSON report")
	if err := flags.Parse(args); err != nil {
		return err
	}
	rep, st, err := loadReport(*dbPath, *runID)
	if err != nil {
		return err
	}
	defer st.Close()
	if *asJSON {
		return printJSON(rep)
	}
	fmt.Print(rep.Text())
	return nil
}

func runReport(args []string) error {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	dbPath := flags.String("db", "", "SQLite database path")
	runID := flags.String("run", "", "run id (default: latest)")
	format := flags.String("format", "json", "json or text")
	output := flags.String("out", "", "output file (default: stdout)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	rep, st, err := loadReport(*dbPath, *runID)
	if err != nil {
		return err
	}
	defer st.Close()
	var payload []byte
	switch *format {
	case "json":
		payload, err = rep.JSON()
	case "text":
		payload = []byte(rep.Text())
	default:
		return fmt.Errorf("unsupported report format %q", *format)
	}
	if err != nil {
		return err
	}
	if *output == "" {
		_, err = os.Stdout.Write(payload)
		return err
	}
	if err := ensureParent(*output); err != nil {
		return err
	}
	return os.WriteFile(*output, payload, 0o644)
}

func runVerify(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	dbPath := flags.String("db", "", "SQLite database path")
	runID := flags.String("run", "", "run id (default: latest)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	st, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	resolved, err := st.ResolveRunID(context.Background(), *runID)
	if err != nil {
		return err
	}
	result, err := engine.Verify(context.Background(), st, resolved, nil)
	if err != nil {
		return err
	}
	return printJSON(result)
}

func runExtract(args []string) error {
	flags := flag.NewFlagSet("extract-original", flag.ContinueOnError)
	dbPath := flags.String("db", "", "SQLite database path")
	runID := flags.String("run", "", "run id (default: latest)")
	output := flags.String("out", "", "output file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *output == "" {
		return fmt.Errorf("extract-original requires --out")
	}
	st, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	resolved, err := st.ResolveRunID(context.Background(), *runID)
	if err != nil {
		return err
	}
	item, err := st.GetRun(context.Background(), resolved)
	if err != nil {
		return err
	}
	if err := ensureParent(*output); err != nil {
		return err
	}
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
	if err != nil {
		return fmt.Errorf("create extracted original: %w", err)
	}
	if _, err := file.Write(item.Original); err != nil {
		file.Close()
		return fmt.Errorf("write extracted original: %w", err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	return printJSON(map[string]any{
		"run_id":     item.ID,
		"out":        *output,
		"size":       len(item.Original),
		"sha256":     item.SourceSHA256,
		"unmodified": true,
	})
}

func loadReport(dbPath, runID string) (report.Report, *store.Store, error) {
	st, err := openStore(dbPath)
	if err != nil {
		return report.Report{}, nil, err
	}
	resolved, err := st.ResolveRunID(context.Background(), runID)
	if err != nil {
		st.Close()
		return report.Report{}, nil, err
	}
	rep, err := report.Build(context.Background(), st, resolved, nil)
	if err != nil {
		st.Close()
		return report.Report{}, nil, err
	}
	return rep, st, nil
}

func openStore(dbPath string) (*store.Store, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("--db is required")
	}
	if err := ensureParent(dbPath); err != nil {
		return nil, err
	}
	return store.Open(dbPath)
}

func ensureParent(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}
	return nil
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func usage() {
	fmt.Println(`mountaudit - resumable container mount permission audit

Commands:
  init              import an unmodified capture, resolve anchors, store original
  run               execute pending stages (optionally --pause-after N)
  resume            alias for run; completed stages are replayed and compared
  status            show checkpoints, anchors, offsets, and timestamps
  report            emit JSON or text evidence report
  verify            replay all stages and compare the final digest
  extract-original  export the immutable original bytes from SQLite`)
}
