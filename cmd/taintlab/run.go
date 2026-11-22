package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"taintlab/internal/canonical"
	"taintlab/internal/store"
	"taintlab/internal/taint"
)

const toolVersion = "taintlab/0.1.0"

type runSummary struct {
	RunID             int64  `json:"run_id"`
	CaseID            string `json:"case_id"`
	TraceID           string `json:"trace_id"`
	Status            string `json:"status"`
	Decision          string `json:"decision"`
	TriggerDetected   bool   `json:"trigger_detected"`
	TaintedEscalation bool   `json:"tainted_escalation"`
	ClockSkewMS       int64  `json:"clock_skew_ms"`
	ResultSHA256      string `json:"result_sha256"`
	Output            string `json:"output,omitempty"`
}

func runCommand(args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	dbPath := flags.String("db", "artifacts/evidence.sqlite", "SQLite artifact path")
	inputPath := flags.String("input", "-", "input file, or - for stdin")
	outputPath := flags.String("out", "", "optional canonical result JSON path")
	createdAt := flags.String("created-at", "", "RFC3339 creation time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	reader, closeInput, err := openInput(*inputPath)
	if err != nil {
		return err
	}
	defer closeInput()
	result, err := taint.ExecuteReader(reader)
	if err != nil {
		return err
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	runID, err := db.SaveResult(context.Background(), result, *createdAt)
	if err != nil {
		return err
	}
	resultJSON, err := canonical.JSON(result)
	if err != nil {
		return err
	}
	if *outputPath != "" {
		if err := writeArtifact(*outputPath, resultJSON); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(runSummary{
		RunID:             runID,
		CaseID:            result.CaseID,
		TraceID:           result.TraceID,
		Status:            result.Status,
		Decision:          result.Permission.Decision,
		TriggerDetected:   result.Trigger.Detected,
		TaintedEscalation: result.Permission.TaintedEscalation,
		ClockSkewMS:       result.Evidence.Clock.SkewMS,
		ResultSHA256:      canonical.SumBytes(resultJSON),
		Output:            *outputPath,
	})
}

func openInput(path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open input: %w", err)
	}
	return file, func() { _ = file.Close() }, nil
}

func writeArtifact(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create artifact directory: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write artifact: %w", err)
	}
	return nil
}

func showCommand(args []string) error {
	flags := flag.NewFlagSet("show", flag.ContinueOnError)
	dbPath := flags.String("db", "artifacts/evidence.sqlite", "SQLite artifact path")
	runID := flags.Int64("run", 0, "run id to show")
	caseID := flags.String("case", "", "show all runs for a case id")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *runID <= 0 && *caseID == "" {
		return fmt.Errorf("show requires --run or --case")
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	encoder := json.NewEncoder(os.Stdout)
	if *runID > 0 {
		stored, err := db.LoadRun(context.Background(), *runID)
		if err != nil {
			return err
		}
		return encoder.Encode(stored.Result)
	}
	runs, err := db.LoadAll(context.Background(), *caseID)
	if err != nil {
		return err
	}
	for _, stored := range runs {
		if err := encoder.Encode(stored.Result); err != nil {
			return err
		}
	}
	return nil
}

func verifyDBCommand(args []string) error {
	flags := flag.NewFlagSet("verify-db", flag.ContinueOnError)
	dbPath := flags.String("db", "artifacts/evidence.sqlite", "SQLite artifact path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	runs, err := db.LoadAll(context.Background(), "")
	if err != nil {
		return err
	}
	events := 0
	for _, run := range runs {
		events += len(run.Result.Evidence.Events)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Verified   bool   `json:"verified"`
		Database   string `json:"database"`
		Runs       int    `json:"runs"`
		Events     int    `json:"events"`
		VerifiedAt string `json:"verified_at"`
	}{
		Verified:   true,
		Database:   *dbPath,
		Runs:       len(runs),
		Events:     events,
		VerifiedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
}
