package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"taintlab/internal/export"
	"taintlab/internal/store"
	"taintlab/internal/taint"
)

func exportCommand(args []string) error {
	flags := flag.NewFlagSet("export", flag.ContinueOnError)
	dbPath := flags.String("db", "artifacts/evidence.sqlite", "SQLite artifact path")
	outputDir := flags.String("out", "artifacts/export", "export directory")
	caseID := flags.String("case", "", "export only one case id")
	exportedAt := flags.String("exported-at", "", "RFC3339 export time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	runs, err := db.LoadAll(context.Background(), *caseID)
	if err != nil {
		return err
	}
	manifest, err := export.WriteDir(*outputDir, runs, export.Options{
		ExportedAt: *exportedAt,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(manifest)
}

func verifyExportCommand(args []string) error {
	flags := flag.NewFlagSet("verify-export", flag.ContinueOnError)
	dir := flags.String("dir", "artifacts/export", "export directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	verification, err := export.VerifyDir(*dir)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Verified       bool   `json:"verified"`
		Directory      string `json:"directory"`
		Runs           int    `json:"runs"`
		Events         int    `json:"events"`
		ReplayedRuns   int    `json:"replayed_runs"`
		IncompleteRuns int    `json:"incomplete_runs"`
	}{
		Verified:       true,
		Directory:      *dir,
		Runs:           verification.Runs,
		Events:         verification.Events,
		ReplayedRuns:   verification.ReplayedRuns,
		IncompleteRuns: verification.IncompleteRuns,
	})
}

func demoCommand(args []string) error {
	flags := flag.NewFlagSet("demo", flag.ContinueOnError)
	dir := flags.String("dir", "artifacts", "artifact directory")
	samplePath := flags.String("sample", "testdata/cases/unsynced-truncation.json",
		"sample scenario path")
	createdAt := flags.String("created-at", "2026-11-22T04:00:00Z",
		"RFC3339 creation time")
	exportedAt := flags.String("exported-at", "2026-11-22T05:00:00Z",
		"RFC3339 export time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	sample, err := os.ReadFile(*samplePath)
	if err != nil {
		return fmt.Errorf("read sample: %w", err)
	}
	inputs := []struct {
		name  string
		bytes []byte
	}{
		{"unsynced-truncation", sample},
		{"empty", nil},
		{"oversized", bytes.Repeat([]byte("A"), taint.MaxInputBytes+64)},
		{"malformed", []byte(`{"source":`)},
	}
	dbPath := filepath.Join(*dir, "evidence.sqlite")
	db, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	runIDs := make([]int64, 0, len(inputs))
	for _, input := range inputs {
		result := taint.Execute(input.bytes)
		runID, err := db.SaveResult(context.Background(), result, *createdAt)
		if err != nil {
			return fmt.Errorf("save %s: %w", input.name, err)
		}
		runIDs = append(runIDs, runID)
	}
	for _, runID := range runIDs {
		stored, err := db.LoadRun(context.Background(), runID)
		if err != nil {
			return err
		}
		path := filepath.Join(*dir, "runs", fmt.Sprintf("run-%06d.json", runID))
		if err := writeArtifact(path, stored.ResultJSON); err != nil {
			return err
		}
	}
	runs, err := db.LoadAll(context.Background(), "")
	if err != nil {
		return err
	}
	exportDir := filepath.Join(*dir, "export")
	manifest, err := export.WriteDir(exportDir, runs, export.Options{ExportedAt: *exportedAt})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Database string   `json:"database"`
		Export   string   `json:"export"`
		RunIDs   []int64  `json:"run_ids"`
		Runs     int      `json:"runs"`
		Events   int      `json:"events"`
		Files    []string `json:"files"`
	}{
		Database: dbPath,
		Export:   exportDir,
		RunIDs:   runIDs,
		Runs:     manifest.RunCount,
		Events:   manifest.EventCount,
		Files:    []string{"records.jsonl", "evidence.jsonl", "manifest.json", "README.txt"},
	})
}
