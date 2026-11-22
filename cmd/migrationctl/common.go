package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"example.com/migration-review/internal/evidence"
	"example.com/migration-review/internal/manifest"
	"example.com/migration-review/internal/model"
	"example.com/migration-review/internal/policy"
	"example.com/migration-review/internal/report"
	"example.com/migration-review/internal/review"
)

func loadManifest(path string) (*model.Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read input %s: %w", path, err)
	}
	m, err := manifest.Parse(data, filepath.Base(path))
	if err != nil {
		return nil, fmt.Errorf("parse input %s: %w", path, err)
	}
	if m.SourceName == "" {
		m.SourceName = path
	}
	return m, nil
}

func loadPolicy(path string) (*policy.Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %s: %w", path, err)
	}
	engine, err := policy.Load(data)
	if err != nil {
		return nil, err
	}
	return engine, nil
}

func openEvidence(path string) (*evidence.Store, error) {
	store, err := evidence.Open(path)
	if err != nil {
		return nil, err
	}
	return store, nil
}

func writeReport(store *evidence.Store, policyPath, outPath string) error {
	engine, err := loadPolicy(policyPath)
	if err != nil {
		return err
	}
	reportData, err := report.Render(context.Background(), store, report.Options{
		EvidencePath: store.Path(),
		PolicyPath:   policyPath,
		PolicySHA256: engine.Hash(),
	})
	if err != nil {
		return fmt.Errorf("render report: %w", err)
	}
	if outPath == "-" {
		_, err = os.Stdout.Write(reportData)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil && filepath.Dir(outPath) != "." {
		return err
	}
	if err := os.WriteFile(outPath, reportData, 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func exitForRunError(err error) int {
	if err == nil {
		return 0
	}
	var runErr *review.RunError
	if !errors.As(err, &runErr) {
		return 1
	}
	switch runErr.Status {
	case model.StatusDenied:
		return 2
	case model.StatusCancelled:
		return 3
	}
	return 1
}
