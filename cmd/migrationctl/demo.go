package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"example.com/migration-review/internal/evidence"
	"example.com/migration-review/internal/model"
	"example.com/migration-review/internal/review"
	_ "modernc.org/sqlite"
)

type demoSummary struct {
	Evidence  string            `json:"evidence"`
	Report    string            `json:"report"`
	Target    string            `json:"target"`
	AttackRaw string            `json:"attack_raw"`
	Runs      map[string]string `json:"runs"`
}

func cmdDemo(args []string) int {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	outDir := fs.String("out", "artifacts/review", "output directory (must be absent or empty)")
	policyPath := fs.String("policy", "config/policy.json", "permission policy")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if err := ensureEmptyDir(*outDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	targetPath := filepath.Join(*outDir, "target.db")
	evidencePath := filepath.Join(*outDir, "evidence.sqlite")
	reportPath := filepath.Join(*outDir, "review-report.md")
	summaryPath := filepath.Join(*outDir, "summary.json")
	attackCopyPath := filepath.Join(*outDir, "attack-input.bin")
	if err := initDemoTarget(targetPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	engine, err := loadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	store, err := evidence.Open(evidencePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx := context.Background()
	expected := map[string]model.RunStatus{
		"demo-v2-success":    model.StatusAllowed,
		"demo-legacy-attack": model.StatusDenied,
		"demo-cancel-midway": model.StatusCancelled,
	}
	inputs := []struct {
		runID string
		path  string
		opts  review.Options
	}{
		{"demo-v2-success", "testdata/migrations/new-add-orders.json", review.Options{TargetPath: targetPath, InputPath: "testdata/migrations/new-add-orders.json", RunID: "demo-v2-success"}},
		{"demo-legacy-attack", "testdata/attack/legacy-drop-audit.json", review.Options{TargetPath: targetPath, InputPath: "testdata/attack/legacy-drop-audit.json", RunID: "demo-legacy-attack"}},
		{"demo-cancel-midway", "testdata/migrations/new-cancel-index.json", review.Options{TargetPath: targetPath, InputPath: "testdata/migrations/new-cancel-index.json", RunID: "demo-cancel-midway", CancelAfter: 1}},
	}
	failed := false
	for _, item := range inputs {
		m, err := loadManifest(item.path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			_ = store.Close()
			return 1
		}
		record, runErr := review.Run(ctx, store, engine, m, item.opts)
		if record.Status != expected[item.runID] {
			fmt.Fprintf(os.Stderr, "demo %s: expected %s, got %s (%v)\n",
				item.runID, expected[item.runID], record.Status, runErr)
			failed = true
		}
		if item.runID == "demo-legacy-attack" {
			raw, err := os.ReadFile(item.path)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				failed = true
			} else if err := os.WriteFile(attackCopyPath, raw, 0o644); err != nil {
				fmt.Fprintln(os.Stderr, err)
				failed = true
			}
		}
		if runErr != nil {
			var runErrValue *review.RunError
			if !errors.As(runErr, &runErrValue) {
				fmt.Fprintln(os.Stderr, runErr)
				failed = true
			}
		}
	}
	if err := verifyDemoTarget(targetPath); err != nil {
		fmt.Fprintf(os.Stderr, "demo target verification: %v\n", err)
		failed = true
	}
	if err := writeReportToPath(store, *policyPath, reportPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		failed = true
	}
	summaries := map[string]string{}
	records, err := store.ListRuns(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		failed = true
	}
	for _, record := range records {
		summaries[record.RunID] = string(record.Status)
	}
	summary := demoSummary{
		Evidence: evidencePath, Report: reportPath, Target: targetPath,
		AttackRaw: attackCopyPath, Runs: summaries,
	}
	summaryData, _ := json.MarshalIndent(summary, "", "  ")
	if err := os.WriteFile(summaryPath, summaryData, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		failed = true
	}
	if err := store.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		failed = true
	}
	if failed {
		return 1
	}
	fmt.Printf("evidence=%s\nreport=%s\ntarget=%s\nattack_raw=%s\n",
		evidencePath, reportPath, targetPath, attackCopyPath)
	return 0
}

func initDemoTarget(path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	statements := []string{
		"CREATE TABLE accounts (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
		"CREATE TABLE audit_log (id INTEGER PRIMARY KEY, event TEXT NOT NULL)",
		"INSERT INTO accounts(name) VALUES ('reviewer')",
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("initialize demo target: %w", err)
		}
	}
	return nil
}

func verifyDemoTarget(path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	var auditLog, cancelProbe, orders int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_log'").Scan(&auditLog); err != nil {
		return err
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cancel_probe'").Scan(&cancelProbe); err != nil {
		return err
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='orders'").Scan(&orders); err != nil {
		return err
	}
	if auditLog != 1 || cancelProbe != 0 || orders != 1 {
		return fmt.Errorf("audit_log=%d cancel_probe=%d orders=%d; want 1/0/1", auditLog, cancelProbe, orders)
	}
	return nil
}

func ensureEmptyDir(path string) error {
	entries, err := os.ReadDir(path)
	if err == nil && len(entries) > 0 {
		return fmt.Errorf("output directory %s is not empty; use a new --out value to preserve old evidence", path)
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.MkdirAll(path, 0o755)
}

func writeReportToPath(store *evidence.Store, policyPath, outPath string) error {
	return writeReport(store, policyPath, outPath)
}
