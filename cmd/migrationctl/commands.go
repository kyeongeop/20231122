package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"example.com/migration-review/internal/review"
	_ "modernc.org/sqlite"
)

func cmdReview(args []string) int {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	input := fs.String("input", "", "migration manifest (legacy JSON/SQL or v2 JSON)")
	target := fs.String("db", "", "target SQLite database")
	evidencePath := fs.String("evidence", "evidence.sqlite", "evidence SQLite database")
	policyPath := fs.String("policy", "config/policy.json", "permission policy JSON")
	reportPath := fs.String("report", "", "optional Markdown report output")
	actor := fs.String("actor", "", "actor for legacy raw SQL with no signed metadata")
	runID := fs.String("run-id", "", "stable run id (generated when omitted)")
	cancelAfter := fs.Int("cancel-after", 0, "cancel after N committed statements in the transaction")
	allowDestructive := fs.Bool("allow-destructive", false, "operator approval for destructive SQL")
	allowAttach := fs.Bool("allow-attach", false, "operator approval for ATTACH/DETACH")
	allowAdmin := fs.Bool("allow-admin", false, "operator approval for privileged/unrecognized SQL")
	approvalID := fs.String("approval-id", "", "external change approval id")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *input == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "--input and --db are required")
		return 1
	}
	m, err := loadManifest(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	engine, err := loadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	store, err := openEvidence(*evidencePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer store.Close()
	record, runErr := review.Run(context.Background(), store, engine, m, review.Options{
		ActorOverride:    *actor,
		TargetPath:       *target,
		InputPath:        *input,
		RunID:            *runID,
		CancelAfter:      *cancelAfter,
		AllowDestructive: *allowDestructive,
		AllowAttach:      *allowAttach,
		AllowAdmin:       *allowAdmin,
		ApprovalID:       *approvalID,
	})
	if encodeErr := printJSON(record); encodeErr != nil {
		fmt.Fprintln(os.Stderr, encodeErr)
		return 1
	}
	if *reportPath != "" {
		if err := writeReport(store, *policyPath, *reportPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	if runErr != nil {
		fmt.Fprintln(os.Stderr, runErr)
	}
	return exitForRunError(runErr)
}

func cmdReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	evidencePath := fs.String("evidence", "evidence.sqlite", "evidence SQLite database")
	policyPath := fs.String("policy", "config/policy.json", "policy path recorded in report")
	outPath := fs.String("out", "-", "output Markdown path, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	store, err := openEvidence(*evidencePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer store.Close()
	if err := writeReport(store, *policyPath, *outPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *outPath != "-" {
		fmt.Printf("report=%s\n", *outPath)
	}
	return 0
}

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	evidencePath := fs.String("evidence", "evidence.sqlite", "evidence SQLite database")
	runID := fs.String("run", "", "verify one run; all runs when omitted")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	store, err := openEvidence(*evidencePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer store.Close()
	ctx := context.Background()
	var runIDs []string
	if *runID != "" {
		runIDs = []string{*runID}
	} else {
		records, err := store.ListRuns(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		for _, record := range records {
			runIDs = append(runIDs, record.RunID)
		}
	}
	failed := 0
	for _, id := range runIDs {
		if err := store.VerifyRun(ctx, id); err != nil {
			fmt.Printf("FAIL run=%s evidence=%v\n", id, err)
			failed++
			continue
		}
		fmt.Printf("PASS run=%s\n", id)
	}
	if failed > 0 {
		return 1
	}
	return 0
}

type inspectOutput struct {
	Run       any              `json:"run"`
	Logs      any              `json:"logs"`
	Artifacts []artifactOutput `json:"artifacts"`
}

type artifactOutput struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Bytes   int    `json:"bytes"`
	Content string `json:"content_base64,omitempty"`
}

func cmdInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	evidencePath := fs.String("evidence", "evidence.sqlite", "evidence SQLite database")
	runID := fs.String("run", "", "run id")
	includeContent := fs.Bool("include-content", false, "include base64 evidence content")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *runID == "" {
		fmt.Fprintln(os.Stderr, "--run is required")
		return 1
	}
	store, err := openEvidence(*evidencePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer store.Close()
	ctx := context.Background()
	record, err := store.GetRun(ctx, *runID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	logs, err := store.Logs(ctx, *runID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	records, err := store.Artifacts(ctx, *runID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var artifacts []artifactOutput
	for _, record := range records {
		item := artifactOutput{
			Kind: record.Kind, Name: record.Name, SHA256: record.SHA256, Bytes: len(record.Content),
		}
		if *includeContent {
			item.Content = base64.StdEncoding.EncodeToString(record.Content)
		}
		artifacts = append(artifacts, item)
	}
	if err := printJSON(inspectOutput{Run: record, Logs: logs, Artifacts: artifacts}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func cmdVersion(args []string) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer db.Close()
	var version string
	if err := db.QueryRow("SELECT sqlite_version()").Scan(&version); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("go=%s\nsqlite=%s\nengine=libFuzzer+Go c-shared target\n", runtime.Version(), version)
	return 0
}

func cmdFuzzEval(args []string) int {
	fs := flag.NewFlagSet("fuzz-eval", flag.ContinueOnError)
	policyPath := fs.String("policy", "config/policy.json", "permission policy")
	inputPath := fs.String("input", "", "single fuzz input")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *inputPath == "" {
		fmt.Fprintln(os.Stderr, "--input is required")
		return 1
	}
	data, err := os.ReadFile(*inputPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return evalFuzz(data, *policyPath)
}

func evalFuzz(data []byte, policyPath string) int {
	started := time.Now()
	m, err := parseFuzzManifest(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse: %v\n", err)
		return 1
	}
	engine, err := loadPolicy(policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	decision := engine.Authorize(m, policyOptionsForFuzz())
	result := map[string]any{
		"format":        m.Format,
		"bytes":         len(data),
		"elapsed_us":    time.Since(started).Microseconds(),
		"allowed":       decision.Allowed,
		"statements":    len(decision.Statements),
		"deny_reason":   decision.DenyReason,
		"trigger":       decision.Statements,
		"policy_sha256": decision.PolicySHA256,
	}
	_ = printJSON(result)
	if !decision.Allowed {
		return 2
	}
	return 0
}
