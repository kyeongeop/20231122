package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"auditfix/internal/audit"
	"auditfix/internal/db"
	"auditfix/internal/model"
)

func (a *App) runCase(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("case requires import, show, or list")
	}
	switch args[0] {
	case "import":
		return a.caseImport(ctx, args[1:])
	case "show":
		return a.caseShow(ctx, args[1:])
	case "list":
		return a.caseList(ctx, args[1:])
	default:
		return fmt.Errorf("unknown case command %q", args[0])
	}
}

func (a *App) caseImport(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("case import", flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	dbPath := flags.String("db", "", "SQLite database path")
	caseID := flags.String("case-id", "", "case identifier")
	pathA := flags.String("a", "", "device-a JSONL log")
	pathB := flags.String("b", "", "device-b JSONL log")
	description := flags.String("description", "", "case description")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := a.requireDB(flags, *dbPath); err != nil {
		return err
	}
	if !cleanID(*caseID) {
		return errors.New("--case-id must use letters, digits, '-', '_' or '.'")
	}
	if err := requirePath("a", *pathA); err != nil {
		return err
	}
	if err := requirePath("b", *pathB); err != nil {
		return err
	}

	logA, err := os.ReadFile(*pathA)
	if err != nil {
		return fmt.Errorf("read device-a log: %w", err)
	}
	logB, err := os.ReadFile(*pathB)
	if err != nil {
		return fmt.Errorf("read device-b log: %w", err)
	}
	eventsA, err := audit.ParseDeviceLog(bytes.NewReader(logA), "device-a")
	if err != nil {
		return err
	}
	eventsB, err := audit.ParseDeviceLog(bytes.NewReader(logB), "device-b")
	if err != nil {
		return err
	}

	store, err := db.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	createdAt := nowText()
	analysis := audit.Analyze(eventsA, eventsB, *caseID, createdAt)
	c := model.Case{
		CaseID:           *caseID,
		CreatedAt:        createdAt,
		Description:      *description,
		Status:           analysis.Status,
		AnalyzerVersion:  model.ToolVersion,
		ClockOffsetNS:    analysis.ClockOffsetNS,
		ChainStatus:      analysis.ChainStatus,
		AnchorPairCount:  analysis.AnchorPairs,
		DeviceAEventRows: len(eventsA),
		DeviceBEventRows: len(eventsB),
		CorrectionCount:  len(analysis.Corrections),
	}
	blobs := []db.EvidenceBlob{
		{
			Role:       "device-a-log",
			SourceName: filepath.Base(*pathA),
			SHA256:     sha256Hex(logA),
			Data:       logA,
		},
		{
			Role:       "device-b-log",
			SourceName: filepath.Base(*pathB),
			SHA256:     sha256Hex(logB),
			Data:       logB,
		},
	}
	if err := store.CreateCaseAtomic(ctx, c, blobs, analysis.Events,
		analysis.Corrections); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "imported case=%s status=%s %s\n",
		c.CaseID, c.Status, audit.Summary(analysis))
	for _, warning := range analysis.Warnings {
		fmt.Fprintf(a.Stdout, "warning: %s\n", warning)
	}
	return nil
}

func (a *App) caseShow(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("case show", flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	dbPath := flags.String("db", "", "SQLite database path")
	caseID := flags.String("case-id", "", "case identifier")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := a.requireDB(flags, *dbPath); err != nil {
		return err
	}
	store, err := db.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	c, err := store.GetCase(ctx, *caseID)
	if err != nil {
		return err
	}
	corrections, err := store.ListCorrections(ctx, *caseID)
	if err != nil {
		return err
	}
	evidence, err := store.ListEvidence(ctx, *caseID)
	if err != nil {
		return err
	}
	payload := struct {
		Case        model.Case         `json:"case"`
		Corrections []model.Correction `json:"corrections"`
		Evidence    []model.Evidence   `json:"evidence"`
	}{Case: c, Corrections: corrections, Evidence: evidence}
	return printJSON(a.Stdout, payload)
}

func (a *App) caseList(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("case list", flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	dbPath := flags.String("db", "", "SQLite database path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := a.requireDB(flags, *dbPath); err != nil {
		return err
	}
	store, err := db.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	cases, err := store.ListCases(ctx)
	if err != nil {
		return err
	}
	for _, c := range cases {
		fmt.Fprintf(a.Stdout, "%s\t%s\tchain=%s\tclock_offset_ns=%d\tgaps=%d\n",
			c.CaseID, c.Status, c.ChainStatus, c.ClockOffsetNS, c.CorrectionCount)
	}
	return nil
}
