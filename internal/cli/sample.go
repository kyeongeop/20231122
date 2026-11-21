package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"auditfix/internal/db"
	"auditfix/internal/model"
)

func (a *App) runSample(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("sample requires import or list")
	}
	switch args[0] {
	case "import":
		return a.sampleImport(ctx, args[1:])
	case "list":
		return a.sampleList(ctx, args[1:])
	default:
		return fmt.Errorf("unknown sample command %q", args[0])
	}
}

func (a *App) sampleImport(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("sample import", flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	dbPath := flags.String("db", "", "SQLite database path")
	caseID := flags.String("case-id", "", "case identifier")
	dir := flags.String("dir", "", "sample corpus directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := a.requireDB(flags, *dbPath); err != nil {
		return err
	}
	if err := requirePath("case-id", *caseID); err != nil {
		return err
	}
	if err := requirePath("dir", *dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return fmt.Errorf("read corpus directory: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var samples []model.Sample
	var contents [][]byte
	seenSHA := make(map[string]bool)
	importedAt := nowText()
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		path := filepath.Join(*dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if info.Size() > 16*1024*1024 {
			return fmt.Errorf("sample %q exceeds 16 MiB", entry.Name())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256Hex(data)
		if seenSHA[sum] {
			return fmt.Errorf("duplicate sample content in corpus: %s", entry.Name())
		}
		seenSHA[sum] = true
		samples = append(samples, model.Sample{
			SampleID:    "sample-" + sum[:12],
			CaseID:      *caseID,
			SampleIndex: len(samples) + 1,
			Name:        entry.Name(),
			SHA256:      sum,
			Size:        int64(len(data)),
			SourceName:  entry.Name(),
			ImportedAt:  importedAt,
		})
		contents = append(contents, data)
	}
	if len(samples) == 0 {
		return errors.New("corpus directory contains no regular sample files")
	}
	store, err := db.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	if _, err := store.GetCase(ctx, *caseID); err != nil {
		return err
	}
	existing, err := store.SampleCount(ctx, *caseID)
	if err != nil {
		return err
	}
	if existing != 0 {
		return fmt.Errorf("case %q already has %d samples", *caseID, existing)
	}
	if err := store.InsertSamples(ctx, samples, contents); err != nil {
		return err
	}
	for _, sample := range samples {
		fmt.Fprintf(a.Stdout, "%d\t%s\t%s\t%d\n",
			sample.SampleIndex, sample.Name, sample.SHA256, sample.Size)
	}
	return nil
}

func (a *App) sampleList(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("sample list", flag.ContinueOnError)
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
	samples, err := store.ListSamples(ctx, *caseID)
	if err != nil {
		return err
	}
	for _, sample := range samples {
		fmt.Fprintf(a.Stdout, "%d\t%s\t%s\t%d\n",
			sample.SampleIndex, sample.Name, sample.SHA256, sample.Size)
	}
	return nil
}
