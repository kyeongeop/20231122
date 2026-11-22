package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"quotabypass/internal/evidence"
	"quotabypass/internal/model"
	"quotabypass/internal/store"
)

func loadAllV2(st *store.StoreV2) ([]model.Record, error) {
	ordinals, err := st.Ordinals()
	if err != nil {
		return nil, err
	}
	records := make([]model.Record, 0, len(ordinals))
	for _, n := range ordinals {
		rec, err := st.Load(n)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, nil
}

func cmdExportV2(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	dbPath := fs.String("db", "artifacts/evidence.sqlite", "SQLite database path")
	outDir := fs.String("out", "artifacts", "export directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.OpenV2(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	records, err := loadAllV2(st)
	if err != nil {
		return err
	}
	return writeExportsV2(records, *outDir)
}

func cmdImportV2(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	dbPath := fs.String("db", "artifacts/evidence.sqlite", "SQLite database path")
	inFile := fs.String("in", "artifacts/evidence.jsonl", "JSONL input path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	f, err := os.Open(*inFile)
	if err != nil {
		return err
	}
	defer f.Close()

	records, err := evidence.ReadJSONL(f)
	if err != nil {
		return err
	}
	st, err := store.OpenV2(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, rec := range records {
		if err := st.Save(rec); err != nil {
			return fmt.Errorf("import %s: %w", rec.RunID, err)
		}
	}
	fmt.Printf("imported and verified %d records <- %s\n", len(records), *inFile)
	return nil
}

func cmdVerifyV2(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	dbPath := fs.String("db", "artifacts/evidence.sqlite", "SQLite database path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.OpenV2(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	records, err := loadAllV2(st)
	if err != nil {
		return err
	}
	for _, rec := range records {
		if err := evidence.VerifyRecord(rec); err != nil {
			return fmt.Errorf("%s: %w", rec.RunID, err)
		}
		fmt.Printf("OK  ordinal=%d %-28s sha256=%s\n", rec.Ordinal, rec.Scenario, rec.RecordSHA256)
	}
	fmt.Printf("all %d records verified\n", len(records))
	return nil
}

func cmdQueryV2(args []string) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	dbPath := fs.String("db", "artifacts/evidence.sqlite", "SQLite database path")
	ordinal := fs.Int("ordinal", 1, "record ordinal to inspect")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.OpenV2(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	rec, err := st.Load(*ordinal)
	if err != nil {
		return err
	}
	summary := map[string]any{
		"ordinal":         rec.Ordinal,
		"run_id":          rec.RunID,
		"scenario":        rec.Scenario,
		"mode":            rec.Mode,
		"permission":      rec.Permission,
		"summary":         rec.Summary,
		"input_evidence":  rec.Input,
		"record_sha256":   rec.RecordSHA256,
		"attempts_sample": firstAttempts(rec.Attempts, 3),
		"logs_tail":       lastLogs(rec.Logs, 3),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}

func firstAttempts(in []model.Attempt, n int) []model.Attempt {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func lastLogs(in []model.LogEntry, n int) []model.LogEntry {
	if len(in) <= n {
		return in
	}
	return in[len(in)-n:]
}

// manifestEntry 是清单中的单条记录条目，字段顺序与参考 manifest 对齐。
type manifestEntry struct {
	Ordinal      int           `json:"ordinal"`
	RunID        string        `json:"run_id"`
	Scenario     string        `json:"scenario"`
	Mode         string        `json:"mode"`
	InputSHA256  string        `json:"input_sha256"`
	RecordSHA256 string        `json:"record_sha256"`
	Summary      model.Summary `json:"summary"`
}

type manifestFile struct {
	Schema      string          `json:"schema"`
	Database    string          `json:"database"`
	RecordCount int             `json:"record_count"`
	Order       []manifestEntry `json:"order"`
}

func cmdManifestV2(args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ContinueOnError)
	dbPath := fs.String("db", "artifacts/evidence.sqlite", "SQLite database path")
	outFile := fs.String("out", "artifacts/manifest.json", "manifest output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.OpenV2(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	records, err := loadAllV2(st)
	if err != nil {
		return err
	}

	mf := manifestFile{
		Schema:      evidence.ExportSchema,
		Database:    *dbPath,
		RecordCount: len(records),
		Order:       make([]manifestEntry, 0, len(records)),
	}
	for _, rec := range records {
		mf.Order = append(mf.Order, manifestEntry{
			Ordinal:      rec.Ordinal,
			RunID:        rec.RunID,
			Scenario:     rec.Scenario,
			Mode:         rec.Mode,
			InputSHA256:  rec.Input.SHA256,
			RecordSHA256: rec.RecordSHA256,
			Summary:      rec.Summary,
		})
	}
	raw, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*outFile, append(raw, '\n'), 0o644)
}
