package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/example/syscallwhitelist/internal/checker"
	"github.com/example/syscallwhitelist/internal/model"
	"github.com/example/syscallwhitelist/internal/report"
	"github.com/example/syscallwhitelist/internal/store"
	"github.com/example/syscallwhitelist/internal/tempstate"
)

type registryFile struct {
	TrustedSources []model.Source   `json:"trusted_sources"`
	Snapshots      []model.Snapshot `json:"snapshots"`
}

func main() {
	registryPath := flag.String("registry", "testdata/registry.json", "来源与白名单快照文件")
	recordsPath := flag.String("records", "testdata/records.json", "待检查记录文件")
	dbPath := flag.String("db", "artifacts/audit.db", "SQLite 输出路径")
	pagePath := flag.String("page", "artifacts/check-page.html", "HTML 检查页输出路径")
	flag.Parse()

	if err := run(*registryPath, *recordsPath, *dbPath, *pagePath); err != nil {
		fmt.Fprintln(os.Stderr, "audit failed:", err)
		os.Exit(1)
	}
}

func run(registryPath, recordsPath, dbPath, pagePath string) error {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(pagePath), 0o755); err != nil {
		return err
	}

	registry, err := loadRegistry(registryPath)
	if err != nil {
		return fmt.Errorf("load registry: %w", err)
	}
	records, err := loadRecords(recordsPath)
	if err != nil {
		return fmt.Errorf("load records: %w", err)
	}

	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	for _, src := range registry.TrustedSources {
		if err := st.UpsertSource(src); err != nil {
			return fmt.Errorf("upsert source: %w", err)
		}
	}
	for i := range registry.Snapshots {
		snap := registry.Snapshots[i]
		snap.Fingerprint = fingerprint(snap)
		if err := st.SaveSnapshot(snap); err != nil {
			return fmt.Errorf("save snapshot: %w", err)
		}
	}

	// 临时状态根目录放在系统临时区，结束统一清理。
	tmp, err := tempstate.New(os.TempDir())
	if err != nil {
		return err
	}
	chk := checker.New(st, tmp)

	counters := map[string]int{}
	for _, rec := range records {
		// 单条记录异常（含 panic）不会中断循环，后续对象继续处理。
		f, _ := chk.Process(rec)
		counters[string(f.Verdict)]++
		fmt.Printf("[%s] %s -> %s\n", f.RecordID, f.Verdict, f.Reason)
	}

	findings, err := st.AllFindings()
	if err != nil {
		return err
	}
	versions, err := st.SnapshotVersions()
	if err != nil {
		return err
	}

	cleanErr := tmp.CleanupAll()
	cleaned := cleanErr == nil && !tmp.RootExists()
	liveLeft := tmp.LiveCount()

	page := report.PageData{
		SnapshotVers: versions,
		Findings:     findings,
		RawByID:      buildRawViews(records),
		Counters:     counters,
		TempCleaned:  cleaned,
		TempLiveLeft: liveLeft,
	}
	if err := report.WriteFile(pagePath, page); err != nil {
		return fmt.Errorf("write page: %w", err)
	}

	fmt.Printf("\nsnapshots=%v findings=%d counters=%v\n", versions, len(findings), counters)
	fmt.Printf("temp cleaned=%v live_left=%d root=%s\n", cleaned, liveLeft, tmp.Root())
	fmt.Printf("sqlite=%s page=%s\n", dbPath, pagePath)
	return nil
}

func loadRegistry(path string) (registryFile, error) {
	var reg registryFile
	data, err := os.ReadFile(path)
	if err != nil {
		return reg, err
	}
	err = json.Unmarshal(data, &reg)
	return reg, err
}

func loadRecords(path string) ([]model.Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, err
	}
	return recs, nil
}

func fingerprint(snap model.Snapshot) string {
	canonical, _ := json.Marshal(snap.Syscalls)
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func buildRawViews(recs []model.Record) map[string]report.RawView {
	out := make(map[string]report.RawView, len(recs))
	for _, r := range recs {
		sum := sha256.Sum256([]byte(r.Raw))
		out[r.ID] = report.RawView{
			Raw:       r.Raw,
			SHA256:    hex.EncodeToString(sum[:]),
			Truncated: r.Truncated,
		}
	}
	return out
}
