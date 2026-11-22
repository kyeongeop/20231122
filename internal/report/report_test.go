package report_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.com/migration-review/internal/evidence"
	"example.com/migration-review/internal/manifest"
	"example.com/migration-review/internal/policy"
	"example.com/migration-review/internal/report"
	"example.com/migration-review/internal/review"
	_ "modernc.org/sqlite"
)

func TestReportSeparatesAutomaticAndManualAndIncludesActions(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.db")
	initTarget(t, target)
	store, err := evidence.Open(filepath.Join(dir, "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := loadPolicy(t)
	ctx := context.Background()
	runs := []struct {
		path   string
		source string
		opts   review.Options
	}{
		{"../../testdata/migrations/new-add-orders.json", "new-add-orders.json", review.Options{TargetPath: target, RunID: "allow", InputPath: "new-add-orders.json"}},
		{"../../testdata/attack/legacy-drop-audit.json", "legacy-drop-audit.json", review.Options{TargetPath: target, RunID: "deny", InputPath: "legacy-drop-audit.json"}},
		{"../../testdata/migrations/new-cancel-index.json", "new-cancel-index.json", review.Options{TargetPath: target, RunID: "cancel", InputPath: "new-cancel-index.json", CancelAfter: 1}},
	}
	for _, item := range runs {
		data, err := os.ReadFile(item.path)
		if err != nil {
			t.Fatal(err)
		}
		m, err := manifest.Parse(data, item.source)
		if err != nil {
			t.Fatal(err)
		}
		_, runErr := review.Run(ctx, store, engine, m, item.opts)
		var typed *review.RunError
		if item.opts.RunID != "allow" && (!errors.As(runErr, &typed)) {
			t.Fatalf("run %s: %v", item.opts.RunID, runErr)
		}
	}
	for _, runID := range []string{"allow", "deny", "cancel"} {
		if err := store.VerifyRun(ctx, runID); err != nil {
			t.Fatalf("verify %s: %v", runID, err)
		}
	}
	data, err := report.Render(ctx, store, report.Options{
		EvidencePath: store.Path(),
		PolicyPath:   "../../config/policy.json",
		PolicySHA256: engine.Hash(),
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	required := []string{
		"## 自动结论",
		"## 人工确认",
		"人工复核状态：**未确认**",
		"策略文件与证据一致 | **PASS**",
		"所有运行已完结 | **PASS**",
		"旧格式兼容 | **PASS**",
		"新格式兼容 | **PASS**",
		"中途取消并回滚 | **PASS**",
		"危险权限攻击被拦截 | **PASS**",
		"legacy-drop-audit.json#sql:3:1",
		"DROP / destructive",
		"CANCELLED / 已回滚",
		"## 失败与后续操作",
		"migrationctl verify",
	}
	for _, want := range required {
		if !strings.Contains(text, want) {
			t.Fatalf("report missing %q", want)
		}
	}
}

func initTarget(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range []string{
		"CREATE TABLE accounts (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
		"CREATE TABLE audit_log (id INTEGER PRIMARY KEY, event TEXT NOT NULL)",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
}

func loadPolicy(t *testing.T) *policy.Engine {
	t.Helper()
	data, err := os.ReadFile("../../config/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}
