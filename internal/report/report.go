package report

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"example.com/deserialize-boundary/internal/ledger"
)

type Automated struct {
	Verdict string         `json:"verdict"`
	Passed  int            `json:"passed"`
	Failed  int            `json:"failed"`
	Checks  []ledger.Check `json:"checks"`
}

type ManualItem struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Why     string `json:"why"`
	Command string `json:"command"`
	Status  string `json:"status"`
}

type Manual struct {
	Status string       `json:"status"`
	Items  []ManualItem `json:"items"`
}

type FollowUp struct {
	CheckID  string `json:"check_id"`
	Priority string `json:"priority"`
	Action   string `json:"action"`
	Command  string `json:"command"`
}

type Report struct {
	Title        string     `json:"title"`
	GeneratedAt  string     `json:"generated_at"`
	Database     string     `json:"database"`
	Automated    Automated  `json:"automated"`
	Manual       Manual     `json:"manual_confirmation"`
	FollowUps    []FollowUp `json:"follow_ups"`
	EvidenceRoot string     `json:"evidence_root"`
}

func Generate(ctx context.Context, db *ledger.Ledger, dbPath, evidenceDir, outDir string) (Report, error) {
	checks, err := db.Checks(ctx)
	if err != nil {
		return Report{}, err
	}
	checks = refreshStepCheck(ctx, db, checks)
	sort.Slice(checks, func(i, j int) bool { return checks[i].ID < checks[j].ID })
	checks = append(checks, verifyManifest(evidenceDir))

	report := Report{
		Title:        "反序列化边界测试：可回放实验报告",
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Database:     dbPath,
		EvidenceRoot: evidenceDir,
		Manual: Manual{
			Status: "PENDING",
			Items:  manualItems(),
		},
	}
	for _, check := range checks {
		if check.Passed {
			report.Automated.Passed++
		} else {
			report.Automated.Failed++
		}
	}
	report.Automated.Checks = checks
	report.Automated.Verdict = "PASS"
	if report.Automated.Failed > 0 || len(checks) == 0 {
		report.Automated.Verdict = "FAIL"
	}
	if report.Automated.Verdict == "FAIL" {
		report.FollowUps = followUps(checks)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return Report{}, err
	}
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return Report{}, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "report.json"), append(jsonData, '\n'), 0o644); err != nil {
		return Report{}, err
	}
	automatedData, err := json.MarshalIndent(map[string]any{
		"title":         report.Title,
		"generated_at":  report.GeneratedAt,
		"database":      report.Database,
		"automated":     report.Automated,
		"follow_ups":    report.FollowUps,
		"evidence_root": report.EvidenceRoot,
	}, "", "  ")
	if err != nil {
		return Report{}, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "automated-conclusions.json"), append(automatedData, '\n'), 0o644); err != nil {
		return Report{}, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "manual-confirmation.md"), []byte(renderManual(report)), 0o644); err != nil {
		return Report{}, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "report.md"), []byte(renderMarkdown(report)), 0o644); err != nil {
		return Report{}, err
	}
	return report, nil
}

func refreshStepCheck(ctx context.Context, db *ledger.Ledger, checks []ledger.Check) []ledger.Check {
	total, totalErr := db.ScalarInt(ctx, `SELECT COUNT(*) FROM steps`)
	bad, badErr := db.ScalarInt(ctx, `SELECT COUNT(*) FROM steps
		WHERE input_sha256 = '' OR input_json = '' OR state_before = ''
		OR state_after = '' OR outcome = '' OR result_json = ''`)
	passed := totalErr == nil && badErr == nil && total > 0 && bad == 0
	observed := fmt.Sprintf("steps=%d incomplete=%d", total, bad)
	for i := range checks {
		if checks[i].ID != "step_ledger_complete" {
			continue
		}
		checks[i].Passed = passed
		checks[i].Observed = observed
		return checks
	}
	checks = append(checks, ledger.Check{
		ID:       "step_ledger_complete",
		Category: "evidence",
		Passed:   passed,
		Expected: "every step has non-empty input JSON, hash, state before/after, outcome, and result",
		Observed: observed,
		Evidence: "artifacts/evidence/experiment.db#steps",
		Detail:   "Recomputed at report time across core and fuzz replay steps.",
	})
	return checks
}

func verifyManifest(evidenceDir string) ledger.Check {
	manifestPath := filepath.Join(evidenceDir, "MANIFEST.sha256")
	total, errors, err := VerifyManifest(evidenceDir)
	if err != nil {
		return newCheck("evidence_manifest_valid", false, "evidence manifest exists and all hashes match",
			"manifest error: "+err.Error(), manifestPath)
	}
	passed := total > 0 && len(errors) == 0
	observed := fmt.Sprintf("entries=%d mismatches=%d", total, len(errors))
	if len(errors) > 0 {
		observed += " first_error=" + errors[0]
	}
	return newCheck("evidence_manifest_valid", passed,
		"evidence manifest exists and all hashes match", observed, manifestPath)
}

func manualItems() []ManualItem {
	return []ManualItem{
		{
			ID:      "manual-cancel-point",
			Title:   "确认目标取消确实发生在第 2 条记录之后",
			Why:     "自动检查依赖 SQLite 中的 result_json；人工需核对步骤语义与取消位置。",
			Command: `./build/dfexp query --db artifacts/evidence/experiment.db --sql "SELECT seq, action, outcome, json_extract(result_json,'$.accepted_before_cancel') AS accepted_before_cancel FROM steps WHERE run_id='cancel-target' ORDER BY seq;"`,
			Status:  "PENDING",
		},
		{
			ID:      "manual-cancel-control",
			Title:   "比较目标取消与对照取消的逐步结果",
			Why:     "确认对照运行独立且在同一中点行为一致，排除单次偶发差异。",
			Command: `./build/dfexp query --db artifacts/evidence/experiment.db --sql "SELECT run_id, seq, action, outcome FROM steps WHERE run_id IN ('cancel-target','cancel-control') ORDER BY run_id, seq;"`,
			Status:  "PENDING",
		},
		{
			ID:      "manual-order",
			Title:   "抽查升序与降序运行的最终摘要",
			Why:     "确认顺序改变只影响写入顺序，不改变按 id 规范化的语义状态。",
			Command: `./build/dfexp query --db artifacts/evidence/experiment.db --sql "SELECT run_id, status, state_digest FROM runs WHERE run_id IN ('order-asc','order-desc');"`,
			Status:  "PENDING",
		},
		{
			ID:      "manual-duplicate",
			Title:   "确认重复 id 被拒绝且未产生额外行",
			Why:     "同时核对步骤结果和 SQLite 行数，排除只改审计而未约束领域表的假通过。",
			Command: `./build/dfexp query --db artifacts/evidence/experiment.db --sql "SELECT record_id, COUNT(*) AS rows FROM records WHERE run_id='duplicate-submit' GROUP BY record_id;"`,
			Status:  "PENDING",
		},
		{
			ID:      "manual-libfuzzer",
			Title:   "确认 fuzzer.log 来自 libFuzzer 且没有崩溃产物",
			Why:     "自动结论只能解析日志；人工应确认启动横幅、执行次数和产物目录。",
			Command: `head -30 artifacts/evidence/fuzz/fuzzer.log && find artifacts/evidence/fuzz -maxdepth 1 -type f -printf '%f\n' | sort`,
			Status:  "PENDING",
		},
		{
			ID:      "manual-replay",
			Title:   "独立执行回放并复核报告",
			Why:     "确认新进程、新 SQLite 文件仍得到相同状态摘要与输入哈希。",
			Command: `./scripts/run-all.sh && ./build/dfexp verify-manifest --dir artifacts/evidence`,
			Status:  "PENDING",
		},
	}
}

func followUps(checks []ledger.Check) []FollowUp {
	var out []FollowUp
	for _, check := range checks {
		if check.Passed {
			continue
		}
		out = append(out, followUpFor(check.ID))
	}
	if len(out) == 0 {
		out = append(out, FollowUp{
			CheckID:  "unknown",
			Priority: "P1",
			Action:   "没有可识别检查但自动判定失败；先检查报告与 SQLite 是否完整。",
			Command:  `./build/dfexp query --db artifacts/evidence/experiment.db --sql "SELECT * FROM checks ORDER BY check_id;"`,
		})
	}
	return out
}

func followUpFor(checkID string) FollowUp {
	switch {
	case checkID == "core_run_command":
		return FollowUp{CheckID: checkID, Priority: "P1",
			Action:  "重新运行核心场景；若命令仍失败，先查看 core-run.err 与 SQLite 锁状态。",
			Command: `./build/dfexp run --db artifacts/evidence/experiment.db --out artifacts/evidence`}
	case strings.HasPrefix(checkID, "cancel_"):
		return FollowUp{CheckID: checkID, Priority: "P1",
			Action:  "重新运行取消场景，再按 seq 检查取消点与已提交行数。",
			Command: `./build/dfexp run --db artifacts/evidence/experiment.db --out artifacts/evidence`}
	case strings.HasPrefix(checkID, "parser_") || checkID == "step_ledger_complete":
		return FollowUp{CheckID: checkID, Priority: "P1",
			Action:  "先运行边界单元测试，再重建核心场景和账本。",
			Command: `go test -v ./internal/wire && ./build/dfexp run --db artifacts/evidence/experiment.db --out artifacts/evidence`}
	case strings.HasPrefix(checkID, "db_order") || strings.HasPrefix(checkID, "duplicate_"):
		return FollowUp{CheckID: checkID, Priority: "P1",
			Action:  "检查领域表与状态摘要；若不一致，保留数据库并缩小到单次提交。",
			Command: `./build/dfexp query --db artifacts/evidence/experiment.db --sql "SELECT * FROM runs; SELECT * FROM records ORDER BY run_id, record_id;"`}
	case strings.HasPrefix(checkID, "libfuzzer") || strings.HasPrefix(checkID, "fuzz_"):
		return FollowUp{CheckID: checkID, Priority: "P0",
			Action:  "保留 fuzzer 日志/崩溃产物，重跑 libFuzzer，再回放保留语料。",
			Command: `make fuzz && ./build/dfexp ingest-fuzz --db artifacts/evidence/experiment.db --corpus artifacts/evidence/fuzz/corpus --out artifacts/evidence`}
	case checkID == "replay_core_equivalence" || checkID == "replay_command":
		return FollowUp{CheckID: checkID, Priority: "P1",
			Action:  "对比源与回放 JSONL；不要删除旧库，先定位首个结果差异步骤。",
			Command: `./build/dfexp replay --source artifacts/evidence/experiment.db --dest artifacts/evidence/replay.db --out artifacts/evidence`}
	case checkID == "evidence_manifest_valid":
		return FollowUp{CheckID: checkID, Priority: "P2",
			Action:  "重新生成证据清单并逐项校验；不要手改哈希。",
			Command: `./build/dfexp manifest --dir artifacts/evidence && ./build/dfexp verify-manifest --dir artifacts/evidence`}
	default:
		return FollowUp{CheckID: checkID, Priority: "P1",
			Action:  "检查该失败项的证据与 SQLite 记录，再重跑对应子实验。",
			Command: `./build/dfexp query --db artifacts/evidence/experiment.db --sql "SELECT * FROM checks WHERE passed=0;"`}
	}
}

func renderMarkdown(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", report.Title)
	fmt.Fprintf(&b, "- 生成时间：`%s`\n", report.GeneratedAt)
	fmt.Fprintf(&b, "- SQLite：`%s`\n", report.Database)
	fmt.Fprintf(&b, "- 自动判定：**%s**（通过 %d，失败 %d）\n\n", report.Automated.Verdict, report.Automated.Passed, report.Automated.Failed)
	b.WriteString("## 自动结论\n\n")
	b.WriteString("| 检查项 | 结果 | 预期 | 观测 | 证据 |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, check := range report.Automated.Checks {
		status := "PASS"
		if !check.Passed {
			status = "FAIL"
		}
		fmt.Fprintf(&b, "| `%s` | **%s** | %s | %s | `%s` |\n",
			check.ID, status, escapeCell(check.Expected), escapeCell(check.Observed), check.Evidence)
	}
	b.WriteString("\n自动结论仅来自脚本/数据库判定，不替代人工确认。\n\n")
	b.WriteString("## 人工确认\n\n")
	b.WriteString("以下项目保持 `PENDING`，必须由审阅者执行命令并勾选。\n\n")
	for _, item := range report.Manual.Items {
		fmt.Fprintf(&b, "- [ ] **%s**（`%s`）\n", item.Title, item.ID)
		fmt.Fprintf(&b, "  - 原因：%s\n", item.Why)
		fmt.Fprintf(&b, "  - 命令：`%s`\n", item.Command)
	}
	b.WriteString("\n## 失败时的可执行后续操作\n\n")
	if len(report.FollowUps) == 0 {
		b.WriteString("当前无自动失败项。可用下列命令复核：\n\n")
		b.WriteString("```bash\n./build/dfexp verify-manifest --dir artifacts/evidence\n./scripts/run-all.sh\n```\n")
	} else {
		for _, item := range report.FollowUps {
			fmt.Fprintf(&b, "- **%s %s**：%s\n", item.Priority, item.CheckID, item.Action)
			fmt.Fprintf(&b, "  ```bash\n  %s\n  ```\n", item.Command)
		}
	}
	b.WriteString("\n## 复现入口\n\n")
	b.WriteString("```bash\n./scripts/run-all.sh\n./build/dfexp report --db artifacts/evidence/experiment.db --evidence artifacts/evidence --out artifacts\n```\n")
	b.WriteString("\n## 证据\n\n")
	b.WriteString("- `artifacts/evidence/experiment.db`：步骤、状态、领域记录、检查、证据哈希。\n")
	b.WriteString("- `artifacts/evidence/traces/*.jsonl`：每个场景逐步导出的输入/状态/结果。\n")
	b.WriteString("- `artifacts/evidence/fuzz/`：libFuzzer 日志、种子与保留语料、崩溃产物目录。\n")
	b.WriteString("- `artifacts/evidence/replay.db`：由记录输入重建的独立回放数据库。\n")
	b.WriteString("- `artifacts/evidence/MANIFEST.sha256`：证据哈希清单。\n")
	return b.String()
}

func renderManual(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 人工确认清单\n\n自动判定：**%s**。人工状态：**%s**。\n\n", report.Automated.Verdict, report.Manual.Status)
	for _, item := range report.Manual.Items {
		fmt.Fprintf(&b, "- [ ] **%s**\n  - ID：`%s`\n  - 原因：%s\n  - 命令：\n\n```bash\n%s\n```\n\n", item.Title, item.ID, item.Why, item.Command)
	}
	return b.String()
}

func escapeCell(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}

func newCheck(id string, passed bool, expected, observed, evidence string) ledger.Check {
	return ledger.Check{
		ID:       id,
		Category: "evidence",
		Passed:   passed,
		Expected: expected,
		Observed: observed,
		Evidence: evidence,
		Detail:   "Computed by report generation.",
	}
}
