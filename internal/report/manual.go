package report

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"example.com/migration-review/internal/model"
)

func writeManual(out *bytes.Buffer, views []runView, opts Options) {
	fmt.Fprintln(out, "## 人工确认")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "> 以下项目必须由授权复核人完成。自动检查通过不等于业务授权成立；未填写签字栏前，报告状态保持“未确认”。")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "- [ ] **M1 策略基线**：确认 `%s` 与已批准版本一致，尤其确认迁移账号不具备 `destructive`。\n",
		strings.ReplaceAll(opts.PolicyPath, "`", "'"))
	fmt.Fprintln(out, "- [ ] **M2 攻击语义**：人工阅读原始攻击载荷，确认危险操作确实指向受保护对象，而不是解析器误报。")
	fmt.Fprintln(out, "- [ ] **M3 特权操作**：如存在 `destructive` / `attach` / `admin`，确认审批单、执行人、时间窗和独立 `--approval-id` 真实有效。")
	fmt.Fprintln(out, "- [ ] **M4 取消策略**：确认中途取消的时机、回滚结果和重试窗口符合变更规范。")
	fmt.Fprintln(out, "- [ ] **M5 证据保管**：确认证据库及其 `-wal` 文件已复制到独立、受限、可追溯的保管位置。")
	fmt.Fprintln(out, "- [ ] **M6 最终签字**：逐项核对本报告自动结论与证据哈希后签字。")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "**人工复核记录（留空表示尚未确认）**")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "| 运行 | 复核结论（同意/拒绝/补充） | 复核人 | 时间（UTC） | 签字/工单 |")
	fmt.Fprintln(out, "| --- | --- | --- | --- | --- |")
	for _, view := range views {
		fmt.Fprintf(out, "| %s |  |  |  |  |\n", code(view.record.RunID))
	}
	fmt.Fprintln(out)
	hashes := policyHashes(views)
	if len(hashes) == 0 {
		fmt.Fprintln(out, "策略哈希：无运行记录。")
	} else {
		fmt.Fprintln(out, "本次涉及的策略哈希：")
		for _, hash := range hashes {
			fmt.Fprintf(out, "- %s\n", code(hash))
		}
	}
	fmt.Fprintln(out)
}

func policyHashes(views []runView) []string {
	seen := map[string]bool{}
	var hashes []string
	for _, view := range views {
		hash := view.record.Decision.PolicySHA256
		if hash != "" && !seen[hash] {
			seen[hash] = true
			hashes = append(hashes, hash)
		}
	}
	sort.Strings(hashes)
	return hashes
}

func writeFollowUps(out *bytes.Buffer, views []runView, checks []check, opts Options) {
	fmt.Fprintln(out, "## 失败与后续操作")
	fmt.Fprintln(out)
	actions := 0
	for _, item := range checks {
		if item.Status == "PASS" {
			continue
		}
		actions++
		fmt.Fprintf(out, "### 自动检查未通过：%s\n\n", item.Name)
		fmt.Fprintln(out, autoCheckAction(item, opts))
		fmt.Fprintln(out)
	}
	for _, view := range views {
		if view.record.Status == model.StatusAllowed {
			continue
		}
		actions++
		writeRunAction(out, view, opts)
	}
	if actions == 0 {
		fmt.Fprintln(out, "当前没有 FAIL、NOT_COVERED、DENIED、CANCELLED 或 FAILED 项。上线前仍须完成人工确认清单。")
		fmt.Fprintln(out)
		return
	}
	fmt.Fprintln(out, "执行上述操作后，重新生成报告并确认所有自动检查为 PASS；任何 `--allow-destructive`、`--allow-attach` 或 `--allow-admin` 的使用都必须绑定人工审批单。")
	fmt.Fprintln(out)
}

func autoCheckAction(item check, opts Options) string {
	switch item.Name {
	case "策略文件与证据一致":
		return strings.Join([]string{
			"1. 获取本次运行实际使用的策略快照：`migrationctl inspect --evidence " + shellQuote(opts.EvidencePath) + " --run <run-id> --include-content`。",
			"2. 将 `policy/snapshot.json` 与已批准策略版本逐字比对，禁止用当前 `config/policy.json` 覆盖历史快照。",
			"3. 修正策略路径或恢复已批准策略后重新生成报告；若证据中的策略未经批准，停止上线。",
		}, "\n")
	case "所有运行已完结":
		return strings.Join([]string{
			"1. 检查 `RUNNING` 是否来自进程崩溃或强制终止，保留证据库及 `-wal`。",
			"2. 查询目标库 schema，并与最后一次 `schema/before.json` 快照对照。",
			"3. 在确认目标库状态前停止写入；恢复或修复后用新 run id 重跑，禁止删除未完成记录。",
		}, "\n")
	case "日志哈希链完整", "证据内容哈希完整":
		return strings.Join([]string{
			"1. 立即冻结证据库，保留 `" + opts.EvidencePath + "` 及同目录 `-wal` / `-shm` 文件。",
			"2. 停止继续迁移，执行 `migrationctl verify --evidence " + shellQuote(opts.EvidencePath) + "` 定位首个断链。",
			"3. 如证据被篡改或损坏，不得用该结论放行；从备份恢复并重新执行迁移复核。",
		}, "\n")
	case "旧格式兼容", "新格式兼容", "中途取消并回滚", "危险权限攻击被拦截":
		return strings.Join([]string{
			"1. 补充对应场景的可复现输入，并保留原始字节。",
			"2. 运行 `go test ./...` 与 `scripts/run_libfuzzer.sh`，确认不是解析或权限回归。",
			"3. 重新执行 `migrationctl demo`，将新证据库和报告一起送审。",
		}, "\n")
	default:
		return "1. 在 `migrationctl inspect` 中核对运行记录。\n2. 保留证据并通知变更负责人；修复后重新执行完整复核。"
	}
}

func writeRunAction(out *bytes.Buffer, view runView, opts Options) {
	record := view.record
	fmt.Fprintf(out, "### 运行 %s：%s\n\n", code(record.RunID), statusLabel(record.Status))
	fmt.Fprintf(out, "原因：%s\n\n", cell(record.Reason))
	fmt.Fprintln(out, "可执行操作：")
	switch record.Status {
	case model.StatusRunning:
		fmt.Fprintln(out, "1. 立即检查证据库中最后一条日志和 `schema/before.json`：")
		fmt.Fprintf(out, "   `migrationctl inspect --evidence %s --run %s`\n", shellQuote(opts.EvidencePath), shellQuote(record.RunID))
		fmt.Fprintln(out, "2. 检查目标库是否存在未提交的半成品对象；确认前停止所有写入。")
		fmt.Fprintln(out, "3. 若事务未提交，修复后使用新 run id 重跑；若提交状态不确定，从备份恢复。")
	case model.StatusDenied:
		fmt.Fprintln(out, "1. 不要为同一输入启用危险能力开关；先保留并上报攻击载荷：")
		fmt.Fprintf(out, "   `migrationctl inspect --evidence %s --run %s`\n", shellQuote(opts.EvidencePath), shellQuote(record.RunID))
		fmt.Fprintln(out, "2. 安全事件流程：轮换该 actor 凭据，检查构建/发布系统是否被污染，并核对 `requested_by`。")
		fmt.Fprintln(out, "3. 若确认是误报，只能修改策略并走代码评审；在隔离库重放：")
		fmt.Fprintf(out, "   `migrationctl review --input %s --db /tmp/review-staging.db --policy %s --evidence /tmp/review-staging-evidence.db`\n",
			shellQuote(record.InputPath), shellQuote(opts.PolicyPath))
	case model.StatusCancelled:
		fmt.Fprintln(out, "1. 先核对回滚证据与目标库状态：")
		fmt.Fprintf(out, "   `migrationctl verify --evidence %s --run %s`\n", shellQuote(opts.EvidencePath), shellQuote(record.RunID))
		fmt.Fprintln(out, "2. 在 SQLite 中确认未出现半成品对象：`SELECT name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%';`")
		fmt.Fprintln(out, "3. 修复取消原因后，在 staging 使用新的 run id 重跑，不复用已取消运行：")
		fmt.Fprintf(out, "   `migrationctl review --input %s --db /tmp/review-staging.db --policy %s --evidence /tmp/review-staging-evidence.db`\n",
			shellQuote(record.InputPath), shellQuote(opts.PolicyPath))
	case model.StatusFailed:
		fmt.Fprintln(out, "1. 导出失败日志与 schema 快照：")
		fmt.Fprintf(out, "   `migrationctl inspect --evidence %s --run %s`\n", shellQuote(opts.EvidencePath), shellQuote(record.RunID))
		fmt.Fprintln(out, "2. 对照 `schema_before` 快照检查目标库；若提交状态不确定，停止写入并从备份恢复。")
		fmt.Fprintln(out, "3. 修复根因后使用新证据库重跑；不得删除本次失败证据。")
	default:
		fmt.Fprintln(out, "1. 执行 `migrationctl inspect` 核对日志。")
	}
	fmt.Fprintln(out)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
