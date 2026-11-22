package report

import (
	"bytes"
	"fmt"
)

func writeEvidenceAccess(out *bytes.Buffer, opts Options) {
	fmt.Fprintln(out, "## 证据访问与复算")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "以下命令可从留存的 SQLite 证据库重新生成报告和核验哈希：")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "```bash")
	fmt.Fprintf(out, "migrationctl report --evidence %s --policy %s --out review-report.md\n",
		shellQuote(opts.EvidencePath), shellQuote(opts.PolicyPath))
	fmt.Fprintf(out, "migrationctl verify --evidence %s\n", shellQuote(opts.EvidencePath))
	fmt.Fprintf(out, "migrationctl inspect --evidence %s --run <run-id>\n", shellQuote(opts.EvidencePath))
	fmt.Fprintln(out, "```")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "关键表：")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "- `runs`：权限结论、执行状态、触发位置、schema 前后哈希和日志头。")
	fmt.Fprintln(out, "- `logs`：带 `prev_hash` / `entry_hash` 的追加式日志，可检测删除、修改和乱序。")
	fmt.Fprintln(out, "- `evidence`：原始输入、归一化清单、策略快照、权限判定和 schema 快照，逐对象记录 SHA-256。")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "证据库中的原始输入可能会触发安全扫描规则；分析时应使用只读副本，不要直接在报告渲染器中执行其中的 SQL。")
}
