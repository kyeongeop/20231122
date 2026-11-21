// Command report renders the SQLite evidence into a Markdown acceptance
// document that ties each attack input to its trigger site, permission
// decision, concrete timestamp and original byte offset.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kyeongeop/20231122/internal/store"
)

func main() {
	base := flag.String("base", ".", "workspace root")
	flag.Parse()

	st, err := store.Open(filepath.Join(*base, "evidence", "audit.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer st.Close()

	cases := []string{"CASE-A1", "CASE-A2", "CASE-A3", "CASE-EMPTY", "CASE-OVERSIZE"}
	out, err := os.Create(filepath.Join(*base, "evidence", "reports", "ACCEPTANCE.md"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer out.Close()

	fmt.Fprintln(out, "# 解析器整数溢出审计 — 验收报告")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "技术栈: Go + libFuzzer(clang 18, ASan/UBSan) + SQLite")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "| 案例 | 锚点 | 原始偏移 | 输入大小 | 权限 | 回绕证据 | hardened 结果 | 时间点 (UTC) |")
	fmt.Fprintln(out, "|------|------|---------:|---------:|------|----------|---------------|--------------|")

	for _, id := range cases {
		rows, err := st.EvidenceByCase(id)
		if err != nil || len(rows) == 0 {
			continue
		}
		first := rows[0]
		hardErr := "(n/a)"
		for _, r := range rows {
			if r.ParserMode == "hardened" {
				if r.ErrText == "" {
					hardErr = "accepted, no error"
				} else {
					hardErr = r.ErrText
				}
			}
		}
		wrap := first.Wrapped
		if wrap == "" {
			wrap = "-"
		}
		fmt.Fprintf(out, "| %s | `%s` | %d | %d | %s | `%s` | %s | %s |\n",
			id, first.Anchor, first.RawOffset, first.InputSize,
			first.Permission, wrap, hardErr, first.EventTime)
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "## 证据指针")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "- 原始输入只读快照: `evidence/original/` (权限 0444)")
	fmt.Fprintln(out, "- 工作语料: `evidence/corpus/`")
	fmt.Fprintln(out, "- 哈希清单: `evidence/reports/SHA256SUMS`")
	fmt.Fprintln(out, "- 结构化日志: `evidence/reports/audit.log`")
	fmt.Fprintln(out, "- SQLite 证据库: `evidence/audit.db`")
	fmt.Fprintln(out, "- libFuzzer 复现: `evidence/crashers/ubsan-vulnerable.log`")
	fmt.Fprintln(out, "- hardened 模糊测试: `evidence/crashers/hardened-fuzz-60s.log`")
	fmt.Println("wrote evidence/reports/ACCEPTANCE.md")
}
