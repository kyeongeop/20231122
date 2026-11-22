// Command report renders the acceptance report from the SQLite store.
// Every case is presented with its concrete creation timestamp, SHA-256
// anchor, anchor marker offsets and exact offending byte offsets, so the
// attack input, trigger position, permission verdict and log evidence line up.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"dnscheck/internal/store"
)

type caseDetail struct {
	store.CaseRow
	Findings []store.FindingRow
}

func main() {
	dbPath := flag.String("db", "artifacts/dnscheck.db", "SQLite database path")
	jsonOut := flag.String("json", "artifacts/report.json", "JSON report output path")
	mdOut := flag.String("md", "artifacts/report.md", "Markdown report output path")
	flag.Parse()

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	if err := st.VerifyIntegrity(); err != nil {
		log.Fatalf("integrity: %v", err)
	}
	cases, err := st.ListCases()
	if err != nil {
		log.Fatalf("list cases: %v", err)
	}
	counts, err := st.VerdictCounts()
	if err != nil {
		log.Fatalf("counts: %v", err)
	}

	details := make([]caseDetail, 0, len(cases))
	for _, c := range cases {
		fs, err := st.FindingsOf(c.ID)
		if err != nil {
			log.Fatalf("findings %d: %v", c.ID, err)
		}
		details = append(details, caseDetail{CaseRow: c, Findings: fs})
	}

	report := map[string]any{
		"integrity": "all stored raw inputs match their sha256 anchors",
		"counts":    counts,
		"cases":     details,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(*jsonOut, data, 0o644); err != nil {
		log.Fatalf("write json: %v", err)
	}
	if err := writeMarkdown(*mdOut, counts, details); err != nil {
		log.Fatalf("write md: %v", err)
	}
	fmt.Printf("wrote %s and %s (%d cases)\n", *jsonOut, *mdOut, len(details))
}

func writeMarkdown(path string, counts []store.CountRow, details []caseDetail) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintln(f, "# DNS 名称编码校验 · 验收报告")
	fmt.Fprintln(f)
	fmt.Fprintln(f, "技术栈固定：Go（判定管线）+ libFuzzer（模糊测试）+ SQLite（证据存储）。")
	fmt.Fprintln(f, "完整性：库内全部原始输入均通过 SHA-256 重算校验，原始材料未被修改。")
	fmt.Fprintln(f)
	fmt.Fprintln(f, "## 判定汇总")
	fmt.Fprintln(f)
	fmt.Fprintln(f, "| 权限判定 | 用例数 |")
	fmt.Fprintln(f, "|---|---|")
	for _, c := range counts {
		fmt.Fprintf(f, "| %s | %d |\n", c.Label, c.Count)
	}
	fmt.Fprintln(f)
	fmt.Fprintln(f, "## 用例明细（时间点 + 原始偏移）")
	fmt.Fprintln(f)
	for _, d := range details {
		fmt.Fprintf(f, "### %s — %s\n", d.Label, d.Verdict)
		fmt.Fprintf(f, "- 入库时间（UTC）：%s\n", d.CreatedAt)
		fmt.Fprintf(f, "- 原始长度：%d 字节；SHA-256：%s\n", d.RawLen, d.SHA256)
		fmt.Fprintf(f, "- 权限判断：%s\n", d.Verdict)
		fmt.Fprintf(f, "- 结论依据：%s\n", d.Rationale)
		if len(d.Findings) == 0 {
			if d.Verdict == "allow" {
				fmt.Fprintln(f, "- 触发位置：无（三段锚点全部通过）")
			} else {
				fmt.Fprintln(f, "- 触发位置：不适用（输入在 guard 阶段被隔离，未进入锚点解析）")
			}
		} else {
			fmt.Fprintln(f, "- 触发位置（攻击输入 → 锚点 → 原始偏移）：")
			for _, g := range d.Findings {
				fmt.Fprintf(f, "  - %s | 标记偏移=%d | 字节原始偏移=%d | 阶段=%s | 代码=%s | %s\n",
					g.Anchor, g.MarkerOff, g.ByteOffset, g.Stage, g.Code, g.Message)
			}
		}
		fmt.Fprintln(f)
	}
	return nil
}
