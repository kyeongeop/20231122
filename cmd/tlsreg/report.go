package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"tlsreg/internal/journal"
)

// cmdReport renders the journal of one run into a Markdown evidence report.
func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	dbPath := fs.String("db", "", "sqlite journal path")
	runID := fs.String("run", "", "run id")
	out := fs.String("out", "", "output markdown path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	j, err := journal.Open(*dbPath)
	if err != nil {
		return err
	}
	defer j.Close()

	counts, err := j.Counts(*runID)
	if err != nil {
		return err
	}
	steps, err := j.LoadSteps(*runID)
	if err != nil {
		return err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# TLS 配置回归实验报告\n\nrun id: `%s`\n\n", *runID)
	fmt.Fprintf(&b, "## 步骤计数\n\n")
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "- `%s`: %d\n", k, counts[k])
	}
	fmt.Fprintf(&b, "\n## 分歧记录（v1 vs v2）\n\n")

	// divergence details come from comparisons; query via steps is enough for
	// the per-record table, but use a dedicated query for clarity.
	rows, err := j.QueryComparisons(*runID)
	if err != nil {
		return err
	}
	fmt.Fprintf(&b, "| phase | record | divergent | detail |\n|---|---|---|---|\n")
	for _, c := range rows {
		mark := ""
		if c.Divergent {
			mark = "**YES**"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.Phase, c.RecordID, mark, c.Detail)
	}
	fmt.Fprintf(&b, "\n## 关键步骤样本（每阶段前 3 条）\n\n")
	seen := map[string]int{}
	fmt.Fprintf(&b, "| seq | phase | record | version | status | input sha256 |\n|---|---|---|---|---|---|\n")
	for _, s := range steps {
		if seen[s.Phase] >= 3 {
			continue
		}
		seen[s.Phase]++
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | `%s` |\n",
			s.Seq, s.Phase, s.RecordID, s.Version, s.Status, s.InputHash[:16])
	}
	return os.WriteFile(*out, []byte(b.String()), 0o644)
}
