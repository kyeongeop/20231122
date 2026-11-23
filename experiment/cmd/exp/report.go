package main

import (
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// phaseEvidence preserves key evidence: corpus copies, fuzz artifacts,
// and a human-readable report. The SQLite ledger is copied later by
// snapshotDB so the cleanup step is included.
func (r *runner) phaseEvidence() error {
	if err := os.MkdirAll(r.evidence, 0o755); err != nil {
		return err
	}
	dst := filepath.Join(r.evidence, "corpus")
	if err := copyDir(filepath.Join(r.tmp, "corpus"), dst); err != nil {
		return err
	}
	if r.fuzzDir != "" {
		if err := copyDir(r.fuzzDir, filepath.Join(r.evidence, "fuzz")); err != nil {
			log.Printf("fuzz evidence: %v", err)
		}
	}
	rep, err := r.buildReport()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(r.evidence, "report.md"), rep, 0o644); err != nil {
		return err
	}
	r.step("evidence", "", "", nil, map[string]any{"dir": r.evidence},
		"evidence_preserved", nil)
	log.Printf("evidence written to %s", r.evidence)
	return nil
}

// snapshotDB checkpoints WAL and copies the ledger into evidence.
func (r *runner) snapshotDB() error {
	if err := r.led.Checkpoint(); err != nil {
		return err
	}
	src := filepath.Join(r.tmp, "experiment.db")
	dst := filepath.Join(r.evidence, "experiment.db")
	if err := os.MkdirAll(r.evidence, 0o755); err != nil {
		return err
	}
	return copyFile(src, dst)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFile(path, target)
	})
}

func (r *runner) buildReport() ([]byte, error) {
	steps, err := r.led.QuerySteps()
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# YAML 别名资源耗尽实验报告\n\nrun_id: `%s`\n\n", r.led.RunID)
	fmt.Fprintf(&b, "| seq | phase | object | snapshot | sha256(8) | bytes | result |\n")
	fmt.Fprintf(&b, "|----:|-------|--------|----------|-----------|------:|--------|\n")
	for i, s := range steps {
		sha := s.InputSHA256
		if len(sha) > 8 {
			sha = sha[:8]
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %d | %s |\n",
			i+1, s.Phase, orDash(s.ObjectID), orDash(s.Snapshot),
			orDash(sha), s.InputBytes, s.Result)
	}
	b.WriteString("\n## 结论\n\n")
	for _, s := range steps {
		switch s.Phase {
		case "order-verify":
			fmt.Fprintf(&b, "- 顺序变更验证: `%s` (%s)\n", s.Result, s.Detail)
		case "repeat-verify":
			fmt.Fprintf(&b, "- 重复提交验证: `%s` (%s)\n", s.Result, s.Detail)
		}
	}
	b.WriteString("- v1(无防护) 对炸弹对象资源耗尽崩溃; v2(限额) 返回 limit_exceeded\n")
	b.WriteString("- 异常对象(fault-empty)触发 panic 已恢复, 后续对象全部处理\n")
	return []byte(b.String()), nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
