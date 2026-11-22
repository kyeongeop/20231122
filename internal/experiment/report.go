package experiment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func writeReportFiles(report *Report, outDir string) error {
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	reportJSON = append(reportJSON, '\n')
	if err := os.WriteFile(filepath.Join(outDir, "report.json"), reportJSON, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "report.md"), []byte(renderMarkdown(report)), 0o644); err != nil {
		return err
	}
	recordJSON, err := json.MarshalIndent(report.Record, "", "  ")
	if err != nil {
		return err
	}
	recordJSON = append(recordJSON, '\n')
	return os.WriteFile(filepath.Join(outDir, "records", "record.json"), recordJSON, 0o644)
}

func renderMarkdown(report *Report) string {
	var b strings.Builder
	b.WriteString("# GraphQL 查询深度：可回放实验\n\n")
	b.WriteString("本实验以“首个错误状态”为判定，不计算或输出总分。\n\n")
	b.WriteString("## 首个错误状态\n\n")
	writeFirstErrorLine(&b, "截断记录", report.FirstErrors["truncated"])
	writeFirstErrorLine(&b, "恢复后的对照", report.FirstErrors["recovered_control"])
	writeFirstErrorLine(&b, "顺序改变", report.FirstErrors["check_order_changed"])
	writeFirstErrorLine(&b, "重复提交", report.FirstErrors["check_duplicate_submission"])

	b.WriteString("\n## 记录与恢复\n\n")
	b.WriteString("| 项目 | 值 |\n|---|---|\n")
	writeRow(&b, "原始 SHA-256", report.Record.OriginalSHA256)
	writeRow(&b, "截断 SHA-256", report.Record.TruncatedSHA256)
	writeRow(&b, "恢复 SHA-256", report.Record.RecoverySHA256)
	writeRow(&b, "截断偏移", fmt.Sprintf("%d", report.Record.TruncationOffset))
	writeRow(&b, "被截断字节", fmt.Sprintf("%d", report.Record.OriginalBytes-report.Record.TruncatedBytes))
	writeRow(&b, "恢复后等于原始记录", fmt.Sprintf("%t", report.Record.RecoveredEqualsOriginal))
	writeRow(&b, "深度上限", fmt.Sprintf("%d", report.Limit))
	b.WriteString("\n被截断的后缀：`")
	b.WriteString(strings.ReplaceAll(report.Record.OmittedSuffix, "`", "\\`"))
	b.WriteString("`\n")

	for _, run := range report.Runs {
		b.WriteString("\n## 运行 `")
		b.WriteString(run.RunID)
		b.WriteString("`\n\n")
		b.WriteString("场景：`" + run.Scenario + "`；状态：`" + run.Status + "`\n\n")
		if run.FirstError != nil {
			b.WriteString(fmt.Sprintf("首个错误：`seq=%d stage=%s code=%s` — %s\n\n",
				run.FirstError.Seq, run.FirstError.Stage, run.FirstError.Code,
				escapeMarkdown(run.FirstError.Detail)))
		}
		b.WriteString("| Seq | Stage | Input | State before → after | Result | Status |\n")
		b.WriteString("|---:|---|---|---|---|---|\n")
		for _, step := range run.Steps {
			status := step.Status
			if step.ErrorCode != "" {
				status += ": " + step.ErrorCode + " — " + step.ErrorDetail
			}
			b.WriteString(fmt.Sprintf("| %d | `%s` | `%s` | `%s` → `%s` | `%s` | %s |\n",
				step.Seq, step.Stage, escapeCell(step.Input), escapeCell(step.StateBefore),
				escapeCell(step.StateAfter), escapeCell(step.Result), escapeCell([]byte(status))))
		}
	}

	b.WriteString("\n## 重放与提交检查\n\n")
	b.WriteString("| Check | Status | First error | Observed |\n|---|---|---|---|\n")
	for _, check := range report.Checks {
		first := "—"
		if check.FirstError != nil {
			first = fmt.Sprintf("seq=%d stage=%s code=%s", check.FirstError.Seq,
				check.FirstError.Stage, check.FirstError.Code)
		}
		b.WriteString(fmt.Sprintf("| `%s` | `%s` | %s | `%s` |\n",
			check.CheckID, check.Status, escapeCell([]byte(first)), escapeCell(check.Observed)))
	}
	b.WriteString("\n## 证据文件\n\n")
	b.WriteString("- SQLite：`" + report.DatabasePath + "`\n")
	b.WriteString("- JSON：`" + filepath.Join(filepath.Dir(report.DatabasePath), "report.json") + "`\n")
	b.WriteString("- 清单：`" + report.ManifestPath + "`\n")
	b.WriteString("- 原始记录：`" + report.Record.OriginalPath + "`\n")
	b.WriteString("- 截断记录：`" + report.Record.TruncatedPath + "`\n")
	b.WriteString("- 恢复记录：`" + report.Record.RecoveredPath + "`\n")
	return b.String()
}

func writeFirstErrorLine(b *strings.Builder, label string, failure *ErrorView) {
	if failure == nil {
		b.WriteString("- " + label + "：无错误\n")
		return
	}
	b.WriteString(fmt.Sprintf("- %s：`seq=%d` `stage=%s` `code=%s` — %s\n",
		label, failure.Seq, failure.Stage, failure.Code, escapeMarkdown(failure.Detail)))
}

func writeRow(b *strings.Builder, key, value string) {
	b.WriteString(fmt.Sprintf("| %s | `%s` |\n", key, escapeCell([]byte(value))))
}

func escapeMarkdown(value string) string {
	value = strings.ReplaceAll(value, "`", "\\`")
	return strings.ReplaceAll(value, "\n", " ")
}

func escapeCell(value []byte) string {
	text := strings.ReplaceAll(string(value), "|", "\\|")
	text = strings.ReplaceAll(text, "`", "'")
	text = strings.ReplaceAll(text, "\n", " ")
	return text
}

func writeManifest(outDir, manifestPath string) error {
	var paths []string
	err := filepath.WalkDir(outDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		absoluteManifest, _ := filepath.Abs(manifestPath)
		absolutePath, _ := filepath.Abs(path)
		if absolutePath == absoluteManifest {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(paths)
	var b strings.Builder
	for _, path := range paths {
		hash, err := hashFile(path)
		if err != nil {
			return err
		}
		b.WriteString(hash)
		b.WriteString("  ")
		b.WriteString(relTo(outDir, path))
		b.WriteByte('\n')
	}
	return os.WriteFile(manifestPath, []byte(b.String()), 0o644)
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
