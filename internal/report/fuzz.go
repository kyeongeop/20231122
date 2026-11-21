package report

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"pathaliaslab/internal/ledger"
)

var (
	executionPattern = regexp.MustCompile(`stat::number_of_executed_units:\s*([0-9]+)`)
	runsPattern      = regexp.MustCompile(`Done\s+([0-9]+)\s+runs`)
)

func collectFuzz(artifactDir string) FuzzSummary {
	fuzzDir := filepath.Join(artifactDir, "fuzz")
	summary := FuzzSummary{
		Status:         "not_run",
		LogPath:        filepath.ToSlash(filepath.Join(fuzzDir, "fuzz.log")),
		BinaryPath:     filepath.ToSlash(filepath.Join(fuzzDir, "pathalias_fuzzer")),
		CrashArtifacts: make([]string, 0),
	}
	statusBytes, statusErr := os.ReadFile(filepath.Join(fuzzDir, "status.txt"))
	if statusErr == nil {
		summary.Status = strings.SplitN(strings.TrimSpace(string(statusBytes)), "\n", 2)[0]
	}
	logBytes, logErr := os.ReadFile(summary.LogPath)
	if logErr == nil {
		summary.Available = true
		summary.LogSHA256 = ledger.SHA256(logBytes)
		text := string(logBytes)
		for _, match := range executionPattern.FindAllStringSubmatch(text, -1) {
			if value, err := strconv.ParseInt(match[1], 10, 64); err == nil {
				summary.Executions = value
			}
		}
		if summary.Executions == 0 {
			for _, match := range runsPattern.FindAllStringSubmatch(text, -1) {
				if value, err := strconv.ParseInt(match[1], 10, 64); err == nil {
					summary.Executions = value
				}
			}
		}
		lines := strings.Split(strings.TrimSpace(text), "\n")
		if len(lines) > 0 {
			summary.Detail = lines[len(lines)-1]
		}
	}
	if binaryBytes, err := os.ReadFile(summary.BinaryPath); err == nil {
		summary.Available = true
		summary.BinarySHA256 = ledger.SHA256(binaryBytes)
	}
	corpusEntries, _ := os.ReadDir(filepath.Join(fuzzDir, "corpus"))
	for _, entry := range corpusEntries {
		if !entry.IsDir() {
			summary.CorpusFiles++
		}
	}
	artifactEntries, _ := os.ReadDir(fuzzDir)
	for _, entry := range artifactEntries {
		name := entry.Name()
		if strings.HasPrefix(name, "crash-") || strings.HasPrefix(name, "timeout-") ||
			strings.HasPrefix(name, "oom-") || strings.HasPrefix(name, "leak-") {
			summary.CrashArtifacts = append(summary.CrashArtifacts,
				filepath.ToSlash(filepath.Join(fuzzDir, name)))
		}
	}
	if len(summary.CrashArtifacts) > 0 {
		summary.Status = "failed"
		summary.Detail = "libFuzzer produced a failing artifact"
	}
	if summary.Available && summary.Status == "not_run" {
		summary.Status = "failed"
		summary.Detail = "fuzzer evidence exists but status.txt is missing"
	}
	return summary
}
