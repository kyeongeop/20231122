package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ckaudit/internal/store"
)

type Outcome struct {
	Status     string
	ExitCode   int
	Findings   []store.Finding
	Evidence   []store.Evidence
	StderrText string
}

func (t *Toolchain) sampleDir(workDir string, sampleID int64) string {
	return filepath.Join(workDir, "evidence", strconv.FormatInt(sampleID, 10))
}

func writeEvidenceFile(dir, name string, data []byte) (store.Evidence, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return store.Evidence{}, err
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return store.Evidence{}, err
	}
	sum := sha256.Sum256(data)
	return store.Evidence{
		Kind: strings.TrimSuffix(name, filepath.Ext(name)),
		Path: path, SHA256: hex.EncodeToString(sum[:]),
		Bytes: int64(len(data)), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func parseCKA(stderr string) []store.Finding {
	var findings []store.Finding
	for _, line := range strings.Split(stderr, "\n") {
		if !strings.HasPrefix(line, "CKA|") {
			continue
		}
		parts := strings.SplitN(line, "|", 4)
		if len(parts) < 4 || parts[1] == "SUMMARY" {
			continue
		}
		findings = append(findings, store.Finding{
			Severity: parts[1], Code: parts[2], Message: parts[3],
		})
	}
	return findings
}

func classify(exitCode int) string {
	switch {
	case exitCode == 0:
		return "ok"
	case exitCode >= 70:
		return "crash"
	default:
		return "error"
	}
}

func (t *Toolchain) RerunSample(ctx context.Context, workDir string, smp store.Sample) (*Outcome, error) {
	dir := t.sampleDir(workDir, smp.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	inputPath := filepath.Join(dir, "input.bin")
	if err := os.WriteFile(inputPath, []byte(smp.Input), 0o644); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, t.PlainBin, inputPath)
	cmd.Env = append(os.Environ(), "CK_AUDIT_DUMP=1",
		"ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:symbolize=0")
	var combined strings.Builder
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return nil, err
		}
	}
	stderr := combined.String()

	var evidence []store.Evidence
	inputEv, err := writeEvidenceFile(dir, "input.bin", []byte(smp.Input))
	if err != nil {
		return nil, err
	}
	inputEv.Kind = "input"
	evidence = append(evidence, inputEv)

	outEv, err := writeEvidenceFile(dir, "stderr.log", []byte(stderr))
	if err != nil {
		return nil, err
	}
	outEv.Kind = "stderr"
	evidence = append(evidence, outEv)

	status := classify(exitCode)
	if status == "crash" {
		crashEv, cerr := writeEvidenceFile(dir, "crash.log", []byte(stderr))
		if cerr != nil {
			return nil, cerr
		}
		crashEv.Kind = "crash"
		evidence = append(evidence, crashEv)
	}

	return &Outcome{
		Status: status, ExitCode: exitCode,
		Findings: parseCKA(stderr), Evidence: evidence, StderrText: stderr,
	}, nil
}
