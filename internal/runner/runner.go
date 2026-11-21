// Package runner executes single-sample replays against the libFuzzer-built
// harnesses and turns each execution into timestamped evidence.
package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"krfix/internal/store"
)

// Phases are the two harness variants every sample is replayed against.
const (
	PhaseVuln  = "vuln"
	PhaseFixed = "fixed"
)

// Verdict labels derived from process exit codes.
const (
	LabelRotationFailure = "ROTATION_FAILURE_REPRODUCED" // exit 133/77: stale key accepted
	LabelStaleRejected   = "STALE_KEY_REJECTED"          // exit 78: fix works
	LabelAccepted        = "FRAME_ACCEPTED"              // exit 0
	LabelCrashed         = "HARNESS_CRASH"
)

// Config locates the build outputs and evidence directory.
type Config struct {
	WorkDir     string // .krfix root
	ReplayVuln  string // kr_replay_vuln binary
	ReplayFixed string // kr_replay_fixed binary
	EvidenceDir string
}

// Result is one replay outcome.
type Result struct {
	ExitCode    int
	VerdictCode int
	Label       string
	DurationNS  int64
	StdoutLog   string
	StderrLog   string
}

func replayBin(cfg Config, phase string) string {
	if phase == PhaseVuln {
		return cfg.ReplayVuln
	}
	return cfg.ReplayFixed
}

// Classify maps an exit code to the acceptance verdict.
func Classify(phase string, exitCode int) (int, string) {
	switch phase {
	case PhaseVuln:
		if exitCode == 133 || exitCode == 77 {
			return 77, LabelRotationFailure
		}
		if exitCode == 0 {
			return 0, LabelAccepted
		}
		return exitCode, LabelCrashed
	case PhaseFixed:
		if exitCode == 78 {
			return 78, LabelStaleRejected
		}
		if exitCode == 0 {
			return 0, LabelAccepted
		}
		return exitCode, LabelCrashed
	}
	return exitCode, LabelCrashed
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Replay runs one sample through one harness phase, streaming stdout/stderr
// to evidence files. Context cancellation kills the child (stop/resume).
func Replay(ctx context.Context, cfg Config, sample *store.Sample, phase string) (*Result, error) {
	bin := replayBin(cfg, phase)
	if _, err := os.Stat(bin); err != nil {
		return nil, fmt.Errorf("replay binary missing (%s); run 'krfix build' first: %w", bin, err)
	}
	if _, err := os.Stat(sample.RawPath); err != nil {
		return nil, fmt.Errorf("sample copy missing: %w", err)
	}

	started := time.Now()
	cmd := exec.CommandContext(ctx, bin, sample.RawPath)
	cmd.Env = append(os.Environ(),
		"ASAN_OPTIONS=abort_on_error=1:exitcode=99:handle_segv=1")
	if delay := os.Getenv("KRFIX_REPLAY_DELAY_MS"); delay != "" {
		// Test hook: slow each replay so stop/resume can be exercised
		// deterministically. Unset in normal operation.
		cmd.Env = append(cmd.Env, "KRFIX_REPLAY_DELAY_MS="+delay)
	}

	logDir := filepath.Join(cfg.EvidenceDir, sample.Name, phase)
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, err
	}
	attemptTag := started.UTC().Format("20060102T150405.000000000Z")
	stdoutPath := filepath.Join(logDir, attemptTag+".stdout.log")
	stderrPath := filepath.Join(logDir, attemptTag+".stderr.log")
	outF, err := os.Create(stdoutPath)
	if err != nil {
		return nil, err
	}
	defer outF.Close()
	errF, err := os.Create(stderrPath)
	if err != nil {
		return nil, err
	}
	defer errF.Close()
	cmd.Stdout = outF
	cmd.Stderr = errF

	err = cmd.Run()
	duration := time.Since(started).Nanoseconds()

	res := &Result{
		DurationNS: duration,
		StdoutLog:  stdoutPath,
		StderrLog:  stderrPath,
	}
	if err == nil {
		res.ExitCode = 0
	} else if ee, ok := err.(*exec.ExitError); ok {
		res.ExitCode = ee.ExitCode()
	} else if ctx.Err() != nil {
		return nil, ctx.Err()
	} else {
		return nil, err
	}
	res.VerdictCode, res.Label = Classify(phase, res.ExitCode)
	return res, nil
}

// HashEvidence returns the sha256 of a captured evidence file.
func HashEvidence(path string) (string, error) { return hashFile(path) }
