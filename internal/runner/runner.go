package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	HarnessPath string
	Timeout     time.Duration
}

type Outcome struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Signal   int
	TimedOut bool
	Err      error
}

func RunSample(ctx context.Context, cfg Config, sample []byte) (Outcome, error) {
	if cfg.HarnessPath == "" {
		return Outcome{}, errors.New("harness path is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	tempDir, err := os.MkdirTemp("", "auditfix-sample-")
	if err != nil {
		return Outcome{}, err
	}
	defer os.RemoveAll(tempDir)
	samplePath := filepath.Join(tempDir, "input")
	if err := os.WriteFile(samplePath, sample, 0o600); err != nil {
		return Outcome{}, err
	}

	runCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	args := []string{
		"-runs=1",
		"-verbosity=0",
		"-print_final_stats=0",
		"-detect_leaks=0",
		samplePath,
	}
	cmd := exec.CommandContext(runCtx, cfg.HarnessPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = time.Second
	cmd.Env = append(os.Environ(),
		"ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0",
		"UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=0",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()

	outcome := Outcome{Stdout: stdout.String(), Stderr: stderr.String()}
	if cmd.ProcessState != nil {
		outcome.ExitCode = cmd.ProcessState.ExitCode()
		if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			outcome.Signal = int(status.Signal())
		}
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		outcome.TimedOut = true
		outcome.Err = fmt.Errorf("sample timed out after %s", cfg.Timeout)
		return outcome, nil
	}
	if ctx.Err() != nil {
		outcome.Err = ctx.Err()
		return outcome, ctx.Err()
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		outcome.Err = fmt.Errorf("harness exited with status %d: %s",
			outcome.ExitCode, concise(stderr.String()))
		return outcome, nil
	}
	if err != nil {
		return outcome, fmt.Errorf("execute harness: %w", err)
	}
	return outcome, nil
}

func concise(value string) string {
	value = strings.ToValidUTF8(strings.TrimSpace(value), "\uFFFD")
	if len(value) > 300 {
		return value[:300] + "..."
	}
	return value
}
