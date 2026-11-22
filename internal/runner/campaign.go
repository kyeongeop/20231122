package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"ckaudit/internal/audit"
	"ckaudit/internal/store"
)

type CampaignConfig struct {
	WorkDir string
	Name    string
	MaxRuns int64
	MaxLen  int
	Seed    int64
	Jobs    int
}

type LockError struct{ Path string }

func (e *LockError) Error() string {
	return fmt.Sprintf("another campaign is active (lock %s); use 'stop' or remove stale lock", e.Path)
}

func lockPath(workDir string) string { return filepath.Join(workDir, "campaign.lock") }

func acquireLock(workDir string) error {
	path := lockPath(workDir)
	if data, err := os.ReadFile(path); err == nil {
		pid, perr := strconv.Atoi(strings.TrimSpace(string(data)))
		if perr == nil && processAlive(pid) {
			return &LockError{Path: path}
		}
	}
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o644)
}

func releaseLock(workDir string) {
	_ = os.Remove(lockPath(workDir))
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); err == nil {
		return true
	}
	return syscall.Kill(pid, 0) == nil
}

func ReleaseStaleLock(workDir string) error {
	path := lockPath(workDir)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("no lock file at %s", path)
	}
	pid, perr := strconv.Atoi(strings.TrimSpace(string(data)))
	if perr == nil && processAlive(pid) {
		return fmt.Errorf("process %d still running", pid)
	}
	return os.Remove(path)
}

func Prepare(workDir string) (*store.Store, *Toolchain, error) {
	if err := os.MkdirAll(filepath.Join(workDir, "evidence"), 0o755); err != nil {
		return nil, nil, err
	}
	st, err := store.Open(filepath.Join(workDir, "audit.db"))
	if err != nil {
		return nil, nil, err
	}
	tc, err := Locate(findRepoRoot())
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	if err := tc.Build(); err != nil {
		st.Close()
		return nil, nil, err
	}
	return st, tc, nil
}

func findRepoRoot() string {
	if v := os.Getenv("CK_REPO_ROOT"); v != "" {
		return v
	}
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

func Init(ctx context.Context, cfg CampaignConfig) (int64, error) {
	if err := os.MkdirAll(filepath.Join(cfg.WorkDir, "evidence"), 0o755); err != nil {
		return 0, err
	}
	st, _, err := Prepare(cfg.WorkDir)
	if err != nil {
		return 0, err
	}
	defer st.Close()

	run := &store.Run{
		Name: cfg.Name, Status: "running", Mode: "fuzz",
		MaxRuns: cfg.MaxRuns, MaxLen: cfg.MaxLen, Seed: cfg.Seed,
		Jobs: cfg.Jobs, PID: int64(os.Getpid()),
	}
	runID, err := st.CreateRun(run)
	if err != nil {
		return 0, err
	}
	samples, err := audit.Generate(runID)
	if err != nil {
		return 0, err
	}
	for i := range samples {
		if err := st.AddSample(&samples[i]); err != nil {
			return 0, err
		}
	}
	if err := st.TouchRun(runID, "interrupted", nil, "initialized; samples pending"); err != nil {
		return 0, err
	}
	return runID, nil
}
