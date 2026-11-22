package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"ckaudit/internal/store"
)

type FuzzConfig struct {
	WorkDir string
	RunID   int64
	Runs    int64
	MaxLen  int
	Seed    int64
	Jobs    int
}

type FuzzResult struct {
	ExitCode  int
	LibFuzzer string
	Artifacts []store.Evidence
	CorpusDir string
	CrashDir  string
}

func (t *Toolchain) Fuzz(ctx context.Context, cfg FuzzConfig) (*FuzzResult, error) {
	if err := acquireLock(cfg.WorkDir); err != nil {
		return nil, err
	}
	defer releaseLock(cfg.WorkDir)

	base := filepath.Join(cfg.WorkDir, "libfuzzer")
	corpusDir := filepath.Join(base, "corpus")
	crashDir := filepath.Join(base, "crash")
	seedDir := filepath.Join(base, "seeds")
	for _, d := range []string{corpusDir, crashDir, seedDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}

	st, err := store.Open(filepath.Join(cfg.WorkDir, "audit.db"))
	if err != nil {
		return nil, err
	}
	samples, err := st.AllSamples(cfg.RunID)
	st.Close()
	if err != nil {
		return nil, err
	}
	for i, smp := range samples {
		seedPath := filepath.Join(seedDir, fmt.Sprintf("seed-%04d", i))
		if err := os.WriteFile(seedPath, []byte(smp.Input), 0o644); err != nil {
			return nil, err
		}
	}

	args := []string{
		corpusDir, seedDir,
		fmt.Sprintf("-runs=%d", cfg.Runs),
		fmt.Sprintf("-max_len=%d", cfg.MaxLen),
		fmt.Sprintf("-seed=%d", cfg.Seed),
		fmt.Sprintf("-jobs=%d", cfg.Jobs),
		fmt.Sprintf("-artifact_prefix=%s/", crashDir),
		"-print_final_stats=1",
		"-detect_leaks=1",
	}
	cmd := exec.CommandContext(ctx, t.FuzzBin, args...)
	cmd.Dir = base
	cmd.Env = append(os.Environ(),
		"ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=1")
	var combined strings.Builder
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	runErr := cmd.Run()

	exitCode := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return nil, runErr
		}
	}
	logText := combined.String()
	logEv, err := writeEvidenceFile(base, "libfuzzer.log", []byte(logText))
	if err != nil {
		return nil, err
	}
	logEv.Kind = "libfuzzer-log"

	res := &FuzzResult{
		ExitCode: exitCode, LibFuzzer: logText,
		CorpusDir: corpusDir, CrashDir: crashDir,
		Artifacts: []store.Evidence{logEv},
	}

	entries, _ := os.ReadDir(crashDir)
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(crashDir, ent.Name()))
		if rerr != nil {
			continue
		}
		ev, werr := writeEvidenceFile(crashDir, ent.Name()+".meta", data)
		if werr == nil {
			ev.Kind = "libfuzzer-crash"
			res.Artifacts = append(res.Artifacts, ev)
		}
	}
	return res, nil
}
