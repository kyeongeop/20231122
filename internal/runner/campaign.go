package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// CampaignConfig drives one bounded libFuzzer coverage-guided run.
type CampaignConfig struct {
	Binary      string // kr_fuzz_vuln or kr_fuzz_fixed
	CorpusDir   string // persistent corpus (created if missing)
	ArtifactDir string // crash artifacts libFuzzer writes
	MaxTotalSec int    // -max_total_time
	MaxLen      int    // -max_len
	Jobs        int    // -jobs (1 keeps output deterministic)
}

// CampaignResult summarizes a fuzzing campaign.
type CampaignResult struct {
	ExitCode      int
	CorpusEntries int
	CrashFiles    []string
	StdoutLog     string
	StderrLog     string
}

// RunCampaign executes a bounded libFuzzer campaign. Any crash input is
// captured under ArtifactDir and can be imported later via 'krfix import
// --file'. Context cancellation terminates the campaign; the on-disk corpus
// and crash files survive for the next session.
func RunCampaign(ctx context.Context, cfg CampaignConfig, logDir, tag string) (*CampaignResult, error) {
	if _, err := os.Stat(cfg.Binary); err != nil {
		return nil, fmt.Errorf("fuzz binary missing (%s); run 'krfix build' first: %w",
			cfg.Binary, err)
	}
	if err := os.MkdirAll(cfg.CorpusDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.ArtifactDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, err
	}

	args := []string{
		cfg.CorpusDir,
		fmt.Sprintf("-artifact_prefix=%s/", cfg.ArtifactDir),
		fmt.Sprintf("-max_total_time=%d", cfg.MaxTotalSec),
		fmt.Sprintf("-max_len=%d", cfg.MaxLen),
		"-print_final_stats=1",
	}
	if cfg.Jobs > 1 {
		args = append(args, fmt.Sprintf("-jobs=%d", cfg.Jobs))
	}
	cmd := exec.CommandContext(ctx, cfg.Binary, args...)
	cmd.Env = append(os.Environ(),
		"ASAN_OPTIONS=abort_on_error=1:exitcode=99")

	stdoutPath := filepath.Join(logDir, tag+".fuzz.stdout.log")
	stderrPath := filepath.Join(logDir, tag+".fuzz.stderr.log")
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

	runErr := cmd.Run()
	res := &CampaignResult{StdoutLog: stdoutPath, StderrLog: stderrPath}
	if runErr == nil {
		res.ExitCode = 0
	} else if ee, ok := runErr.(*exec.ExitError); ok {
		res.ExitCode = ee.ExitCode()
	} else if ctx.Err() != nil {
		return nil, ctx.Err()
	} else {
		return nil, runErr
	}

	entries, err := os.ReadDir(cfg.CorpusDir)
	if err != nil {
		return nil, err
	}
	res.CorpusEntries = len(entries)
	crashes, err := os.ReadDir(cfg.ArtifactDir)
	if err != nil {
		return nil, err
	}
	for _, c := range crashes {
		if !c.IsDir() {
			res.CrashFiles = append(res.CrashFiles,
				filepath.Join(cfg.ArtifactDir, c.Name()))
		}
	}
	return res, nil
}
