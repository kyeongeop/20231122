package fuzzrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"apiskew.local/apiskew/internal/domain"
)

type Options struct {
	Binary       string
	WorkDir      string
	Seconds      int
	Scenario     domain.Scenario
	Seed         []byte
	FindingLimit int
}

type Finding struct {
	Path  string
	Input []byte
}

type Result struct {
	Command      []string
	CorpusDir    string
	FindingsDir  string
	CrashDir     string
	LogPath      string
	FuzzerSHA256 string
	Findings     []Finding
	Interrupted  bool
	FuzzerExit   string
	DurationMS   int64
	CorpusFiles  int
}

type VerifyResult struct {
	Detected    bool
	Command     []string
	WorkDir     string
	FindingsDir string
	LogPath     string
}

func Run(ctx context.Context, options Options) (Result, error) {
	if options.Binary == "" {
		return Result{}, errors.New("fuzzer binary is required")
	}
	if options.WorkDir == "" {
		return Result{}, errors.New("fuzzer work directory is required")
	}
	if options.Seconds <= 0 {
		return Result{}, errors.New("fuzz duration must be positive")
	}
	absoluteBinary, err := filepath.Abs(options.Binary)
	if err != nil {
		return Result{}, err
	}
	if _, err := os.Stat(absoluteBinary); err != nil {
		return Result{}, fmt.Errorf("fuzzer binary: %w", err)
	}
	workDir, err := filepath.Abs(options.WorkDir)
	if err != nil {
		return Result{}, err
	}
	corpusDir := filepath.Join(workDir, "corpus")
	findingsDir := filepath.Join(workDir, "findings")
	crashDir := filepath.Join(workDir, "crashes")
	for _, dir := range []string{workDir, corpusDir, findingsDir, crashDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return Result{}, err
		}
	}
	if err := ensureSeed(corpusDir, options.Seed); err != nil {
		return Result{}, err
	}
	corpusFiles, err := countFiles(corpusDir)
	if err != nil {
		return Result{}, err
	}
	fuzzerSHA, err := FileSHA256(absoluteBinary)
	if err != nil {
		return Result{}, err
	}
	logPath := filepath.Join(workDir, "fuzzer.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return Result{}, err
	}
	defer logFile.Close()

	args := []string{
		fmt.Sprintf("-max_total_time=%d", options.Seconds),
		"-timeout=5",
		"-rss_limit_mb=1024",
		"-print_final_stats=1",
		"-artifact_prefix=" + crashDir + string(os.PathSeparator),
		corpusDir,
	}
	cmd := exec.CommandContext(ctx, absoluteBinary, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	findingLimit := options.FindingLimit
	if findingLimit <= 0 {
		findingLimit = 5000
	}
	cmd.Env = append(os.Environ(), fuzzerEnv(findingsDir, options.Scenario, findingLimit)...)
	started := time.Now()
	runErr := cmd.Run()
	duration := time.Since(started)

	findings, err := readFindings(findingsDir, 0)
	if err != nil {
		return Result{}, err
	}
	result := Result{
		Command:      append([]string{absoluteBinary}, args...),
		CorpusDir:    corpusDir,
		FindingsDir:  findingsDir,
		CrashDir:     crashDir,
		LogPath:      logPath,
		FuzzerSHA256: fuzzerSHA,
		Findings:     findings,
		Interrupted:  ctx.Err() != nil,
		DurationMS:   duration.Milliseconds(),
		CorpusFiles:  corpusFiles,
	}
	if runErr != nil {
		result.FuzzerExit = runErr.Error()
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if runErr != nil {
		return result, fmt.Errorf("libFuzzer exited: %w", runErr)
	}
	return result, nil
}

func VerifyOne(ctx context.Context, binary, workDir string, scenario domain.Scenario, input []byte) (VerifyResult, error) {
	absoluteBinary, err := filepath.Abs(binary)
	if err != nil {
		return VerifyResult{}, err
	}
	if _, err := os.Stat(absoluteBinary); err != nil {
		return VerifyResult{}, fmt.Errorf("fuzzer binary: %w", err)
	}
	oracleRoot := filepath.Join(workDir, "oracle")
	if err := os.MkdirAll(oracleRoot, 0o755); err != nil {
		return VerifyResult{}, err
	}
	runDir, err := os.MkdirTemp(oracleRoot, "sample-")
	if err != nil {
		return VerifyResult{}, err
	}
	findingsDir := filepath.Join(runDir, "findings")
	if err := os.MkdirAll(findingsDir, 0o755); err != nil {
		return VerifyResult{}, err
	}
	inputPath := filepath.Join(runDir, "input.bin")
	if err := os.WriteFile(inputPath, input, 0o644); err != nil {
		return VerifyResult{}, err
	}
	logPath := filepath.Join(runDir, "fuzzer.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return VerifyResult{}, err
	}
	defer logFile.Close()
	args := []string{"-runs=1", inputPath}
	cmd := exec.CommandContext(ctx, absoluteBinary, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = append(os.Environ(), fuzzerEnv(findingsDir, scenario, 1)...)
	if err := cmd.Run(); err != nil {
		return VerifyResult{
			Command:     []string{absoluteBinary, "-runs=1", "<sample-input>"},
			WorkDir:     runDir,
			FindingsDir: findingsDir,
			LogPath:     logPath,
		}, err
	}
	findings, err := readFindings(findingsDir, 0)
	if err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{
		Detected:    len(findings) > 0,
		Command:     []string{absoluteBinary, "-runs=1", "<sample-input>"},
		WorkDir:     runDir,
		FindingsDir: findingsDir,
		LogPath:     logPath,
	}, nil
}

func fuzzerEnv(findingsDir string, scenario domain.Scenario, findingLimit int) []string {
	return []string{
		"APISKEW_FINDINGS=" + findingsDir,
		fmt.Sprintf("APISKEW_MAX_FINDINGS=%d", findingLimit),
		fmt.Sprintf("APISKEW_REV_A=%d", scenario.Object.Replicas[0].Revision),
		fmt.Sprintf("APISKEW_REV_B=%d", scenario.Object.Replicas[1].Revision),
		fmt.Sprintf("APISKEW_UPDATED_A=%d", scenario.Object.Replicas[0].UpdatedAtMS),
		fmt.Sprintf("APISKEW_UPDATED_B=%d", scenario.Object.Replicas[1].UpdatedAtMS),
		fmt.Sprintf("APISKEW_ACL_A=%d", scenario.Object.Replicas[0].ACL),
		fmt.Sprintf("APISKEW_ACL_B=%d", scenario.Object.Replicas[1].ACL),
		fmt.Sprintf("APISKEW_DELETED_A=%d", boolNumber(scenario.Object.Replicas[0].Deleted)),
		fmt.Sprintf("APISKEW_DELETED_B=%d", boolNumber(scenario.Object.Replicas[1].Deleted)),
		"APISKEW_OBJECT_KEY=" + scenario.Object.Key,
	}
}

func ensureSeed(corpusDir string, seed []byte) error {
	corpusFiles, err := countFiles(corpusDir)
	if err != nil {
		return err
	}
	if corpusFiles > 0 {
		return nil
	}
	if len(seed) == 0 {
		seed = domain.MustEncodeAttack(domain.Attack{
			ActorRole:     domain.RoleEditor,
			Action:        domain.ActionRead,
			TenantMatch:   true,
			RequestDevice: "device-a",
			SkewAMS:       0,
			SkewBMS:       4500,
		})
	}
	return os.WriteFile(filepath.Join(corpusDir, "seed.bin"), seed, 0o644)
}

func countFiles(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			count++
		}
	}
	return count, nil
}

func readFindings(dir string, max int) ([]Finding, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "finding-") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if max > 0 && len(names) > max {
		names = names[:max]
	}
	findings := make([]Finding, 0, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		input, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		findings = append(findings, Finding{Path: path, Input: input})
	}
	return findings, nil
}

func FileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func boolNumber(value bool) int {
	if value {
		return 1
	}
	return 0
}
