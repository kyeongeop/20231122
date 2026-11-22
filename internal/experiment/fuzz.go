package experiment

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cacheleak.local/experiment/internal/model"
)

func RunLibFuzzer(ctx context.Context, opts Options, runID, tempBase string, evidence *EvidenceManager) (*model.FuzzResult, error) {
	result := &model.FuzzResult{
		ID:        "fuzz-" + runID,
		Tool:      "libFuzzer",
		Status:    "skipped",
		Runs:      opts.FuzzRuns,
		StartedAt: time.Now().UTC(),
	}
	if opts.FuzzMode == "skip" {
		result.SkipReason = "disabled by --fuzz=skip"
		result.FinishedAt = time.Now().UTC()
		return result, nil
	}
	compiler := opts.ClangXX
	if compiler == "" {
		compiler = "clang++"
	}
	resolved, err := exec.LookPath(compiler)
	if err != nil {
		result.SkipReason = fmt.Sprintf("%s not found in PATH", compiler)
		result.FinishedAt = time.Now().UTC()
		if opts.FuzzMode == "run" {
			result.Status = "failed"
			result.SkipReason += " (required by --fuzz=run)"
		}
		return result, nil
	}
	source, err := findFuzzSource()
	if err != nil {
		result.Status = "failed"
		result.SkipReason = err.Error()
		result.FinishedAt = time.Now().UTC()
		return result, nil
	}
	fuzzRoot := filepath.Join(tempBase, "fuzz")
	corpusDir := filepath.Join(fuzzRoot, "corpus")
	artifactDir := filepath.Join(fuzzRoot, "artifacts")
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return nil, err
	}
	seed := []byte{'B', 'q', '7', 'x', 0x00}
	if err := os.WriteFile(filepath.Join(corpusDir, "seed-q7x.bin"), seed, 0o644); err != nil {
		return nil, err
	}
	binary := filepath.Join(fuzzRoot, "cache_key_fuzzer")
	buildArgs := []string{
		"-std=c++17", "-O1", "-g", "-fsanitize=fuzzer,address",
		"-fno-omit-frame-pointer", source, "-o", binary,
	}
	versionCmd := exec.CommandContext(ctx, resolved, "--version")
	version, _ := versionCmd.CombinedOutput()
	result.Version = strings.TrimSpace(strings.SplitN(string(version), "\n", 2)[0])
	build := exec.CommandContext(ctx, resolved, buildArgs...)
	if output, err := build.CombinedOutput(); err != nil {
		result.Status = "failed"
		result.ExitCode = exitCode(err)
		result.SkipReason = fmt.Sprintf("compile libFuzzer target: %v: %s", err, strings.TrimSpace(string(output)))
		result.FinishedAt = time.Now().UTC()
		return result, nil
	}
	runArgs := []string{
		fmt.Sprintf("-runs=%d", opts.FuzzRuns),
		"-timeout=10",
		"-rss_limit_mb=512",
		"-detect_leaks=0",
		"-artifact_prefix=" + artifactDir + string(os.PathSeparator),
		corpusDir,
	}
	result.Command = strings.Join(append([]string{binary}, runArgs...), " ")
	run := exec.CommandContext(ctx, binary, runArgs...)
	run.Dir = fuzzRoot
	var output bytes.Buffer
	run.Stdout = &output
	run.Stderr = &output
	runErr := run.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	result.ExitCode = exitCode(runErr)
	result.FinishedAt = time.Now().UTC()
	logFile := filepath.Join(fuzzRoot, "libfuzzer.log")
	if err := os.WriteFile(logFile, output.Bytes(), 0o644); err != nil {
		return nil, err
	}
	logEv, err := evidence.CopyFile(ctx, "fuzz-log", "fuzz-log",
		"libFuzzer stdout/stderr captured from the assertion run", logFile)
	if err != nil {
		return nil, err
	}
	result.LogPath = logEv.Path
	result.LogSHA256 = logEv.SHA256
	result.AssertionText = assertionLine(output.String())

	artifact, err := firstArtifact(artifactDir)
	if err != nil {
		return nil, err
	}
	if artifact == "" {
		result.Status = "no-finding"
		if runErr != nil {
			result.SkipReason = fmt.Sprintf("libFuzzer exited %d without an artifact", result.ExitCode)
		}
		return result, nil
	}
	artifactEv, err := evidence.CopyFile(ctx, "fuzz-crash-artifact", "fuzz-artifact",
		"libFuzzer crash artifact for the version-blind cache assertion", artifact)
	if err != nil {
		return nil, err
	}
	result.Status = "completed"
	result.Found = true
	result.ArtifactPath = artifactEv.Path
	result.ArtifactSHA = artifactEv.SHA256
	if result.AssertionText == "" {
		result.AssertionText = "CACHELEAK_ASSERT: second snapshot was served from first snapshot cache entry"
	}
	return result, nil
}

func findFuzzSource() (string, error) {
	candidates := []string{
		filepath.Join("fuzz", "cache_key_fuzzer.cpp"),
	}
	if executable, err := os.Executable(); err == nil {
		dir := filepath.Dir(executable)
		candidates = append(candidates,
			filepath.Join(dir, "fuzz", "cache_key_fuzzer.cpp"),
			filepath.Join(dir, "..", "fuzz", "cache_key_fuzzer.cpp"),
		)
	}
	if root := os.Getenv("CACHELEAK_ROOT"); root != "" {
		candidates = append([]string{filepath.Join(root, "fuzz", "cache_key_fuzzer.cpp")}, candidates...)
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			absolute, absErr := filepath.Abs(candidate)
			if absErr != nil {
				return candidate, nil
			}
			return absolute, nil
		}
	}
	return "", errors.New("fuzz/cache_key_fuzzer.cpp not found; run from the repository root or set CACHELEAK_ROOT")
}

func firstArtifact(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.HasPrefix(name, "crash-") || strings.HasPrefix(name, "leak-") ||
			strings.HasPrefix(name, "timeout-") || strings.HasPrefix(name, "oom-") {
			return filepath.Join(dir, name), nil
		}
	}
	return "", nil
}

func assertionLine(log string) string {
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "CACHELEAK_ASSERT") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
