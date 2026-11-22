package replay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"seedreview/internal/evidence"
	"seedreview/internal/manifest"
	"seedreview/internal/model"
	"seedreview/internal/store"
)

type Options struct {
	Store            *store.Store
	Evidence         *evidence.Store
	Manifest         manifest.Parsed
	TargetOverride   string
	ArtifactOverride string
	Timeout          time.Duration
}

type Engine struct {
	options Options
}

type execution struct {
	stdout      []byte
	stderr      []byte
	trace       []byte
	exitCode    int
	signal      string
	targetSHA   string
	targetData  []byte
	inputData   []byte
	inputSHA    string
	status      string
	failureCode string
	failureMsg  string
}

func New(options Options) *Engine {
	if options.Timeout <= 0 {
		options.Timeout = 15 * time.Second
	}
	return &Engine{options: options}
}

func (e *Engine) Run(ctx context.Context) (model.RunResult, error) {
	recovery := e.options.Manifest.Recovery
	if e.options.TargetOverride != "" {
		recovery.Target = e.options.TargetOverride
	}
	if e.options.ArtifactOverride != "" {
		recovery.Artifact = e.options.ArtifactOverride
	}
	started := time.Now().UTC()

	manifestEvidence, err := e.options.Evidence.Put(
		"recovery-manifest", "application/json", e.options.Manifest.Raw,
	)
	if err != nil {
		return model.RunResult{}, err
	}
	allEvidence := []model.Evidence{manifestEvidence}

	execution, err := e.execute(ctx, recovery)
	if err != nil {
		return model.RunResult{}, err
	}
	completed := time.Now().UTC()

	inputEvidence, err := e.options.Evidence.Put("fuzz-input", "application/octet-stream", execution.inputData)
	if err != nil {
		return model.RunResult{}, err
	}
	stdoutEvidence, err := e.options.Evidence.Put("replay-stdout", "text/plain; charset=utf-8", execution.stdout)
	if err != nil {
		return model.RunResult{}, err
	}
	stderrEvidence, err := e.options.Evidence.Put("replay-stderr", "text/plain; charset=utf-8", execution.stderr)
	if err != nil {
		return model.RunResult{}, err
	}
	traceEvidence, err := e.options.Evidence.Put("replay-trace", "application/x-ndjson", execution.trace)
	if err != nil {
		return model.RunResult{}, err
	}
	targetEvidence, err := e.options.Evidence.Put("fuzz-target", "application/octet-stream", execution.targetData)
	if err != nil {
		return model.RunResult{}, err
	}
	allEvidence = append(allEvidence, inputEvidence, stdoutEvidence, stderrEvidence, traceEvidence, targetEvidence)

	trace, traceErr := ParseTrace(execution.trace)
	if traceErr != nil && execution.failureCode == "" {
		execution.failureCode = "trace_unreadable"
		execution.failureMsg = traceErr.Error()
		execution.status = "failed"
	}
	if traceErr == nil && len(trace.Starts) == 0 && execution.failureCode == "" {
		execution.failureCode = "trace_missing"
		execution.failureMsg = "target completed without a start event in SEED_AUDIT_TRACE"
		execution.status = "failed"
	}
	findings, manualChecks, conclusion := buildAssessment(recovery, execution, trace, traceErr)
	nextActions := failureActions(recovery, execution)
	logs := ExtractLogs(execution.stderr, stderrEvidence.SHA256)
	write := store.RunWrite{
		Session: recovery, ManifestEvidence: manifestEvidence,
		InputEvidence: inputEvidence, StdoutEvidence: stdoutEvidence,
		StderrEvidence: stderrEvidence, TraceEvidence: traceEvidence,
		AllEvidence: allEvidence, StartedAt: started, CompletedAt: completed,
		Status: execution.status, ExitCode: execution.exitCode,
		Signal: execution.signal, TargetSHA256: execution.targetSHA,
		TargetEvidence: targetEvidence, TargetPath: recovery.Target,
		ArtifactPath: recovery.Artifact, InputSHA256: execution.inputSHA,
		InputSize:     int64(len(execution.inputData)),
		EffectiveSeed: traceEffectiveSeed(trace, recovery.RecoveredSeed),
		FailureCode:   execution.failureCode, FailureMessage: execution.failureMsg,
		NextActions: nextActions, AutoConclusion: conclusion,
		Extensions: traceExtensions(trace), Logs: logs,
		Findings: findings, ManualChecks: manualChecks,
	}
	runID, sessionID, err := e.options.Store.SaveRun(ctx, write)
	if err != nil {
		return model.RunResult{}, err
	}
	return model.RunResult{
		RunID: runID, SessionID: sessionID, Status: execution.status, ExitCode: execution.exitCode,
		Signal: execution.signal, StartedAt: started, CompletedAt: completed,
		InputSHA256: execution.inputSHA, InputSize: int64(len(execution.inputData)),
		TargetSHA256:  execution.targetSHA,
		EffectiveSeed: write.EffectiveSeed, FailureCode: execution.failureCode,
		FailureMessage: execution.failureMsg, NextActions: nextActions,
		Findings: findings, ManualChecks: manualChecks,
	}, nil
}

func (e *Engine) execute(ctx context.Context, recovery model.Recovery) (execution, error) {
	inputData, inputErr := os.ReadFile(recovery.Artifact)
	inputSHA := ""
	if inputErr == nil {
		sum := sha256.Sum256(inputData)
		inputSHA = hex.EncodeToString(sum[:])
	}
	result := execution{inputData: inputData, inputSHA: inputSHA}
	targetInfo, targetErr := os.Stat(recovery.Target)
	targetSHA := ""
	if targetErr == nil {
		targetData, readErr := os.ReadFile(recovery.Target)
		if readErr == nil {
			sum := sha256.Sum256(targetData)
			targetSHA = hex.EncodeToString(sum[:])
			result.targetData = targetData
		}
	}
	result.targetSHA = targetSHA
	if inputErr != nil {
		result.status = "failed"
		result.failureCode = "artifact_missing"
		result.failureMsg = fmt.Sprintf("cannot read fuzz artifact %s: %v", recovery.Artifact, inputErr)
		return result, nil
	}
	if targetErr != nil {
		result.status = "failed"
		result.failureCode = "target_missing"
		result.failureMsg = fmt.Sprintf("cannot stat fuzz target %s: %v", recovery.Target, targetErr)
		return result, nil
	}
	if targetInfo.Mode()&0o111 == 0 {
		result.status = "failed"
		result.failureCode = "target_not_executable"
		result.failureMsg = fmt.Sprintf("fuzz target is not executable: %s", recovery.Target)
		return result, nil
	}
	command, cleanup, err := e.command(ctx, recovery)
	if err != nil {
		return execution{}, err
	}
	defer cleanup()
	stdout := newCappedBuffer(4 << 20)
	stderr := newCappedBuffer(4 << 20)
	command.Stdout = stdout
	command.Stderr = stderr
	runErr := command.Run()
	result.stdout = stdout.Bytes()
	result.stderr = stderr.Bytes()
	if tracePath := command.Env; len(tracePath) > 0 {
		for _, item := range tracePath {
			if strings.HasPrefix(item, "SEED_AUDIT_TRACE=") {
				path := strings.TrimPrefix(item, "SEED_AUDIT_TRACE=")
				if data, readErr := os.ReadFile(path); readErr == nil {
					result.trace = data
				}
			}
		}
	}
	result.status = "ok"
	if runErr != nil {
		classifyRunError(ctx, &result, runErr)
	}
	return result, nil
}

func (e *Engine) command(ctx context.Context, recovery model.Recovery) (*exec.Cmd, func(), error) {
	tempDir, err := os.MkdirTemp("", "seedreview-replay-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create replay temp dir: %w", err)
	}
	cleanup := func() { os.RemoveAll(tempDir) }
	tracePath := filepath.Join(tempDir, "trace.ndjson")
	seconds := int(e.options.Timeout.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	cmd := exec.CommandContext(ctx, recovery.Target,
		"-runs=1", "-timeout="+strconv.Itoa(seconds), recovery.Artifact,
	)
	env := append([]string{}, os.Environ()...)
	for key, value := range recovery.Environment {
		env = append(env, key+"="+value)
	}
	env = append(env,
		"SEED_AUDIT_TRACE="+tracePath,
		"SEED_AUDIT_SINGLE_REPLAY=1",
		"SEED_AUDIT_RECOVERY_SEED="+firstNonEmpty(recovery.RecoveredSeed, recovery.Seed, "0"),
	)
	cmd.Env = env
	return cmd, cleanup, nil
}

func classifyRunError(ctx context.Context, result *execution, err error) {
	result.status = "failed"
	result.failureCode = "target_failed"
	result.failureMsg = err.Error()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.exitCode = exitErr.ExitCode()
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			result.signal = status.Signal().String()
		}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.status = "timeout"
		result.failureCode = "replay_timeout"
		return
	}
	if result.signal != "" || result.exitCode == 77 {
		result.status = "crash"
		result.failureCode = "replay_crash"
		if result.signal == "" {
			result.signal = "libfuzzer-error"
		}
	}
}

type cappedBuffer struct {
	limit     int
	truncated bool
	marked    bool
	data      bytes.Buffer
}

func newCappedBuffer(limit int) *cappedBuffer {
	return &cappedBuffer{limit: limit}
}

func (buffer *cappedBuffer) Write(data []byte) (int, error) {
	original := len(data)
	remaining := buffer.limit - buffer.data.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
			buffer.truncated = true
		}
		_, _ = buffer.data.Write(data)
	} else {
		buffer.truncated = true
	}
	return original, nil
}

func (buffer *cappedBuffer) Bytes() []byte {
	if buffer.truncated && !buffer.marked {
		buffer.marked = true
		buffer.data.WriteString("\n[seedreview: output truncated]\n")
	}
	return buffer.data.Bytes()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
