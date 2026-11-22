package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"mountaudit/internal/audit"
	"mountaudit/internal/store"
)

type InitOptions struct {
	InputPath   string
	ArtifactDir string
	Limits      audit.Limits
}

type InitResult struct {
	Run     store.Run
	Anchors []audit.Anchor
}

func Init(ctx context.Context, st *store.Store, options InitOptions, clock func() time.Time) (InitResult, error) {
	var result InitResult
	if err := options.Limits.Validate(); err != nil {
		return result, err
	}
	info, err := os.Stat(options.InputPath)
	if err != nil {
		return result, fmt.Errorf("stat source: %w", err)
	}
	if !info.Mode().IsRegular() {
		return result, fmt.Errorf("source must be a regular file")
	}
	if info.Size() > options.Limits.MaxInputBytes {
		return result, fmt.Errorf("source is %d bytes, hard input limit is %d",
			info.Size(), options.Limits.MaxInputBytes)
	}
	original, err := os.ReadFile(options.InputPath)
	if err != nil {
		return result, fmt.Errorf("read source: %w", err)
	}
	sourceSHA := audit.SHA256Hex(original)
	absoluteSource, err := filepath.Abs(options.InputPath)
	if err != nil {
		return result, fmt.Errorf("resolve source path: %w", err)
	}
	now := audit.NowUTC(clock)
	plan := audit.MakePlan(original, clock)
	runID, err := newRunID(now)
	if err != nil {
		return result, err
	}

	artifactDir := options.ArtifactDir
	if artifactDir == "" {
		artifactDir = "mountaudit-artifacts"
	}
	runArtifactDir, err := filepath.Abs(filepath.Join(artifactDir, runID))
	if err != nil {
		return result, fmt.Errorf("resolve artifact directory: %w", err)
	}
	if err := os.MkdirAll(runArtifactDir, 0o755); err != nil {
		return result, fmt.Errorf("create artifact directory: %w", err)
	}
	artifactPath := filepath.Join(runArtifactDir, "original.raw")
	if err := writeReadOnly(artifactPath, original); err != nil {
		return result, err
	}
	artifactBytes, err := os.ReadFile(artifactPath)
	if err != nil {
		return result, fmt.Errorf("re-read artifact: %w", err)
	}
	if audit.SHA256Hex(artifactBytes) != sourceSHA {
		return result, fmt.Errorf("artifact checksum differs from source; source was not modified")
	}
	afterInfo, err := os.Stat(absoluteSource)
	if err != nil {
		return result, fmt.Errorf("re-stat source: %w", err)
	}
	if afterInfo.Size() != info.Size() {
		return result, fmt.Errorf("source size changed during import")
	}
	recheck, err := os.ReadFile(absoluteSource)
	if err != nil {
		return result, fmt.Errorf("re-read source for integrity check: %w", err)
	}
	if audit.SHA256Hex(recheck) != sourceSHA {
		return result, fmt.Errorf("source content changed during import")
	}

	run := store.Run{
		ID:           runID,
		CreatedAt:    audit.FormatTime(now),
		UpdatedAt:    audit.FormatTime(now),
		SourcePath:   absoluteSource,
		SourceName:   filepath.Base(absoluteSource),
		SourceSize:   int64(len(original)),
		SourceSHA256: sourceSHA,
		Original:     original,
		ArtifactPath: artifactPath,
		Format:       audit.CaptureFormat,
		Status:       "paused",
		NextStage:    1,
		Degraded:     plan.AnchorFallback,
		Limits:       options.Limits,
	}
	evidence := []store.Evidence{importEvidence(run, artifactPath)}
	if plan.AnchorFallback {
		detail, _ := json.Marshal(map[string]any{
			"reason":  plan.FallbackReason,
			"anchors": plan.Anchors,
			"policy":  "continue with synthesized line-boundary anchors",
		})
		evidence = append(evidence, store.Evidence{
			Kind:        "anchor_fallback",
			CapturedAt:  audit.FormatTime(now),
			StartOffset: 0,
			EndOffset:   int64(len(original)),
			SHA256:      sourceSHA,
			DetailJSON:  string(detail),
		})
	}
	if err := st.CreateRun(ctx, run, plan.Anchors, evidence); err != nil {
		return result, err
	}
	result.Run = run
	result.Anchors = plan.Anchors
	return result, nil
}

func writeReadOnly(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create original artifact: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write original artifact: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync original artifact: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close original artifact: %w", err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		return fmt.Errorf("make original artifact read-only: %w", err)
	}
	return nil
}

func importEvidence(run store.Run, artifactPath string) store.Evidence {
	detail, _ := json.Marshal(map[string]any{
		"source_path":      run.SourcePath,
		"source_name":      run.SourceName,
		"source_size":      run.SourceSize,
		"artifact_path":    artifactPath,
		"artifact_mode":    "0444",
		"source_unchanged": true,
	})
	return store.Evidence{
		Kind:        "original_import",
		CapturedAt:  run.CreatedAt,
		StartOffset: 0,
		EndOffset:   run.SourceSize,
		SHA256:      run.SourceSHA256,
		DetailJSON:  string(detail),
	}
}

func newRunID(now time.Time) (string, error) {
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate run id: %w", err)
	}
	return "run-" + now.Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(random), nil
}
