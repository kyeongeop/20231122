package review

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"example.com/migration-review/internal/evidence"
	"example.com/migration-review/internal/model"
	"example.com/migration-review/internal/policy"
)

type Options struct {
	ActorOverride    string
	TargetPath       string
	InputPath        string
	RunID            string
	CancelAfter      int
	AllowDestructive bool
	AllowAttach      bool
	AllowAdmin       bool
	ApprovalID       string
	ExtraArtifacts   []evidence.Artifact
	AfterStatement   func(context.Context, int)
	EvidenceTimeout  time.Duration
}

type RunError struct {
	RunID  string
	Status model.RunStatus
	Reason string
}

func (e *RunError) Error() string {
	return fmt.Sprintf("run %s finished with %s: %s", e.RunID, e.Status, e.Reason)
}

func Run(ctx context.Context, store *evidence.Store, engine *policy.Engine, manifest *model.Manifest, opts Options) (model.RunRecord, error) {
	if store == nil || engine == nil || manifest == nil {
		return model.RunRecord{}, errors.New("store, policy and manifest are required")
	}
	if strings.TrimSpace(manifest.Actor) == "" && strings.TrimSpace(opts.ActorOverride) != "" {
		manifest.Actor = strings.TrimSpace(opts.ActorOverride)
	}
	if opts.RunID == "" {
		opts.RunID = newRunID()
	}
	if opts.InputPath == "" {
		opts.InputPath = manifest.SourceName
	}
	evCtx, cancelEvidence := evidenceContext(opts.EvidenceTimeout)
	defer cancelEvidence()

	decision := engine.Authorize(manifest, policy.Options{
		AllowDestructive: opts.AllowDestructive,
		AllowAttach:      opts.AllowAttach,
		AllowAdmin:       opts.AllowAdmin,
		ApprovalID:       opts.ApprovalID,
	})
	record := model.RunRecord{
		RunID:       opts.RunID,
		CreatedAt:   time.Now().UTC(),
		Status:      model.StatusDenied,
		Format:      manifest.Format,
		ManifestID:  manifest.ID,
		Actor:       manifest.Actor,
		InputPath:   opts.InputPath,
		InputSHA256: manifest.SourceSHA256,
		InputBytes:  append([]byte(nil), manifest.Raw...),
		Decision:    decision,
	}
	if trigger, ok := denialTrigger(decision); ok {
		record.Trigger = trigger
	} else if len(decision.Statements) > 0 {
		record.Trigger = decision.Statements[0].Trigger
	}
	record.Reason = decision.DenyReason
	if decision.Allowed {
		record.Status = model.StatusRunning
		record.Reason = "permission engine allowed all statements; execution pending"
	}

	decisionJSON, err := json.MarshalIndent(decision, "", "  ")
	if err != nil {
		return record, fmt.Errorf("encode permission decision: %w", err)
	}
	artifacts := []evidence.Artifact{
		{Kind: "input", Name: "raw", Content: manifest.Raw},
		{Kind: "manifest", Name: "normalized.json", Content: manifest.Normalized},
		{Kind: "policy", Name: "snapshot.json", Content: engine.Canonical()},
		{Kind: "permission", Name: "decision.json", Content: decisionJSON},
	}
	artifacts = append(artifacts, opts.ExtraArtifacts...)
	if err := store.BeginRun(evCtx, record, artifacts...); err != nil {
		return record, fmt.Errorf("record preflight evidence: %w", err)
	}
	logRecord, err := store.Log(evCtx, record.RunID, "INFO", "preflight", mustJSON(map[string]any{
		"actor":         manifest.Actor,
		"format":        manifest.Format,
		"input_sha256":  manifest.SourceSHA256,
		"policy_sha256": engine.Hash(),
		"statements":    len(manifest.Statements),
	}))
	if err != nil {
		return record, fmt.Errorf("write preflight log: %w", err)
	}
	for _, sd := range decision.Statements {
		entry, err := store.Log(evCtx, record.RunID, "INFO", "permission_statement", mustJSON(map[string]any{
			"index":      sd.Index,
			"keyword":    sd.Keyword,
			"capability": sd.Capability,
			"allowed":    sd.Allowed,
			"reason":     sd.Reason,
			"trigger":    sd.Trigger,
		}))
		if err != nil {
			return record, fmt.Errorf("write permission log: %w", err)
		}
		logRecord = entry
	}
	level := "INFO"
	if !decision.Allowed {
		level = "DENY"
	}
	finalDecisionLog, err := store.Log(evCtx, record.RunID, level, "permission_decision", mustJSON(decision))
	if err != nil {
		return record, fmt.Errorf("write decision log: %w", err)
	}
	logRecord = finalDecisionLog

	if !decision.Allowed {
		record.LogHeadHash = logRecord.Hash
		record.Reason = decision.DenyReason
		now := time.Now().UTC()
		record.CompletedAt = &now
		if err := store.CompleteRun(evCtx, record); err != nil {
			return record, fmt.Errorf("complete denied run: %w", err)
		}
		stored, getErr := store.GetRun(evCtx, record.RunID)
		if getErr != nil {
			return record, getErr
		}
		return stored, &RunError{RunID: record.RunID, Status: model.StatusDenied, Reason: record.Reason}
	}
	if opts.TargetPath == "" {
		return record, errors.New("target database path is required for an allowed migration")
	}
	return executeAllowed(ctx, evCtx, store, manifest, record, logRecord.Hash, opts)
}

func denialTrigger(decision model.PermissionDecision) (model.Trigger, bool) {
	for _, statement := range decision.Statements {
		if !statement.Allowed {
			return statement.Trigger, true
		}
	}
	return model.Trigger{}, false
}

func evidenceContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return context.WithTimeout(context.Background(), timeout)
}

func newRunID() string {
	var suffix [4]byte
	_, _ = rand.Read(suffix[:])
	return "run-" + time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(suffix[:])
}

func mustJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%q", fmt.Sprint(value))
	}
	return string(data)
}

func resolvePath(path string) (string, error) {
	if strings.HasPrefix(path, "file:") {
		return path, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return abs, nil
}
