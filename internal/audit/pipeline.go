package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const (
	VerdictValid            = "valid"
	VerdictExpired          = "expired"
	VerdictUnknownExtension = "unknown-extension"
	VerdictUndecidable      = "undecidable"
	VerdictError            = "error"
)

// Object is one audit subject: a raw password-reset token record.
type Object struct {
	Label string
	Kind  string // e.g. "snapshot-v1", "snapshot-v2", "unknown-extension", "boundary", "corrupt"
	Raw   string
}

// Pipeline runs the audit and records full provenance into the Store.
type Pipeline struct {
	Store        *Store
	Now          time.Time // audit clock; injectable for reproducibility
	ToolVersion  string
	RulesVersion string
}

func (p *Pipeline) now() string {
	return p.Now.UTC().Format(time.RFC3339Nano)
}

// Run processes every object; a failure on one object is recorded as an
// "error" conclusion and never stops the remaining objects.
func (p *Pipeline) Run(objects []Object) (runID int64, err error) {
	runID, err = p.Store.BeginRun(p.now(), p.ToolVersion, p.RulesVersion)
	if err != nil {
		return 0, err
	}
	if err := p.createTempState(); err != nil {
		return runID, fmt.Errorf("temp state: %w", err)
	}
	for _, obj := range objects {
		p.processOne(runID, obj) // per-object recovery inside
	}
	cleanupOK := p.cleanupTempState()
	if err := p.Store.FinishRun(runID, p.now(), cleanupOK); err != nil {
		return runID, err
	}
	if !cleanupOK {
		return runID, errors.New("temporary state cleanup failed")
	}
	return runID, nil
}

// processOne isolates each object: panics and errors become "error"
// conclusions so later objects still get processed.
func (p *Pipeline) processOne(runID int64, obj Object) {
	sum := sha256.Sum256([]byte(obj.Raw))
	sha := hex.EncodeToString(sum[:])
	objectID, err := p.Store.InsertObject(runID, obj.Label, obj.Kind, obj.Raw, sha)
	if err != nil {
		return // store is broken; nothing reliable to record into
	}
	defer func() {
		if r := recover(); r != nil {
			rec := ConclusionRecord{
				Verdict: VerdictError,
				Reason:  fmt.Sprintf("panic during processing: %v", r),
				Steps:   []Step{{Name: "panic", Detail: fmt.Sprintf("recovered: %v", r)}},
				Evidence: []Evidence{
					{Key: "raw_sha256", Value: sha},
					{Key: "panic_value", Value: fmt.Sprintf("%v", r)},
				},
			}
			p.Store.InsertConclusion(objectID, rec, p.now())
		}
	}()
	rec := p.evaluate(obj, sha)
	if _, err := p.Store.InsertConclusion(objectID, rec, p.now()); err != nil {
		return
	}
}
