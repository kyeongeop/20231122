package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"bombverify/internal/decomp"
	"bombverify/internal/evidence"
)

// Request describes one verification run.
type Request struct {
	Scenario     string
	AttackVector string
	Input        []byte
	Subject      Subject
	Quota        decomp.Quota
	Notes        string
}

// Run executes the permission gate, then the quota-limited decompression,
// and persists one evidence record linking input, trigger location,
// permission decision and audit-log digest.
func Run(req Request, store *evidence.Store, audit *AuditLog) (*evidence.Record, error) {
	sum := sha256.Sum256(req.Input)
	inputHash := hex.EncodeToString(sum[:])
	var chain []byte
	log := func(event string, kv ...any) {
		d, err := audit.Event(event, kv...)
		if err == nil {
			chain = append(chain, d...)
		}
	}

	log("admit", "scenario", req.Scenario, "input_sha256", inputHash, "input_len", len(req.Input))

	allowed, reason := req.Subject.Decide(ActionDecompress)
	decision := "allow"
	if !allowed {
		decision = "deny"
	}
	log("permission", "subject", req.Subject.ID, "action", ActionDecompress, "decision", decision, "reason", reason)

	rec := &evidence.Record{
		TS:                     time.Now().UTC().Format(time.RFC3339Nano),
		Scenario:               req.Scenario,
		InputSHA256:            inputHash,
		InputLen:               int64(len(req.Input)),
		AttackVector:           req.AttackVector,
		PermSubject:            req.Subject.ID,
		PermAction:             ActionDecompress,
		PermDecision:           decision,
		PermReason:             reason,
		QuotaMaxOutputBytes:    req.Quota.MaxOutputBytes,
		QuotaMaxExpansionRatio: req.Quota.MaxExpansionRatio,
		LogFile:                audit.Path(),
		Notes:                  req.Notes,
	}

	if allowed {
		res, err := decomp.Decompress(req.Input, req.Quota, audit)
		if res != nil {
			rec.ExpandedBytes = res.ExpandedBytes
			rec.ExpansionCount = int64(res.ExpansionCount)
		}
		var derr *decomp.Error
		switch {
		case err == nil:
			log("result", "outcome", "ok", "expanded_bytes", res.ExpandedBytes)
		case errors.As(err, &derr):
			rec.TriggerFunc = derr.Func
			rec.TriggerFile = relPath(derr.File)
			rec.TriggerLine = int64(derr.Line)
			log("result", "outcome", "rejected", "error", derr.Reason,
				"trigger", fmt.Sprintf("%s:%d", rec.TriggerFile, derr.Line))
		default:
			log("result", "outcome", "error", "error", err.Error())
		}
	} else {
		log("result", "outcome", "blocked", "reason", reason)
	}

	digest := sha256.Sum256(chain)
	rec.LogDigest = hex.EncodeToString(digest[:])
	if err := store.Insert(rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// relPath makes p relative to the working directory so evidence records are
// portable across machines.
func relPath(p string) string {
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	if r, err := filepath.Rel(wd, p); err == nil {
		return r
	}
	return p
}
