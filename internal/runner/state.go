package runner

import (
	"crypto/sha256"
	"encoding"
	"fmt"
	"hash"
	"time"

	"tve/internal/store"
)

// Runner processes records and checkpoints its state.
type Runner struct {
	Store    *store.Store
	JobID    int64
	Params   Params
	Material []byte
	Now      func() time.Time // injectable clock, defaults to time.Now

	next        int64
	processed   int64
	degradedN   int64
	outBytes    int64
	degraded    bool
	runHash     hash.Hash
	batchHash   hash.Hash
	batchStart  int64
	batchRawOff int64
	batchBytes  int64
	ckptSeq     int64
	resumeNote  string // pending "resumed" evidence, emitted by Run
}

// rawOff returns the raw material offset for record i under the
// runner's current mode.
func (r *Runner) rawOff(i int) int64 {
	return RawOffset(len(r.Material), effVlen(r.Params, r.degraded), i)
}

func (r *Runner) utc() string {
	n := time.Now
	if r.Now != nil {
		n = r.Now
	}
	return n().UTC().Format(time.RFC3339Nano)
}

// NewRunner creates a runner starting at record 0.
func NewRunner(st *store.Store, jobID int64, p Params, material []byte) *Runner {
	return &Runner{
		Store: st, JobID: jobID, Params: p, Material: material,
		runHash: sha256.New(), batchHash: sha256.New(),
	}
}

// ResumeRunner rebuilds a runner from the latest checkpoint. If the job
// previously stopped on resource exhaustion, it resumes in degraded mode.
func ResumeRunner(st *store.Store, jobID int64, p Params, material []byte) (*Runner, error) {
	cp, err := st.LatestCheckpoint(jobID)
	if err != nil {
		return nil, err
	}
	r := NewRunner(st, jobID, p, material)
	if cp == nil {
		return r, nil
	}
	h := sha256.New()
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(cp.HashState); err != nil {
		return nil, fmt.Errorf("restore hash state: %w", err)
	}
	r.runHash = h
	r.next = cp.NextIndex
	r.processed = cp.Processed
	r.degradedN = cp.Degraded
	r.ckptSeq = cp.Seq
	r.batchStart = cp.BatchStart
	r.batchRawOff = cp.BatchRawOff
	if len(cp.BatchState) > 0 {
		bh := sha256.New()
		if err := bh.(encoding.BinaryUnmarshaler).UnmarshalBinary(cp.BatchState); err != nil {
			return nil, fmt.Errorf("restore batch hash state: %w", err)
		}
		r.batchHash = bh
		r.batchBytes = cp.BatchBytes
	}
	job, err := st.GetJob(jobID)
	if err != nil {
		return nil, err
	}
	if job.Status == "exhausted" {
		r.degraded = true
		// A resume after resource exhaustion starts a fresh
		// (degraded) session budget; a pause resume continues
		// the same logical session and keeps the accumulated count.
		r.outBytes = 0
	} else {
		r.outBytes = cp.OutBytes
	}
	r.resumeNote = fmt.Sprintf("from-checkpoint-seq=%d degraded=%v", cp.Seq, r.degraded)
	return r, nil
}

// FinalHash returns the hex digest of all record outputs so far.
func (r *Runner) FinalHash() string {
	return fmt.Sprintf("%x", r.runHash.Sum(nil))
}

// Degraded reports whether the runner is in degraded mode.
func (r *Runner) Degraded() bool { return r.degraded }
