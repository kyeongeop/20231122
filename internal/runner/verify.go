// Acceptance: recompute a reference run from the preserved original
// material and compare it against the recorded evidence. Every check
// is anchored to concrete UTC timestamps and raw material offsets.
package runner

import (
	"crypto/sha256"
	"encoding"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"tve/internal/material"
	"tve/internal/store"
)

// Report is the acceptance outcome.
type Report struct {
	Lines []string
	OK    bool
}

func (r *Report) pass(format string, args ...any) {
	r.Lines = append(r.Lines, "PASS "+fmt.Sprintf(format, args...))
}

func (r *Report) fail(format string, args ...any) {
	r.Lines = append(r.Lines, "FAIL "+fmt.Sprintf(format, args...))
	r.OK = false
}

// Reference simulates an uninterrupted run and returns the final hash
// plus the expected batch rows. It replicates the runner semantics:
// the record that first exceeds the output budget is still rendered in
// normal mode; degraded mode applies from the next record onward.
func Reference(p Params, mat []byte) (string, []store.Batch, error) {
	run := sha256.New()
	batch := sha256.New()
	var batches []store.Batch
	var batchBytes, outBytes int64
	var batchStart int64
	degraded := false
	degradedAtBatchStart := false
	for i := 0; i < p.Repeat; i++ {
		out, _, err := RecordOutput(p, mat, i, degraded)
		if err != nil {
			out = []byte("DEGRADED\n")
		}
		run.Write(out)
		batch.Write(out)
		batchBytes += int64(len(out))
		outBytes += int64(len(out))
		if (int64(i)+1)%int64(p.BatchSize) == 0 {
			batches = append(batches, store.Batch{
				StartIndex: batchStart, EndIndex: int64(i),
				OutSHA256: fmt.Sprintf("%x", batch.Sum(nil)), OutBytes: batchBytes,
				RawOffset: RawOffset(len(mat), effVlen(p, degradedAtBatchStart), int(batchStart)),
			})
			batch.Reset()
			batchBytes = 0
			batchStart = int64(i) + 1
			degradedAtBatchStart = degraded
		}
		if p.OutputBudget > 0 && outBytes > p.OutputBudget {
			if degraded {
				return "", nil, fmt.Errorf("budget exceeded in degraded mode at record %d", i)
			}
			degraded = true
			outBytes = 0 // new session budget after resume
		}
	}
	if batchBytes > 0 {
		batches = append(batches, store.Batch{
			StartIndex: batchStart, EndIndex: int64(p.Repeat) - 1,
			OutSHA256: fmt.Sprintf("%x", batch.Sum(nil)), OutBytes: batchBytes,
			RawOffset: RawOffset(len(mat), effVlen(p, degradedAtBatchStart), int(batchStart)),
		})
	}
	return fmt.Sprintf("%x", run.Sum(nil)), batches, nil
}

// Verify runs all acceptance checks for a job and returns the report.
func Verify(st *store.Store, jobID int64, matDir string) (Report, error) {
	rep := Report{OK: true}
	job, err := st.GetJob(jobID)
	if err != nil {
		return rep, err
	}
	var p Params
	if err := json.Unmarshal([]byte(job.ParamsJSON), &p); err != nil {
		return rep, err
	}
	sha, mat, err := st.LoadMaterial(jobID)
	if err != nil {
		return rep, err
	}

	// 1. Original material is unmodified (DB copy and on-disk copy).
	if got := material.SHA256(mat); got != sha || got != job.MaterialSHA {
		rep.fail("material hash changed: db=%s stored=%s job=%s", got, sha, job.MaterialSHA)
	} else {
		rep.pass("original material unmodified sha256=%s bytes=%d", sha, len(mat))
	}
	if matDir != "" {
		if err := material.VerifyPreserved(matDir, sha); err != nil {
			rep.fail("preserved copy: %v", err)
		} else {
			rep.pass("preserved copy %s/material.bin matches sha256=%s", matDir, sha)
		}
	}

	// 2. Before/after comparison: paused+resumed result == reference.
	wantFinal, wantBatches, err := Reference(p, mat)
	if err != nil {
		return rep, err
	}
	cps, err := st.Checkpoints(jobID)
	if err != nil {
		return rep, err
	}
	if len(cps) == 0 {
		rep.fail("no checkpoints recorded")
		return rep, nil
	}
	last := cps[len(cps)-1]
	h := sha256.New()
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(last.HashState); err != nil {
		rep.fail("checkpoint %d hash state undecodable", last.Seq)
	} else if got := fmt.Sprintf("%x", h.Sum(nil)); got != wantFinal {
		rep.fail("final hash mismatch: resumed=%s reference=%s", got, wantFinal)
	} else {
		rep.pass("final hash after resume == reference: %s (checkpoint seq=%d saved_utc=%s)",
			got, last.Seq, last.SavedUTC)
	}

	// 3. Batch evidence matches reference and covers [0, Repeat).
	gotBatches, err := st.Batches(jobID)
	if err != nil {
		return rep, err
	}
	if len(gotBatches) != len(wantBatches) {
		rep.fail("batch count: got %d want %d", len(gotBatches), len(wantBatches))
	} else {
		ok := true
		for i := range wantBatches {
			g, w := gotBatches[i], wantBatches[i]
			if g.StartIndex != w.StartIndex || g.EndIndex != w.EndIndex ||
				g.OutSHA256 != w.OutSHA256 || g.OutBytes != w.OutBytes || g.RawOffset != w.RawOffset {
				rep.fail("batch %d mismatch: got %+v want %+v", i, g, w)
				ok = false
			}
		}
		if ok {
			rep.pass("%d batches identical to reference, covering records [0,%d)",
				len(gotBatches), p.Repeat)
		}
	}

	// 4. Timestamps: parseable UTC, ordered, resume strictly after pause.
	jobStart, err := time.Parse(time.RFC3339Nano, job.CreatedUTC)
	if err != nil {
		rep.fail("job created_utc unparseable: %q", job.CreatedUTC)
	}
	var pauseTS, resumeTS *time.Time
	evs, err := st.Events(jobID)
	if err != nil {
		return rep, err
	}
	prev := jobStart
	for _, e := range evs {
		ts, err := time.Parse(time.RFC3339Nano, e.TsUTC)
		if err != nil {
			rep.fail("event %d bad timestamp %q", e.ID, e.TsUTC)
			continue
		}
		if ts.Before(prev) {
			rep.fail("event %d ts=%s out of order", e.ID, e.TsUTC)
		}
		prev = ts
		switch e.Kind {
		case store.KindPaused:
			t := ts
			pauseTS = &t
		case store.KindResumed:
			t := ts
			resumeTS = &t
		}
		// 5. Raw offsets must address the original material.
		if e.RawOffset < 0 || e.RawOffset >= int64(len(mat)) {
			rep.fail("event %d raw_offset %d outside material [0,%d)", e.ID, e.RawOffset, len(mat))
		}
	}
	if pauseTS != nil && resumeTS != nil {
		if resumeTS.Before(*pauseTS) {
			rep.fail("resume %s before pause %s", resumeTS, pauseTS)
		} else {
			rep.pass("pause at %s -> resume at %s (delta=%s)",
				pauseTS.Format(time.RFC3339Nano), resumeTS.Format(time.RFC3339Nano),
				resumeTS.Sub(*pauseTS))
		}
	}

	// 6. Key evidence exists: degradation and/or resource events present.
	var kinds []string
	for _, e := range evs {
		kinds = append(kinds, e.Kind)
	}
	joined := strings.Join(kinds, ",")
	if strings.Contains(joined, store.KindDegraded) || strings.Contains(joined, store.KindResource) {
		rep.pass("key evidence events recorded: %d events (%s)", len(evs), summarize(evs))
	} else {
		rep.fail("no degradation or resource-exhaustion evidence recorded")
	}
	return rep, nil
}

func summarize(evs []store.Event) string {
	counts := map[string]int{}
	for _, e := range evs {
		counts[e.Kind]++
	}
	var parts []string
	for k, n := range counts {
		parts = append(parts, fmt.Sprintf("%s=%d", k, n))
	}
	return strings.Join(parts, " ")
}
