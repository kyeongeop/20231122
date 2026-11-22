// Package replay wires ingest, the state machine and the SQLite evidence
// store into one auditable pipeline, and provides deterministic replay.
package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"riskflow/internal/engine"
	"riskflow/internal/ingest"
	"riskflow/internal/model"
	"riskflow/internal/store"
)

// Pipeline is the top-level review service.
type Pipeline struct {
	Store *store.Store
	Eng   *engine.Engine
}

func New(st *store.Store) *Pipeline {
	return &Pipeline{Store: st, Eng: engine.New()}
}

// IngestResult summarizes a (possibly interrupted) ingestion.
type IngestResult struct {
	BatchID   string
	Schema    string
	RawSHA256 string
	Truncated bool
	Detail    string
	RecordCnt int
}

// IngestFile reads a batch file, persists provenance + records and runs the
// state machine. A truncated final record is recorded as evidence rather than
// aborting the whole batch; call Recovery/Replay to re-verify it.
func (p *Pipeline) IngestFile(batchID, path string) (IngestResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return IngestResult{}, err
	}
	return p.Ingest(batchID, path, raw)
}

// Ingest is the byte-oriented entry point (used by tests and the fuzzer bridge).
func (p *Pipeline) Ingest(batchID, sourceURI string, raw []byte) (IngestResult, error) {
	sum := sha256.Sum256(raw)
	out, perr := ingest.Parse(batchID, raw)
	if perr != nil && perr != ingest.ErrTruncated {
		return IngestResult{}, fmt.Errorf("parse: %w", perr)
	}
	schema := out.Schema
	if schema == "" {
		schema = ingest.Detect(raw)
	}

	res := IngestResult{
		BatchID:   batchID,
		Schema:    schema,
		RawSHA256: hex.EncodeToString(sum[:]),
		Truncated: out.Truncated,
		Detail:    out.Detail,
	}
	if err := p.Store.UpsertBatch(batchID, schema, sourceURI, res.RawSHA256,
		int64(len(raw)), out.Truncated); err != nil {
		return res, err
	}

	for _, rec := range out.Records {
		if err := p.Store.InsertRecord(batchID, rec); err != nil {
			return res, err
		}
		r := p.Eng.Run(rec, false)
		if err := p.persistResult(batchID, r); err != nil {
			return res, err
		}
	}
	res.RecordCnt = len(out.Records)
	return res, perr
}

// RecoverTruncated re-feeds a completed version of the previously truncated
// final record. It is marked recovered and routed through the same machine.
func (p *Pipeline) RecoverTruncated(batchID string, completed []byte) (model.Record, error) {
	out, err := ingest.Parse(batchID, completed)
	if err != nil {
		return model.Record{}, fmt.Errorf("recovery parse: %w", err)
	}
	if len(out.Records) == 0 {
		return model.Record{}, fmt.Errorf("recovery: no record in completed fragment")
	}
	rec := out.Records[len(out.Records)-1]
	if err := p.Store.InsertRecord(batchID, rec); err != nil {
		return rec, err
	}
	r := p.Eng.Run(rec, true)
	if err := p.persistResult(batchID, r); err != nil {
		return rec, err
	}
	if err := p.Store.MarkRecovered(batchID); err != nil {
		return rec, err
	}
	return rec, nil
}

func (p *Pipeline) persistResult(batchID string, r engine.Result) error {
	for _, t := range r.Transitions {
		if err := p.Store.AppendTransition(batchID, t); err != nil {
			return err
		}
	}
	if r.FirstError != nil {
		if err := p.Store.SetFirstError(batchID, *r.FirstError); err != nil {
			return err
		}
	}
	return nil
}

// PersistForFuzz exposes transition persistence to the libFuzzer bridge while
// keeping the shared implementation identical to the live/ingest path.
func (p *Pipeline) PersistForFuzz(batchID string, r engine.Result) error {
	return p.persistResult(batchID, r)
}

// Replay re-runs the state machine from retained raw evidence and verifies it
// matches the persisted transition trail, returning a report that names the
// first error state of every record.
func (p *Pipeline) Replay(batchID string) (model.ReplayReport, error) {
	b, err := p.Store.Batch(batchID)
	if err != nil {
		return model.ReplayReport{}, err
	}
	recs, err := p.Store.RawRecords(batchID)
	if err != nil {
		return model.ReplayReport{}, err
	}
	report := model.ReplayReport{BatchID: batchID, EvidenceDB: p.Store.DSN()}
	report.Records = len(recs)

	for _, rec := range recs {
		// Recovered records carry a TRUNCATED step in storage; mirror that flag
		// so the replayed transition sequence is identical by construction.
		recovered := b.Recovered && p.Store.HasState(batchID, rec.RecordID, model.StateTruncated)
		replayed := p.Eng.Run(rec, recovered)
		stored, err := p.Store.Transitions(batchID, rec.RecordID)
		if err != nil {
			return report, err
		}
		if diff := diffTransitions(replayed.Transitions, stored); diff != "" {
			return report, fmt.Errorf("replay divergence for %s: %s", rec.RecordID, diff)
		}
		report.Transitions += len(replayed.Transitions)
		if recovered {
			report.Recovered++
		}
	}

	firsts, err := p.Store.FirstErrors(batchID)
	if err != nil {
		return report, err
	}
	report.FirstErrors = firsts
	report.ReplayedOK = true
	return report, nil
}

// diffTransitions compares the evidence-bearing fields of two trails.
func diffTransitions(want, got []model.Transition) string {
	if len(want) != len(got) {
		return fmt.Sprintf("transition count want=%d got=%d", len(want), len(got))
	}
	for i := range want {
		w, g := want[i], got[i]
		if w.ToState != g.ToState || w.TriggerSite != g.TriggerSite ||
			w.Reason != g.Reason || w.Granted != g.Granted || w.InputHash != g.InputHash {
			return fmt.Sprintf("step %d mismatch want(%s/%s) got(%s/%s)",
				i, w.ToState, w.TriggerSite, g.ToState, g.TriggerSite)
		}
	}
	return ""
}
