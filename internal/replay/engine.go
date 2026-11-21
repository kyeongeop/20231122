package replay

import (
	"fmt"

	"timeoutfsm/internal/fsm"
	"timeoutfsm/internal/store"
)

// StepRecord is the full per-step evidence: input, result and resulting state.
type StepRecord struct {
	Seq       int64
	Input     fsm.Event
	Outcome   fsm.Outcome
	Snapshot  fsm.Snapshot
	StateHash string
}

// Result captures one run plus, when requested, its single replay verification.
type Result struct {
	RunID          string
	Scenario       string
	Steps          []StepRecord
	FinalHash      string
	Replayed       bool
	ReplayMatch    bool
	ReplayMismatch int
}

// Execute runs a scenario through a fresh machine and journals every step to
// SQLite. When replay is true it performs exactly one post-recovery replay of
// the same ordered stream and compares each state hash against the journal.
func Execute(st *store.Store, runID string, sc Scenario, replay bool) (*Result, error) {
	if err := st.EnsureRun(runID, modeName(replay)); err != nil {
		return nil, err
	}

	m := fsm.NewMachine()
	res := &Result{RunID: runID, Scenario: sc.Name, Replayed: replay}

	for _, ev := range sc.Events {
		out, snap := m.Step(fsm.Input{Event: ev})
		hash := snap.Hash()
		res.Steps = append(res.Steps, StepRecord{
			Seq: ev.Seq, Input: ev, Outcome: out,
			Snapshot: snap, StateHash: hash,
		})
		row := store.EventRow{
			RunID: runID, Seq: ev.Seq, Kind: ev.Kind, MsgID: ev.MsgID,
			Accepted: out.Accepted, Duplicate: out.Duplicate,
			Reason: out.Reason, StateAfter: string(snap.State),
			HashAfter: hash,
		}
		if err := st.AppendEvent(row); err != nil {
			return nil, fmt.Errorf("append seq %d: %w", ev.Seq, err)
		}
	}
	res.FinalHash = m.Snapshot().Hash()

	if replay {
		if err := replayOnce(st, runID, sc, res); err != nil {
			return nil, err
		}
	}
	return res, nil
}

func modeName(replay bool) string {
	if replay {
		return "record_and_replay"
	}
	return "record"
}

// replayOnce rebuilds state from the durable journal, one time, and compares
// every recomputed hash with the originally recorded hash.
func replayOnce(st *store.Store, runID string, sc Scenario, res *Result) error {
	rows, err := st.Events(runID)
	if err != nil {
		return err
	}
	if len(rows) != len(sc.Events) {
		return fmt.Errorf("journal length %d != scenario %d", len(rows), len(sc.Events))
	}

	m := fsm.NewMachine()
	matchAll := true
	for i, row := range rows {
		ev := fsm.Event{Seq: row.Seq, Kind: row.Kind, MsgID: row.MsgID}
		_, snap := m.Step(fsm.Input{Event: ev})
		replayHash := snap.Hash()
		match := replayHash == row.HashAfter
		if !match {
			matchAll = false
			res.ReplayMismatch++
		}
		if err := st.RecordReplayCheck(runID, row.Seq,
			row.HashAfter, replayHash, match); err != nil {
			return err
		}
		_ = i
	}
	res.ReplayMatch = matchAll
	return nil
}
