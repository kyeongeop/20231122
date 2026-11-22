package main

/*
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"unsafe"

	"example.com/replay-review/internal/detect"
	"example.com/replay-review/internal/model"
)

// fuzzCase is the libFuzzer input envelope. Keeping it JSON means every
// crashing corpus entry is directly readable by a reviewer.
type fuzzCase struct {
	Config model.Config  `json:"config"`
	Events []model.Event `json:"events"`
	Split  int           `json:"split"`
}

var mem = newFuzzMem()

//export RRFuzzInit
func RRFuzzInit() {
	mem = newFuzzMem()
}

//export RRFuzzRun
func RRFuzzRun(data *C.uchar, size C.size_t) (rc C.int) {
	defer func() {
		if recover() != nil {
			rc = -1
		}
	}()
	if size == 0 || size > 1<<20 {
		return 0
	}
	raw := C.GoBytes(unsafe.Pointer(data), C.int(size))

	var tc fuzzCase
	if err := json.Unmarshal(raw, &tc); err != nil {
		return 0 // unstructured inputs are ignored, not crashes
	}
	if err := tc.Config.Validate(); err != nil {
		return 0
	}
	if len(tc.Events) > 10_000 {
		return 0
	}
	split := tc.Split
	if split < 0 || split > len(tc.Events) {
		split = len(tc.Events) / 2
	}

	// One-shot reference run.
	oneShot := detect.New(tc.Config, mem, mem).Process(tc.Events)

	// Segmented run over the same stream, restoring from JSON snapshots at
	// the split point exactly as the production pipeline restores from SQLite.
	firstDetector := detect.New(tc.Config, mem, mem)
	first := firstDetector.Process(tc.Events[:split])
	snapRaw, err := json.Marshal(firstDetector.Snapshot())
	if err != nil {
		return -2
	}
	var snap detect.Snapshot
	if err := json.Unmarshal(snapRaw, &snap); err != nil {
		return -3
	}
	second := detect.Restore(tc.Config, mem, mem, snap).Process(tc.Events[split:])

	segmented := append(append([]model.Decision{}, first.Decisions...), second.Decisions...)
	if !sameDecisions(segmented, oneShot.Decisions) {
		panic("segmented/one-shot decision divergence")
	}

	// Snapshot round-trip must preserve issues and device cursors.
	reSnap := detect.Restore(tc.Config, mem, mem, snap).Snapshot()
	if len(reSnap.Issues) != len(snap.Issues) || len(reSnap.Devices) != len(snap.Devices) {
		panic("snapshot round-trip lost state")
	}

	// Every produced verdict must use a known outcome label.
	for _, dec := range oneShot.Decisions {
		switch dec.Outcome {
		case model.OutcomeOK, model.OutcomeReplay, model.OutcomeExpired,
			model.OutcomeUnknownCode:
		default:
			panic("unknown outcome label: " + dec.Outcome)
		}
	}
	return C.int(len(oneShot.Decisions))
}

func sameDecisions(a, b []model.Decision) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Sequence != b[i].Sequence ||
			a[i].DeviceID != b[i].DeviceID ||
			a[i].Outcome != b[i].Outcome ||
			a[i].Reason != b[i].Reason ||
			a[i].AgeMs != b[i].AgeMs {
			return false
		}
	}
	return true
}

// fuzzMem is an in-memory IssueFinder/IssueSink so the fuzz target stays
// independent of SQLite and remains fast and deterministic.
type fuzzMem struct {
	issues map[string]model.IssueState
}

func newFuzzMem() *fuzzMem {
	return &fuzzMem{issues: map[string]model.IssueState{}}
}

func (m *fuzzMem) FindIssue(code, userID string) (model.IssueState, bool, error) {
	v, ok := m.issues[model.IssueKey(code, userID)]
	return v, ok, nil
}

func (m *fuzzMem) SaveIssue(iss model.IssueState) error {
	m.issues[model.IssueKey(iss.Code, iss.UserID)] = iss
	return nil
}

func main() {}
