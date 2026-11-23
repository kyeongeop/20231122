package experiment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"example.com/deserialize-boundary/internal/ledger"
	"example.com/deserialize-boundary/internal/wire"
)

const (
	OpSubmit   = "submit"
	OpCancel   = "cancel"
	OpCommit   = "commit"
	OpParseRaw = "parse_raw"
)

type Op struct {
	Kind       string       `json:"kind"`
	Label      string       `json:"label,omitempty"`
	Record     *wire.Record `json:"record,omitempty"`
	Reason     string       `json:"reason,omitempty"`
	RawHex     string       `json:"raw_hex,omitempty"`
	ExpectKind string       `json:"expect_kind,omitempty"`
}

type Scenario struct {
	ID          string
	RunID       string
	Description string
	Role        string
	Mode        string
	Expected    string
	Ops         []Op
}

type State struct {
	Phase         string            `json:"phase"`
	StagedIDs     []int             `json:"staged_ids"`
	CommittedIDs  []int             `json:"committed_ids"`
	Canceled      bool              `json:"canceled"`
	ParserDigests map[string]string `json:"parser_digests,omitempty"`
	CorpusFiles   int               `json:"corpus_files,omitempty"`
	ValidInputs   int               `json:"valid_inputs,omitempty"`
	InvalidInputs int               `json:"invalid_inputs,omitempty"`
	Panics        int               `json:"panics,omitempty"`
	LastOutcome   string            `json:"last_outcome"`
}

func (s State) clone() State {
	out := s
	out.StagedIDs = append([]int(nil), s.StagedIDs...)
	out.CommittedIDs = append([]int(nil), s.CommittedIDs...)
	if s.ParserDigests != nil {
		out.ParserDigests = make(map[string]string, len(s.ParserDigests))
		for key, value := range s.ParserDigests {
			out.ParserDigests[key] = value
		}
	}
	return out
}

type eventInput struct {
	Scenario string `json:"scenario"`
	Index    int    `json:"index"`
	Op       Op     `json:"op"`
	FrameHex string `json:"frame_hex,omitempty"`
}

type ScenarioResult struct {
	RunID       string         `json:"run_id"`
	Scenario    string         `json:"scenario"`
	Role        string         `json:"role"`
	Status      string         `json:"status"`
	StateDigest string         `json:"state_digest"`
	RecordIDs   []int          `json:"record_ids"`
	Steps       int            `json:"steps"`
	Outcomes    map[string]int `json:"outcomes"`
}

type stepRecorder struct {
	ctx     context.Context
	ledger  *ledger.Ledger
	runID   string
	seq     int
	started time.Time
}

func (r *stepRecorder) record(before, after State, action, outcome string, input eventInput, result map[string]any) error {
	r.seq++
	inputJSON, err := json.Marshal(input)
	if err != nil {
		return err
	}
	beforeJSON, err := json.Marshal(before)
	if err != nil {
		return err
	}
	afterJSON, err := json.Marshal(after)
	if err != nil {
		return err
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return err
	}
	sum := sha256Hex(inputJSON)
	return r.ledger.AppendStep(r.ctx, ledger.Step{
		RunID:       r.runID,
		Seq:         r.seq,
		Phase:       "event",
		Action:      action,
		InputSHA256: sum,
		InputJSON:   string(inputJSON),
		InputHex:    input.FrameHex,
		StateBefore: string(beforeJSON),
		StateAfter:  string(afterJSON),
		Outcome:     outcome,
		ResultJSON:  string(resultJSON),
		DurationUS:  time.Since(r.started).Microseconds(),
	})
}

func rawHex(data []byte) string {
	return hex.EncodeToString(data)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
