package pipeline

import (
	"encoding/json"
	"fmt"
	"os"

	"example.com/replay-review/internal/model"
)

// InputFile is the on-disk stream format. Records may arrive unordered; the
// pipeline sorts by sequence before processing so resume positions are stable.
type InputFile struct {
	StreamID string        `json:"stream_id"`
	Config   *model.Config `json:"config,omitempty"`
	Events   []model.Event `json:"events"`
}

// LoadInput reads and normalizes a stream file: JSON parse, schema validation,
// and a stable sequence/device sort. Validation errors do not abort loading;
// the detector records them as evidence.
func LoadInput(path string) (InputFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return InputFile{}, err
	}
	var in InputFile
	if err := json.Unmarshal(raw, &in); err != nil {
		return InputFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if in.StreamID == "" {
		return InputFile{}, fmt.Errorf("stream_id is required")
	}
	sortEvents(in.Events)
	return in, nil
}

func sortEvents(events []model.Event) {
	for i := 1; i < len(events); i++ {
		for j := i; j > 0 && less(events[j], events[j-1]); j-- {
			events[j], events[j-1] = events[j-1], events[j]
		}
	}
}

func less(a, b model.Event) bool {
	if a.Sequence != b.Sequence {
		return a.Sequence < b.Sequence
	}
	return a.DeviceID < b.DeviceID
}
