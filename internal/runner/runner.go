// Package runner implements the pausable template-escaping pipeline:
// a repeated object (Repeat records rendered from one template) is
// processed in batches, checkpoints are persisted to SQLite, and a
// paused or resource-exhausted run can resume and continue.
package runner

import (
	"errors"
	"strconv"
	"strings"

	"tve/internal/escape"
)

// ErrPaused is returned when the runner paused itself (PauseAfter).
var ErrPaused = errors.New("runner paused")

// ErrResourceExhausted is returned when the output budget was exceeded.
var ErrResourceExhausted = errors.New("resource exhausted: output budget")

// Params are the extreme parameters the repeated object is built around.
type Params struct {
	Seed           int64 `json:"seed"`
	Repeat         int   `json:"repeat"`
	TemplatePad    int   `json:"template_pad"`
	ValueLen       int   `json:"value_len"`
	BatchSize      int   `json:"batch_size"`
	MaxValueBytes  int   `json:"max_value_bytes"`
	MaxOutputBytes int   `json:"max_output_bytes"`
	PauseAfter     int   `json:"pause_after"`
	OutputBudget   int64 `json:"output_budget"`
}

// Template builds the deterministic padded template for these params.
func (p Params) Template() []byte {
	head := `<html><body><h1>{{id}}</h1><div>{{payload}}</div><b>{{big}}</b>`
	if p.TemplatePad > len(head) {
		head += strings.Repeat("P", p.TemplatePad-len(head))
	}
	return []byte(head + `</body></html>`)
}

// RawOffset maps a record index to its raw offset in the material.
func RawOffset(materialLen, valueLen, index int) int64 {
	span := materialLen - valueLen
	if span <= 0 {
		return 0
	}
	return int64(index%span) * int64(valueLen) % int64(span)
}

// effVlen is the value length in effect for the given mode.
func effVlen(p Params, degraded bool) int {
	if !degraded {
		return p.ValueLen
	}
	v := p.ValueLen / 8
	if v < 1 {
		v = 1
	}
	return v
}

// RecordOutput renders one record deterministically. Degraded mode
// shrinks values and disables the oversized "big" variable.
func RecordOutput(p Params, material []byte, index int, degraded bool) ([]byte, []escape.Event, error) {
	vlen := effVlen(p, degraded)
	off := RawOffset(len(material), vlen, index)
	end := int(off) + vlen
	if end > len(material) {
		end = len(material)
	}
	vars := map[string]string{
		"id":      strconv.Itoa(index),
		"payload": string(material[off:end]),
	}
	if !degraded {
		vars["big"] = strings.Repeat("B", p.ValueLen*2)
	}
	res, err := escape.Render(p.Template(), vars, escape.Limits{
		MaxValueBytes:  p.MaxValueBytes,
		MaxOutputBytes: p.MaxOutputBytes,
	})
	return res.Output, res.Events, err
}
