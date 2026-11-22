// Package escape implements a deterministic template-variable escaping
// engine with hard limits and explicit degradation paths.
//
// Template syntax: {{name}} substitutes the HTML-escaped value of the
// variable "name". Everything else is literal text.
package escape

import (
	"errors"
	"fmt"
	"strings"
)

// Limits are the extreme parameters the engine is organized around.
// A zero value for a field means "no limit" for that field.
type Limits struct {
	MaxTemplateBytes int // hard reject templates larger than this
	MaxValueBytes    int // values longer than this are truncated (degraded)
	MaxOutputBytes   int // output budget; exceeding it truncates (degraded)
	MaxVars          int // hard reject templates with more variables
}

// Event kinds recorded during rendering.
const (
	EventValueTruncated  = "value-truncated"
	EventOutputTruncated = "output-truncated"
	EventUnknownVar      = "unknown-var"
	EventUnterminated    = "unterminated-var"
)

// Event is a single degradation observation. Offset is the raw byte
// offset inside the input template where the condition was detected.
type Event struct {
	Kind   string
	Offset int
	Detail string
}

// Result is the outcome of one Render call.
type Result struct {
	Output   []byte
	Events   []Event
	Degraded bool // true if any soft degradation was applied
}

// Hard failures: the caller is expected to record a resource-exhaustion
// event and take the degradation path instead of rendering.
var (
	ErrTemplateTooLarge = errors.New("template exceeds MaxTemplateBytes")
	ErrTooManyVars      = errors.New("template declares more vars than MaxVars")
)

var htmlEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&#34;",
	"'", "&#39;",
)

// EscapeHTML escapes a variable value for safe HTML interpolation.
func EscapeHTML(s string) string { return htmlEscaper.Replace(s) }

// Render substitutes every {{name}} occurrence with the escaped value of
// vars[name]. It is deterministic: identical inputs always produce
// identical Output and Events.
func Render(tmpl []byte, vars map[string]string, lim Limits) (Result, error) {
	if lim.MaxTemplateBytes > 0 && len(tmpl) > lim.MaxTemplateBytes {
		return Result{}, ErrTemplateTooLarge
	}
	var res Result
	var out strings.Builder
	out.Grow(len(tmpl))
	nvars := 0
	i := 0
	for i < len(tmpl) {
		open := indexOpen(tmpl, i)
		if open < 0 {
			res.writeLiteral(&out, lim, tmpl[i:], i)
			break
		}
		res.writeLiteral(&out, lim, tmpl[i:open], open)
		close := indexClose(tmpl, open+2)
		if close < 0 {
			res.addEvent(EventUnterminated, open, "no closing }}")
			res.writeLiteral(&out, lim, tmpl[open:], open)
			break
		}
		name := string(tmpl[open+2 : close])
		nvars++
		if lim.MaxVars > 0 && nvars > lim.MaxVars {
			return Result{}, ErrTooManyVars
		}
		val, ok := vars[name]
		if !ok {
			res.addEvent(EventUnknownVar, open, fmt.Sprintf("name=%q", name))
		} else {
			if lim.MaxValueBytes > 0 && len(val) > lim.MaxValueBytes {
				res.addEvent(EventValueTruncated, open,
					fmt.Sprintf("name=%q len=%d limit=%d", name, len(val), lim.MaxValueBytes))
				val = val[:lim.MaxValueBytes]
			}
			res.writeEscaped(&out, lim, val, open)
		}
		i = close + 2
	}
	res.Output = []byte(out.String())
	return res, nil
}

func (r *Result) addEvent(kind string, offset int, detail string) {
	r.Events = append(r.Events, Event{Kind: kind, Offset: offset, Detail: detail})
	r.Degraded = true
}

// writeLiteral appends literal template bytes under the output budget.
func (r *Result) writeLiteral(out *strings.Builder, lim Limits, b []byte, offset int) {
	r.write(out, lim, string(b), offset)
}

// writeEscaped appends an escaped variable value under the output budget.
func (r *Result) writeEscaped(out *strings.Builder, lim Limits, val string, offset int) {
	r.write(out, lim, EscapeHTML(val), offset)
}

func (r *Result) write(out *strings.Builder, lim Limits, s string, offset int) {
	if lim.MaxOutputBytes > 0 && out.Len()+len(s) > lim.MaxOutputBytes {
		remain := lim.MaxOutputBytes - out.Len()
		if remain < 0 {
			remain = 0
		}
		out.WriteString(s[:remain])
		r.addEvent(EventOutputTruncated, offset,
			fmt.Sprintf("budget=%d dropped=%d", lim.MaxOutputBytes, len(s)-remain))
		return
	}
	out.WriteString(s)
}

func indexOpen(b []byte, from int) int {
	for i := from; i+1 < len(b); i++ {
		if b[i] == '{' && b[i+1] == '{' {
			return i
		}
	}
	return -1
}

func indexClose(b []byte, from int) int {
	for i := from; i+1 < len(b); i++ {
		if b[i] == '}' && b[i+1] == '}' {
			return i
		}
	}
	return -1
}
