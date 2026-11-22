// Package depthjson validates JSON documents with a hard nesting-depth
// limit. It reports precisely where validation failed (byte offset,
// depth, JSON path) so callers can map an attack input to its trigger
// location.
package depthjson

import (
	"fmt"
	"strings"
)

// DefaultMaxDepth is the nesting limit applied when callers pass 0.
const DefaultMaxDepth = 128

// Kind classifies a validation failure.
type Kind string

const (
	KindOK           Kind = "ok"
	KindDepth        Kind = "depth_exceeded"
	KindTruncated    Kind = "truncated"
	KindSyntax       Kind = "syntax"
	KindTrailingData Kind = "trailing_data"
)

// Error pinpoints where and why validation failed.
type Error struct {
	Kind   Kind
	Offset int    // byte offset in the input
	Depth  int    // nesting depth at the failure point
	Path   string // JSON path at the failure point, e.g. $.a[2].b
	Msg    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s at offset %d (depth %d, path %s): %s",
		e.Kind, e.Offset, e.Depth, e.Path, e.Msg)
}

// Location returns a compact "offset:depth:path" trigger descriptor.
func (e *Error) Location() string {
	return fmt.Sprintf("offset=%d depth=%d path=%s", e.Offset, e.Depth, e.Path)
}

type frame struct {
	container byte   // '{' or '['
	key       string // current key when container is '{'
	index     int    // element counter when container is '['
	expectKey bool   // object: next token must be a key
}

// Validate checks that data is a single well-formed JSON value whose
// nesting never exceeds maxDepth (0 means DefaultMaxDepth). It never
// recurses, so hostile inputs cannot overflow the goroutine stack.
func Validate(data []byte, maxDepth int) *Error {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	p := &parser{data: data, max: maxDepth}
	return p.run()
}

type parser struct {
	data       []byte
	pos        int
	max        int
	stack      []frame
	lastString string
}

func (p *parser) run() *Error {
	p.skipWS()
	if p.pos >= len(p.data) {
		return p.fail(KindTruncated, "empty input")
	}
	if err := p.value(); err != nil {
		return err
	}
	p.skipWS()
	if p.pos < len(p.data) {
		return p.fail(KindTrailingData, "unexpected data after top-level value")
	}
	return nil
}

func (p *parser) value() *Error {
	p.skipWS()
	if p.pos >= len(p.data) {
		return p.fail(KindTruncated, "unexpected end of input, value expected")
	}
	switch c := p.data[p.pos]; {
	case c == '{' || c == '[':
		return p.container(c)
	case c == '"':
		return p.str()
	case c == 't':
		return p.lit("true")
	case c == 'f':
		return p.lit("false")
	case c == 'n':
		return p.lit("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return p.num()
	default:
		return p.fail(KindSyntax, fmt.Sprintf("unexpected byte %q", c))
	}
}

func (p *parser) container(open byte) *Error {
	if len(p.stack) >= p.max {
		return p.fail(KindDepth, fmt.Sprintf("nesting exceeds limit %d", p.max))
	}
	close := byte('}')
	if open == '[' {
		close = ']'
	}
	p.stack = append(p.stack, frame{container: open, expectKey: open == '{'})
	p.pos++
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == close {
		p.pos++
		return p.pop()
	}
	for {
		top := &p.stack[len(p.stack)-1]
		if top.container == '{' {
			p.skipWS()
			if p.pos >= len(p.data) {
				return p.fail(KindTruncated, "object key expected")
			}
			if p.data[p.pos] != '"' {
				return p.fail(KindSyntax, "object key must be a string")
			}
			if err := p.str(); err != nil {
				return err
			}
			top.key = p.lastString
			p.skipWS()
			if p.pos >= len(p.data) {
				return p.fail(KindTruncated, "':' expected after object key")
			}
			if p.data[p.pos] != ':' {
				return p.fail(KindSyntax, "':' expected after object key")
			}
			p.pos++
		}
		if err := p.value(); err != nil {
			return err
		}
		top = &p.stack[len(p.stack)-1]
		if top.container == '[' {
			top.index++
		}
		p.skipWS()
		if p.pos >= len(p.data) {
			return p.fail(KindTruncated, fmt.Sprintf("%q expected", close))
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
			p.skipWS()
		case close:
			p.pos++
			return p.pop()
		default:
			return p.fail(KindSyntax, fmt.Sprintf("',' or %q expected", close))
		}
	}
}

func (p *parser) pop() *Error {
	p.stack = p.stack[:len(p.stack)-1]
	return nil
}

func (p *parser) str() *Error {
	p.pos++ // opening quote
	var b strings.Builder
	for {
		if p.pos >= len(p.data) {
			return p.fail(KindTruncated, "unterminated string")
		}
		c := p.data[p.pos]
		switch c {
		case '"':
			p.pos++
			p.lastString = b.String()
			return nil
		case '\\':
			if p.pos+1 >= len(p.data) {
				return p.fail(KindTruncated, "unterminated escape")
			}
			esc := p.data[p.pos+1]
			switch esc {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				b.WriteByte('?')
				p.pos += 2
			case 'u':
				if p.pos+5 >= len(p.data) {
					return p.fail(KindTruncated, `unterminated \u escape`)
				}
				for _, h := range p.data[p.pos+2 : p.pos+6] {
					if !isHex(h) {
						return p.fail(KindSyntax, `invalid \u escape`)
					}
				}
				b.WriteByte('?')
				p.pos += 6
			default:
				return p.fail(KindSyntax, fmt.Sprintf("invalid escape %q", esc))
			}
		default:
			if c < 0x20 {
				return p.fail(KindSyntax, "control character in string")
			}
			b.WriteByte(c)
			p.pos++
		}
	}
}

func (p *parser) lit(word string) *Error {
	if p.pos+len(word) > len(p.data) {
		if strings.HasPrefix(word, string(p.data[p.pos:])) {
			return p.fail(KindTruncated, "literal cut off")
		}
		return p.fail(KindSyntax, "invalid literal")
	}
	if string(p.data[p.pos:p.pos+len(word)]) != word {
		return p.fail(KindSyntax, "invalid literal")
	}
	p.pos += len(word)
	return nil
}

func (p *parser) num() *Error {
	if p.data[p.pos] == '-' {
		p.pos++
	}
	if p.pos >= len(p.data) {
		return p.fail(KindTruncated, "number cut off")
	}
	if !isDigit(p.data[p.pos]) {
		return p.fail(KindSyntax, "invalid number")
	}
	for p.pos < len(p.data) && isDigit(p.data[p.pos]) {
		p.pos++
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if p.pos >= len(p.data) || !isDigit(p.data[p.pos]) {
			return p.fail(KindSyntax, "invalid fraction")
		}
		for p.pos < len(p.data) && isDigit(p.data[p.pos]) {
			p.pos++
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if p.pos >= len(p.data) {
			return p.fail(KindTruncated, "exponent cut off")
		}
		if !isDigit(p.data[p.pos]) {
			return p.fail(KindSyntax, "invalid exponent")
		}
		for p.pos < len(p.data) && isDigit(p.data[p.pos]) {
			p.pos++
		}
	}
	return nil
}

func (p *parser) skipWS() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) fail(kind Kind, msg string) *Error {
	return &Error{Kind: kind, Offset: p.pos, Depth: len(p.stack), Path: p.path(), Msg: msg}
}

func (p *parser) path() string {
	var b strings.Builder
	b.WriteByte('$')
	for _, f := range p.stack {
		if f.container == '{' {
			if f.key != "" {
				b.WriteByte('.')
				b.WriteString(f.key)
			}
		} else {
			fmt.Fprintf(&b, "[%d]", f.index)
		}
	}
	return b.String()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
