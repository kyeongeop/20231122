// Package httpwire parses raw HTTP/1.1 byte streams the way a front-end
// proxy or a back-end server would, including keep-alive connection reuse.
// Divergent parsing profiles are what makes HTTP request smuggling possible.
package httpwire

import (
	"bytes"
	"fmt"
	"strings"
)

// Profile selects how ambiguous framing headers are interpreted to be resolved.
type Profile string

const (
	// Frontend prefers Content-Length over Transfer-Encoding, takes the
	// first of duplicate Content-Length headers and ignores Transfer-Encoding
	// values it does not recognize verbatim.
	Frontend Profile = "frontend"
	// Backend prefers Transfer-Encoding over Content-Length, takes the last
	// of duplicate Content-Length headers and leniently normalizes
	// Transfer-Encoding tokens.
	Backend Profile = "backend"
	// FrontendTE prefers Transfer-Encoding over Content-Length (strict
	// token match), taking the first of duplicate Content-Length headers.
	FrontendTE Profile = "frontend-te"
	// BackendCL prefers Content-Length over Transfer-Encoding, taking the
	// last of duplicate Content-Length headers.
	BackendCL Profile = "backend-cl"
)

// Limits bound a single parsed message. Extreme values are used by the
// smuggling scenarios to exercise boundary behavior.
type Limits struct {
	MaxRequestBytes int // hard cap for one buffered request (0 = unlimited)
	MaxBodyBytes    int // hard cap for a message body (0 = unlimited)
	MaxChunks       int // hard cap for chunk count in one body (0 = unlimited)
	MaxHeaders      int // hard cap for header count (0 = unlimited)
}

// Request is one parsed HTTP message.
type Request struct {
	Method  string
	Path    string
	Proto   string
	Headers []Header
	Body    []byte
	Raw     []byte // exact bytes consumed from the connection
}

// Header is a single header field, order preserved.
type Header struct {
	Name  string
	Value string
}

// Get returns all values for a header name, case-insensitively.
func (r *Request) Get(name string) []string {
	var out []string
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
			out = append(out, h.Value)
		}
	}
	return out
}

// Conn models one reusable keep-alive connection with a pending buffer.
type Conn struct {
	Profile Profile
	Limits  Limits
	buf     []byte
	Reused  int // number of requests parsed on this connection
}

// NewConn wraps clientBytes in a connection using the given profile.
func NewConn(profile Profile, limits Limits, clientBytes []byte) *Conn {
	c := &Conn{Profile: profile, Limits: limits}
	c.buf = append(c.buf, clientBytes...)
	return c
}

// Feed appends more bytes to the connection buffer (connection reuse).
func (c *Conn) Feed(p []byte) { c.buf = append(c.buf, p...) }

// Pending returns the unconsumed bytes still sitting on the connection.
func (c *Conn) Pending() []byte { return c.buf }

var (
	ErrEmpty          = fmt.Errorf("empty input")
	ErrIncomplete     = fmt.Errorf("incomplete request")
	ErrTooLarge       = fmt.Errorf("request exceeds MaxRequestBytes")
	ErrBodyTooLarge   = fmt.Errorf("body exceeds MaxBodyBytes")
	ErrTooManyChunks  = fmt.Errorf("chunk count exceeds MaxChunks")
	ErrTooManyHeaders = fmt.Errorf("header count exceeds MaxHeaders")
)

// Next parses and consumes one request from the connection buffer.
// Leftover bytes stay buffered for the next call (pipeline/reuse).
func (c *Conn) Next() (*Request, error) {
	if len(c.buf) == 0 {
		return nil, ErrEmpty
	}
	if c.Limits.MaxRequestBytes > 0 && len(c.buf) > c.Limits.MaxRequestBytes {
		return nil, fmt.Errorf("%w: buffered=%d limit=%d", ErrTooLarge, len(c.buf), c.Limits.MaxRequestBytes)
	}
	head, rest, ok := splitHead(c.buf)
	if !ok {
		return nil, ErrIncomplete
	}
	lines := bytes.Split(head, []byte("\r\n"))
	reqLine := string(lines[0])
	parts := strings.SplitN(reqLine, " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return nil, fmt.Errorf("malformed request line: %q", reqLine)
	}
	req := &Request{Method: parts[0], Path: parts[1], Proto: parts[2]}
	for _, ln := range lines[1:] {
		if len(ln) == 0 {
			continue
		}
		name, value, found := strings.Cut(string(ln), ":")
		if !found {
			return nil, fmt.Errorf("malformed header line: %q", ln)
		}
		req.Headers = append(req.Headers, Header{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
	}
	if c.Limits.MaxHeaders > 0 && len(req.Headers) > c.Limits.MaxHeaders {
		return nil, fmt.Errorf("%w: got=%d limit=%d", ErrTooManyHeaders, len(req.Headers), c.Limits.MaxHeaders)
	}
	body, consumed, err := c.readBody(req, rest)
	if err != nil {
		return nil, err
	}
	req.Body = body
	total := len(c.buf) - len(rest) + consumed
	req.Raw = append([]byte(nil), c.buf[:total]...)
	c.buf = c.buf[total:]
	c.Reused++
	return req, nil
}

func splitHead(buf []byte) (head, rest []byte, ok bool) {
	i := bytes.Index(buf, []byte("\r\n\r\n"))
	if i < 0 {
		return nil, nil, false
	}
	return buf[:i], buf[i+4:], true
}
