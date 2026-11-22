package httpwire

import (
	"fmt"
	"strconv"
	"strings"
)

// readBody applies the connection profile to decide how the message body is
// framed, then consumes exactly those bytes from rest.
func (c *Conn) readBody(req *Request, rest []byte) (body []byte, consumed int, err error) {
	cls := req.Get("Content-Length")
	tes := req.Get("Transfer-Encoding")
	chunked := false
	for _, te := range tes {
		if c.profileChunked(te) {
			chunked = true
		}
	}
	useChunked := false
	var cl int
	switch c.Profile {
	case Frontend:
		// Front-end: first Content-Length wins; TE only honored when no CL.
		if len(cls) > 0 {
			cl, err = parseCL(cls[0])
			if err != nil {
				return nil, 0, err
			}
		} else if chunked {
			useChunked = true
		}
	case Backend:
		// Back-end: Transfer-Encoding wins over Content-Length; last CL wins.
		if chunked {
			useChunked = true
		} else if len(cls) > 0 {
			cl, err = parseCL(cls[len(cls)-1])
			if err != nil {
				return nil, 0, err
			}
		}
	case FrontendTE:
		// Front-end: Transfer-Encoding wins; otherwise first CL wins.
		if chunked {
			useChunked = true
		} else if len(cls) > 0 {
			cl, err = parseCL(cls[0])
			if err != nil {
				return nil, 0, err
			}
		}
	case BackendCL:
		// Back-end: Content-Length wins over Transfer-Encoding; last CL wins.
		if len(cls) > 0 {
			cl, err = parseCL(cls[len(cls)-1])
			if err != nil {
				return nil, 0, err
			}
		} else if chunked {
			useChunked = true
		}
	}
	if useChunked {
		return c.readChunked(rest)
	}
	if cl > 0 {
		if c.Limits.MaxBodyBytes > 0 && cl > c.Limits.MaxBodyBytes {
			return nil, 0, fmt.Errorf("%w: declared=%d limit=%d", ErrBodyTooLarge, cl, c.Limits.MaxBodyBytes)
		}
		if len(rest) < cl {
			return nil, 0, fmt.Errorf("%w: need %d body bytes, have %d", ErrIncomplete, cl, len(rest))
		}
		return append([]byte(nil), rest[:cl]...), cl, nil
	}
	return nil, 0, nil
}

// profileChunked decides whether a Transfer-Encoding value counts as
// "chunked" under this connection's profile.
func (c *Conn) profileChunked(te string) bool {
	switch c.Profile {
	case Frontend, FrontendTE:
		// Strict: only the exact token is understood.
		return strings.EqualFold(strings.TrimSpace(te), "chunked")
	case Backend, BackendCL:
		// Lenient: normalize and look for a chunked token anywhere, which is
		// what makes obfuscated values like "xchunked" dangerous.
		norm := strings.ToLower(strings.TrimSpace(te))
		for _, tok := range strings.FieldsFunc(norm, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == ';'
		}) {
			if strings.HasSuffix(tok, "chunked") {
				return true
			}
		}
		return false
	}
	return false
}

func parseCL(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid Content-Length: %q", s)
	}
	return n, nil
}

// readChunked consumes a chunked body from rest.
func (c *Conn) readChunked(rest []byte) (body []byte, consumed int, err error) {
	var out []byte
	pos := 0
	chunks := 0
	for {
		lineEnd := indexCRLF(rest[pos:])
		if lineEnd < 0 {
			return nil, 0, fmt.Errorf("%w: chunk size line", ErrIncomplete)
		}
		sizeField := strings.TrimSpace(string(rest[pos : pos+lineEnd]))
		if i := strings.IndexByte(sizeField, ';'); i >= 0 {
			sizeField = sizeField[:i]
		}
		size, cerr := strconv.ParseInt(sizeField, 16, 64)
		if cerr != nil || size < 0 {
			return nil, 0, fmt.Errorf("invalid chunk size: %q", sizeField)
		}
		pos += lineEnd + 2
		if size == 0 {
			// Terminal chunk: expect trailing CRLF (no trailer support).
			if len(rest)-pos < 2 {
				return nil, 0, fmt.Errorf("%w: terminal CRLF", ErrIncomplete)
			}
			if rest[pos] != '\r' || rest[pos+1] != '\n' {
				return nil, 0, fmt.Errorf("malformed terminal chunk")
			}
			pos += 2
			return out, pos, nil
		}
		chunks++
		if c.Limits.MaxChunks > 0 && chunks > c.Limits.MaxChunks {
			return nil, 0, fmt.Errorf("%w: chunks=%d limit=%d", ErrTooManyChunks, chunks, c.Limits.MaxChunks)
		}
		if c.Limits.MaxBodyBytes > 0 && int64(len(out))+size > int64(c.Limits.MaxBodyBytes) {
			return nil, 0, fmt.Errorf("%w: chunked body would reach %d limit=%d", ErrBodyTooLarge, int64(len(out))+size, c.Limits.MaxBodyBytes)
		}
		if int64(len(rest)-pos) < size+2 {
			return nil, 0, fmt.Errorf("%w: chunk data", ErrIncomplete)
		}
		out = append(out, rest[pos:pos+int(size)]...)
		pos += int(size)
		if rest[pos] != '\r' || rest[pos+1] != '\n' {
			return nil, 0, fmt.Errorf("missing CRLF after chunk data")
		}
		pos += 2
	}
}

func indexCRLF(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}
