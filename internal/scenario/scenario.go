// Package scenario constructs the extreme-parameter inputs used to
// reconstruct HTTP request-smuggling runs, including the empty input,
// an oversized input, and one sample on each side of a limit boundary.
package scenario

import (
	"bytes"
	"fmt"

	"github.com/kyeongeop/20231122/internal/httpwire"
)

// Scenario is one named attack/boundary input.
type Scenario struct {
	Name     string
	Kind     string // "attack", "empty", "oversize", "boundary-before", "boundary-after"
	Frontend httpwire.Profile
	Backend  httpwire.Profile
	Build    func() []byte
}

const oversizeBytes = 16 << 20 // 16 MiB, far beyond the 1 MiB ingress cap

func head(method, path string, headers ...string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: api.local\r\n", method, path)
	for _, h := range headers {
		b.WriteString(h)
		b.WriteString("\r\n")
	}
	b.WriteString("Connection: keep-alive\r\n\r\n")
	return b.Bytes()
}

func smuggledGET(marker string) []byte {
	return []byte("GET /admin HTTP/1.1\r\nHost: api.local\r\nX-Smuggled: " + marker + "\r\n\r\n")
}

func chunkedBody(pairs ...string) []byte {
	var b bytes.Buffer
	for _, p := range pairs {
		fmt.Fprintf(&b, "%x\r\n%s\r\n", len(p), p)
	}
	b.WriteString("0\r\n\r\n")
	return b.Bytes()
}

// All returns the full scenario set in deterministic order.
func All() []Scenario {
	return []Scenario{
		{
			Name: "CASE-CLTE", Kind: "attack",
			Frontend: httpwire.Frontend, Backend: httpwire.Backend,
			Build: func() []byte {
				// Front-end honors Content-Length: 64; back-end honors chunked
				// and stops at the 0-chunk, leaving GET /admin on the reused conn.
				body := append([]byte("0\r\n\r\n"), smuggledGET("cl-te")...)
				return append(head("POST", "/public",
					"Content-Length: 64", "Transfer-Encoding: chunked"), body...)
			},
		},
		{
			Name: "CASE-TECL", Kind: "attack",
			Frontend: httpwire.FrontendTE, Backend: httpwire.BackendCL,
			Build: func() []byte {
				// Front-end honors chunked and forwards GET /admin as a second
				// request; back-end honors Content-Length: 64, absorbs the
				// smuggled prefix as body bytes and poisons the reused conn.
				body := append([]byte("0\r\n\r\n"), smuggledGET("te-cl")...)
				return append(head("POST", "/public",
					"Content-Length: 64", "Transfer-Encoding: chunked"), body...)
			},
		},
		{
			Name: "CASE-DUP-CL", Kind: "attack",
			Frontend: httpwire.Frontend, Backend: httpwire.Backend,
			Build: func() []byte {
				// Duplicate Content-Length: front-end takes the first (71),
				// back-end takes the last (5); the difference is smuggled.
				body := append([]byte("0\r\n\r\n"), smuggledGET("duplicate-cl")...)
				return append(head("POST", "/public",
					"Content-Length: 71", "Content-Length: 5"), body...)
			},
		},
		{
			Name: "CASE-TE-OBFUSCATED", Kind: "attack",
			Frontend: httpwire.Frontend, Backend: httpwire.Backend,
			Build: func() []byte {
				// Obfuscated Transfer-Encoding: front-end ignores "xchunked"
				// and uses Content-Length: 72; back-end normalizes to chunked.
				body := append([]byte("0\r\n\r\n"), smuggledGET("obfuscated-te")...)
				return append(head("POST", "/public",
					"Content-Length: 72", "Transfer-Encoding: xchunked"), body...)
			},
		},
		{
			Name: "CASE-EMPTY", Kind: "empty",
			Frontend: httpwire.Frontend, Backend: httpwire.Backend,
			Build: func() []byte {
				return nil // empty input must be handled without a parse
			},
		},
		{
			Name: "CASE-OVERSIZE", Kind: "oversize",
			Frontend: httpwire.Frontend, Backend: httpwire.Backend,
			Build: func() []byte {
				// 16 MiB body with a huge declared Content-Length:
				// rejected at the 1 MiB ingress cap before parsing.
				h := head("POST", "/public", "Content-Length: 99999999")
				return append(h, make([]byte, oversizeBytes-len(h))...)
			},
		},
		{
			Name: "BOUNDARY-BEFORE", Kind: "boundary-before",
			Frontend: httpwire.Frontend, Backend: httpwire.Backend,
			Build: func() []byte {
				// Chunked body of exactly MaxBodyBytes (4): accepted.
				return append(head("PUT", "/public", "Transfer-Encoding: chunked"),
					chunkedBody("00", "01")...)
			},
		},
		{
			Name: "BOUNDARY-AFTER", Kind: "boundary-after",
			Frontend: httpwire.Frontend, Backend: httpwire.Backend,
			Build: func() []byte {
				// Chunked body of MaxBodyBytes+2 (6): rejected by the limit.
				return append(head("PUT", "/public", "Transfer-Encoding: chunked"),
					chunkedBody("00", "01", "02")...)
			},
		},
	}
}
