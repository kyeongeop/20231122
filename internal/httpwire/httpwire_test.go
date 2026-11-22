package httpwire

import (
	"errors"
	"testing"
)

const clteStream = "POST /public HTTP/1.1\r\nHost: api.local\r\n" +
	"Content-Length: 64\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n" +
	"0\r\n\r\nGET /admin HTTP/1.1\r\nHost: api.local\r\nX-Smuggled: cl-te\r\n\r\n"

func TestFrontendPrefersContentLength(t *testing.T) {
	c := NewConn(Frontend, Limits{}, []byte(clteStream))
	req, err := c.Next()
	if err != nil {
		t.Fatalf("frontend parse: %v", err)
	}
	if len(req.Body) != 64 {
		t.Fatalf("frontend body = %d bytes, want 64", len(req.Body))
	}
	if len(c.Pending()) != 0 {
		t.Fatalf("frontend leftover = %d bytes, want 0", len(c.Pending()))
	}
}

func TestBackendPrefersChunked(t *testing.T) {
	c := NewConn(Backend, Limits{}, []byte(clteStream))
	req, err := c.Next()
	if err != nil {
		t.Fatalf("backend parse: %v", err)
	}
	if len(req.Body) != 0 {
		t.Fatalf("backend body = %d bytes, want 0 (0-chunk)", len(req.Body))
	}
	// The smuggled request remains on the reused connection.
	next, err := c.Next()
	if err != nil {
		t.Fatalf("backend second parse: %v", err)
	}
	if next.Path != "/admin" {
		t.Fatalf("backend second request path = %q, want /admin", next.Path)
	}
}

func TestEmptyInput(t *testing.T) {
	c := NewConn(Frontend, Limits{}, nil)
	if _, err := c.Next(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty input err = %v, want ErrEmpty", err)
	}
}

func TestOversizeRejected(t *testing.T) {
	limits := Limits{MaxRequestBytes: 1024}
	c := NewConn(Frontend, limits, make([]byte, 2048))
	if _, err := c.Next(); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize err = %v, want ErrTooLarge", err)
	}
}

func TestBoundaryBodyLimit(t *testing.T) {
	limits := Limits{MaxBodyBytes: 4}
	before := "PUT /public HTTP/1.1\r\nHost: api.local\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"2\r\n00\r\n2\r\n01\r\n0\r\n\r\n"
	after := "PUT /public HTTP/1.1\r\nHost: api.local\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"2\r\n00\r\n2\r\n01\r\n2\r\n02\r\n0\r\n\r\n"
	c := NewConn(Frontend, limits, []byte(before))
	req, err := c.Next()
	if err != nil {
		t.Fatalf("boundary-before should parse: %v", err)
	}
	if string(req.Body) != "0001" {
		t.Fatalf("boundary-before body = %q, want %q", req.Body, "0001")
	}
	c = NewConn(Frontend, limits, []byte(after))
	if _, err := c.Next(); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("boundary-after err = %v, want ErrBodyTooLarge", err)
	}
}

func TestDuplicateContentLength(t *testing.T) {
	stream := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 2\r\n\r\nabcde"
	fe := NewConn(Frontend, Limits{}, []byte(stream))
	if req, err := fe.Next(); err != nil || len(req.Body) != 5 {
		t.Fatalf("frontend first-CL: body=%d err=%v, want 5", len(req.Body), err)
	}
	be := NewConn(Backend, Limits{}, []byte(stream))
	req, err := be.Next()
	if err != nil || len(req.Body) != 2 {
		t.Fatalf("backend last-CL: body=%d err=%v, want 2", len(req.Body), err)
	}
	if len(be.Pending()) != 3 {
		t.Fatalf("backend leftover = %d, want 3", len(be.Pending()))
	}
}
