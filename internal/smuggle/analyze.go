package smuggle

import (
	"errors"
	"fmt"

	"github.com/kyeongeop/20231122/internal/httpwire"
)

// parseAll drains a connection, recording one Finding per parse attempt.
func parseAll(layer string, conn *httpwire.Conn, maxRequests int) []Finding {
	var out []Finding
	for i := 0; ; i++ {
		if maxRequests > 0 && i >= maxRequests {
			out = append(out, Finding{Layer: layer, Profile: string(conn.Profile), Index: i,
				Status: "rejected", Detail: fmt.Sprintf("request count exceeds MaxRequests=%d", maxRequests)})
			break
		}
		req, err := conn.Next()
		if err != nil {
			status := "rejected"
			switch {
			case errors.Is(err, httpwire.ErrEmpty):
				status = "empty"
			case errors.Is(err, httpwire.ErrIncomplete):
				status = "incomplete"
			}
			out = append(out, Finding{Layer: layer, Profile: string(conn.Profile), Index: i,
				Status: status, Detail: err.Error()})
			break
		}
		out = append(out, Finding{Layer: layer, Profile: string(conn.Profile), Index: i,
			Status: "ok", Method: req.Method, Path: req.Path, Consumed: len(req.Raw)})
	}
	return out
}

// VictimRequest is a follow-up request fed onto the reused back-end
// connection to demonstrate TE.CL-style connection poisoning: leftover
// bytes from a desynced parse become a prefix of the next user's request.
var VictimRequest = []byte("GET /public HTTP/1.1\r\nHost: api.local\r\nX-Victim: next-user\r\n\r\n")

// Analyze runs one client stream through the front-end and back-end views.
// The front-end parses the client stream and forwards what it consumed over
// a reused keep-alive connection; the back-end re-parses that forwarded
// stream. Requests the back-end serves beyond the front-end's view are
// smuggled and get a permission decision. Leftover bytes on the back-end
// connection are tested against a victim request to detect poisoning.
func Analyze(caseName string, clientStream []byte, opts Options,
	feProfile, beProfile httpwire.Profile) *Analysis {
	a := &Analysis{Case: caseName, InputSize: len(clientStream), InputHash: hashOf(clientStream)}

	fe := httpwire.NewConn(feProfile, opts.Limits, clientStream)
	a.Frontend = parseAll("frontend", fe, opts.MaxRequests)

	// The front-end forwards the bytes it consumed, in order, on one
	// reused back-end connection.
	var forwarded []byte
	fe2 := httpwire.NewConn(feProfile, opts.Limits, clientStream)
	for {
		req, err := fe2.Next()
		if err != nil {
			break
		}
		forwarded = append(forwarded, req.Raw...)
	}

	be := httpwire.NewConn(beProfile, opts.Limits, forwarded)
	a.Backend = parseAll("backend", be, opts.MaxRequests)

	a.Reuse = Reuse{
		FrontendServed:   countOK(a.Frontend),
		BackendServed:    countOK(a.Backend),
		FrontendLeftover: len(fe.Pending()),
		BackendLeftover:  len(be.Pending()),
	}

	// Smuggled = back-end requests beyond what the front-end served.
	beOK := 0
	be2 := httpwire.NewConn(beProfile, opts.Limits, forwarded)
	for {
		req, err := be2.Next()
		if err != nil {
			break
		}
		if beOK >= a.Reuse.FrontendServed {
			a.Smuggled = append(a.Smuggled, SmuggledRequest{
				Method: req.Method, Path: req.Path, SHA256: hashOf(req.Raw), Raw: req.Raw,
			})
		}
		a.Decisions = append(a.Decisions, authorize(req, opts))
		beOK++
	}

	// Connection poisoning: leftover back-end bytes become a prefix of the
	// next request on the reused connection.
	if len(be.Pending()) > 0 && a.Reuse.BackendServed > 0 {
		be.Feed(VictimRequest)
		req, err := be.Next()
		if err != nil {
			a.Backend = append(a.Backend, Finding{Layer: "backend", Profile: string(beProfile),
				Index: a.Reuse.BackendServed, Status: "rejected",
				Detail: fmt.Sprintf("connection poisoning: victim request corrupted: %v", err)})
			a.Notes = append(a.Notes, "backend leftover poisoned the next request on the reused connection")
		} else {
			a.Backend = append(a.Backend, Finding{Layer: "backend", Profile: string(beProfile),
				Index: a.Reuse.BackendServed, Status: "ok", Method: req.Method, Path: req.Path,
				Consumed: len(req.Raw), Detail: "victim request after leftover prefix"})
			a.Decisions = append(a.Decisions, authorize(req, opts))
		}
	}

	if a.Reuse.FrontendServed != a.Reuse.BackendServed {
		a.Desync = true
	}
	if len(a.Smuggled) > 0 {
		a.Desync = true
		a.Notes = append(a.Notes, fmt.Sprintf("backend served %d request(s) the frontend never saw", len(a.Smuggled)))
	}
	for _, n := range a.Notes {
		if n == "backend leftover poisoned the next request on the reused connection" {
			a.Desync = true
		}
	}
	if a.InputSize == 0 {
		a.Notes = append(a.Notes, "empty input handled without parse attempt")
	}
	return a
}

func countOK(fs []Finding) int {
	n := 0
	for _, f := range fs {
		if f.Status == "ok" {
			n++
		}
	}
	return n
}
