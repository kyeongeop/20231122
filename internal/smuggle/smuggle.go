// Package smuggle reconstructs an HTTP request-smuggling run: the client
// stream is parsed by a front-end profile, forwarded over a reused
// keep-alive connection, and re-parsed by a back-end profile. Divergence
// between the two views is reported together with permission decisions.
package smuggle

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/kyeongeop/20231122/internal/httpwire"
)

// Options bundles the extreme limits used to construct the scenarios.
type Options struct {
	Limits      httpwire.Limits
	AdminToken  string // token that authorizes /admin paths
	MaxRequests int    // cap on requests parsed per connection (0 = unlimited)
}

// DefaultOptions returns the extreme parameter set used by the scenarios.
func DefaultOptions() Options {
	return Options{
		Limits: httpwire.Limits{
			MaxRequestBytes: 1 << 20, // 1 MiB ingress cap
			MaxBodyBytes:    1024,    // tightened further by boundary scenarios
			MaxChunks:       8,
			MaxHeaders:      16,
		},
		AdminToken:  "s3cr3t-adm1n",
		MaxRequests: 8,
	}
}

// Identity is the authenticated caller derived from a request.
type Identity struct {
	Name  string
	Admin bool
}

// Decision is the permission verdict for one back-end request.
type Decision struct {
	Path     string
	Identity Identity
	Allowed  bool
	Reason   string
}

// Finding is one parsed-request record at one layer.
type Finding struct {
	Layer    string // "frontend" or "backend"
	Profile  string
	Index    int
	Status   string // "ok", "rejected", "empty", "incomplete"
	Method   string
	Path     string
	Consumed int
	Detail   string
}

// SmuggledRequest is a request the back-end served that the front-end never
// saw as a standalone request.
type SmuggledRequest struct {
	Method string
	Path   string
	SHA256 string
	Raw    []byte
}

// Reuse describes connection-reuse state after the run.
type Reuse struct {
	FrontendServed   int
	BackendServed    int
	FrontendLeftover int
	BackendLeftover  int
}

// Analysis is the full reconstruction of one scenario run.
type Analysis struct {
	Case      string
	InputSize int
	InputHash string
	Frontend  []Finding
	Backend   []Finding
	Smuggled  []SmuggledRequest
	Decisions []Decision
	Reuse     Reuse
	Desync    bool
	Notes     []string
}

// identityFrom derives the caller identity from request headers.
func identityFrom(r *httpwire.Request, opts Options) Identity {
	for _, v := range r.Get("X-Admin-Token") {
		if v == opts.AdminToken {
			return Identity{Name: "admin", Admin: true}
		}
	}
	return Identity{Name: "anonymous"}
}

// authorize applies the permission policy: /admin requires an admin identity.
func authorize(r *httpwire.Request, opts Options) Decision {
	id := identityFrom(r, opts)
	d := Decision{Path: r.Path, Identity: id}
	if strings.HasPrefix(r.Path, "/admin") {
		if id.Admin {
			d.Allowed, d.Reason = true, "valid X-Admin-Token"
		} else {
			d.Allowed, d.Reason = false, "missing or invalid X-Admin-Token"
		}
	} else {
		d.Allowed, d.Reason = true, "public path"
	}
	return d
}

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
