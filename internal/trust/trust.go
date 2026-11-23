// Package trust implements the reverse-proxy trust boundary decision:
// given the TCP peer address and the X-Forwarded-For header, decide
// whether the forwarded header may be trusted and whether the request
// is allowed. Every decision records which rule fired and where.
package trust

import (
	"fmt"
	"net/netip"
	"runtime"
	"strings"
)

const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

// Decision is the outcome of evaluating the trust boundary for one request.
type Decision struct {
	RemoteAddr string `json:"remote_addr"`
	XFF        string `json:"xff"`
	Trusted    bool   `json:"trusted"`
	ClientIP   string `json:"client_ip"`
	Action     string `json:"action"`
	Rule       string `json:"rule"`
	Location   string `json:"location"` // file:line where the rule fired
	Reason     string `json:"reason"`
}

// Boundary holds the trust policy: which peers are trusted proxies and
// which client networks are forbidden.
type Boundary struct {
	TrustedProxies []netip.Prefix
	BlockedClients []netip.Prefix
}

// DefaultBoundary returns the policy used by the audit pipeline:
// two trusted proxy ranges, and a blocklist of internal-only networks
// that must never appear as an external client identity.
func DefaultBoundary() *Boundary {
	return &Boundary{
		TrustedProxies: mustPrefixes("10.1.0.0/16", "192.168.7.0/24"),
		BlockedClients: mustPrefixes("10.0.0.0/8", "169.254.0.0/16"),
	}
}

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

func inAny(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// here captures the caller's source location as file:line.
func here(skip int) string {
	_, file, line, ok := runtime.Caller(skip + 1)
	if !ok {
		return "unknown"
	}
	if i := strings.LastIndex(file, "/"); i >= 0 {
		file = file[i+1:]
	}
	return fmt.Sprintf("%s:%d", file, line)
}

// Decide evaluates one request against the trust boundary.
//
// Rules, in evaluation order:
//
//	R1  peer is a trusted proxy and XFF parses -> client identity from XFF
//	R2  peer is a trusted proxy but XFF is malformed -> deny (fail closed)
//	R3  peer is untrusted and XFF is present -> spoof attempt, deny
//	R4  peer is untrusted, no XFF -> client identity is the peer itself
//	R5  resolved client is on the blocklist -> deny
func (b *Boundary) Decide(remoteAddr, xff string) Decision {
	d := Decision{RemoteAddr: remoteAddr, XFF: xff}

	peer, err := netip.ParseAddr(strings.TrimSpace(remoteAddr))
	if err != nil {
		d.Action, d.Rule, d.Location = ActionDeny, "R0-bad-peer", here(0)
		d.Reason = "unparseable peer address"
		return d
	}

	trusted := inAny(peer, b.TrustedProxies)
	d.Trusted = trusted

	if trusted {
		if strings.TrimSpace(xff) == "" {
			d.ClientIP = peer.String()
			d.Action, d.Rule, d.Location = ActionAllow, "R1-trusted-no-xff", here(0)
			d.Reason = "trusted proxy without XFF; peer is the client"
		} else {
			client, perr := parseLeftmostXFF(xff)
			if perr != nil {
				d.Action, d.Rule, d.Location = ActionDeny, "R2-malformed-xff", here(0)
				d.Reason = "trusted proxy sent malformed XFF: " + perr.Error()
				return d
			}
			d.ClientIP = client.String()
			d.Action, d.Rule, d.Location = ActionAllow, "R1-trusted-proxy", here(0)
			d.Reason = "client identity taken from XFF via trusted proxy"
		}
	} else if strings.TrimSpace(xff) != "" {
		d.ClientIP = peer.String()
		d.Action, d.Rule, d.Location = ActionDeny, "R3-xff-spoof", here(0)
		d.Reason = "untrusted peer presented X-Forwarded-For; header ignored, request denied"
		return d
	} else {
		d.ClientIP = peer.String()
		d.Action, d.Rule, d.Location = ActionAllow, "R4-direct-client", here(0)
		d.Reason = "direct client, no forwarded header"
	}

	client, cerr := netip.ParseAddr(d.ClientIP)
	if cerr == nil && inAny(client, b.BlockedClients) {
		d.Action, d.Rule, d.Location = ActionDeny, "R5-blocked-client", here(0)
		d.Reason = "resolved client " + d.ClientIP + " is on the blocklist"
	}
	return d
}

// parseLeftmostXFF extracts the leftmost (original client) address.
func parseLeftmostXFF(xff string) (netip.Addr, error) {
	first, _, _ := strings.Cut(xff, ",")
	addr, err := netip.ParseAddr(strings.TrimSpace(first))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("bad address %q", strings.TrimSpace(first))
	}
	return addr, nil
}
