package ext

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Plugin models the "unknown extension" under review. Its configuration is
// opaque to the pipeline; the pipeline only records snapshots of its state
// before/after each reproduction run so reviewers can diff behavior.
type Plugin struct {
	Version   string
	Policy    map[string]string
	Decisions []string
}

// NewV1 returns the legacy extension behavior: it allows the token's alg
// header to drive verification and accepts the legacy "crit" passthrough.
func NewV1() *Plugin {
	return &Plugin{
		Version: "ext-v1",
		Policy: map[string]string{
			"alg_source":  "token-header",
			"crit":        "passthrough",
			"key_binding": "loose",
		},
	}
}

// NewV2 returns the current extension behavior: pinned algorithm, strict
// critical-extension handling, and key-type binding.
func NewV2() *Plugin {
	return &Plugin{
		Version: "ext-v2",
		Policy: map[string]string{
			"alg_source":  "server-pinned",
			"crit":        "strict",
			"key_binding": "strict",
		},
	}
}

// Snapshot captures the extension state at a point in time. Two snapshots
// (v1 and v2) are recorded per run and stored as evidence.
type Snapshot struct {
	Version   string            `json:"version"`
	Policy    map[string]string `json:"policy"`
	Decisions []string          `json:"decisions"`
	Digest    string            `json:"digest"`
	TakenAt   time.Time         `json:"taken_at"`
}

// Snap records the current plugin state.
func (p *Plugin) Snap() Snapshot {
	s := Snapshot{
		Version:   p.Version,
		Policy:    p.Policy,
		Decisions: append([]string(nil), p.Decisions...),
		TakenAt:   time.Now().UTC(),
	}
	b, _ := json.Marshal(struct {
		V string            `json:"v"`
		P map[string]string `json:"p"`
	}{p.Version, p.Policy})
	sum := sha256.Sum256(b)
	s.Digest = hex.EncodeToString(sum[:])
	return s
}

// Note records a decision the extension made while handling a token.
func (p *Plugin) Note(format string, args ...any) {
	p.Decisions = append(p.Decisions, fmt.Sprintf(format, args...))
}
