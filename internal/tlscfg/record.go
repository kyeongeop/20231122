package tlscfg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Record is a single TLS configuration object as stored in the corpus.
type Record struct {
	ID             string   `json:"id"`
	MinVersion     string   `json:"min_version,omitempty"`
	MaxVersion     string   `json:"max_version,omitempty"`
	CipherSuites   []string `json:"cipher_suites,omitempty"`
	ALPN           []string `json:"alpn,omitempty"`
	SessionTickets *bool    `json:"session_tickets,omitempty"`
}

// Config is the normalized, validated output of a parser snapshot.
type Config struct {
	MinVersion     string   `json:"min_version"`
	MaxVersion     string   `json:"max_version"`
	CipherSuites   []string `json:"cipher_suites"`
	ALPN           []string `json:"alpn"`
	SessionTickets bool     `json:"session_tickets"`
}

// Outcome is what one parser snapshot produced for one raw input.
type Outcome struct {
	Status string  `json:"status"` // "ok" or "error"
	Config *Config `json:"config,omitempty"`
	Err    string  `json:"error,omitempty"`
}

var knownCiphers = map[string]bool{
	"TLS_AES_128_GCM_SHA256":                true,
	"TLS_AES_256_GCM_SHA384":                true,
	"TLS_CHACHA20_POLY1305_SHA256":          true,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": true,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": true,
}

var knownVersions = map[string]bool{
	"TLS1.0": true, "TLS1.1": true, "TLS1.2": true, "TLS1.3": true,
}

func versionRank(v string) int {
	switch v {
	case "TLS1.0":
		return 10
	case "TLS1.1":
		return 11
	case "TLS1.2":
		return 12
	case "TLS1.3":
		return 13
	}
	return -1
}

func decodeRecord(raw []byte) (*Record, error) {
	var r Record
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if r.ID == "" {
		return nil, fmt.Errorf("decode: missing id")
	}
	return &r, nil
}

func validateCommon(r *Record, c *Config) error {
	if !knownVersions[c.MinVersion] {
		return fmt.Errorf("unknown min_version %q", c.MinVersion)
	}
	if !knownVersions[c.MaxVersion] {
		return fmt.Errorf("unknown max_version %q", c.MaxVersion)
	}
	if versionRank(c.MinVersion) > versionRank(c.MaxVersion) {
		return fmt.Errorf("min_version %s above max_version %s", c.MinVersion, c.MaxVersion)
	}
	for _, cs := range c.CipherSuites {
		if !knownCiphers[cs] {
			return fmt.Errorf("unknown cipher_suite %q", cs)
		}
	}
	_ = r
	return nil
}

// Hash returns the sha256 of the raw input, used as the input fingerprint
// in the journal.
func Hash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Canonical renders an outcome deterministically so two runs can be compared
// byte-for-byte. Snapshot prefixes ("v1: "/"v2: ") are stripped from errors
// so that identical failures in both snapshots compare equal.
func (o Outcome) Canonical() string {
	if o.Status == "error" {
		err := o.Err
		if len(err) > 3 && err[0] == 'v' && err[2] == ':' {
			err = err[4:]
		}
		return "error:" + err
	}
	c := *o.Config
	suites := append([]string(nil), c.CipherSuites...)
	sort.Strings(suites)
	alpn := append([]string(nil), c.ALPN...)
	sort.Strings(alpn)
	b, _ := json.Marshal(struct {
		Min, Max string
		Suites   []string
		ALPN     []string
		Tickets  bool
	}{c.MinVersion, c.MaxVersion, suites, alpn, c.SessionTickets})
	return "ok:" + string(b)
}
