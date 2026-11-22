package tlscfg

// Snapshot v2: refactored parser. Intended changes: min-version floor raised
// to TLS1.2 (hardening). Unintended regression: the ALPN default was dropped
// during the refactor, so records without an explicit alpn list now fail
// instead of defaulting to ["http/1.1"].

// ParseV2 is the frozen v2 snapshot of the TLS config parser.
func ParseV2(raw []byte) Outcome {
	r, err := decodeRecord(raw)
	if err != nil {
		return Outcome{Status: "error", Err: "v2: " + err.Error()}
	}
	c := &Config{
		MinVersion:     r.MinVersion,
		MaxVersion:     r.MaxVersion,
		CipherSuites:   append([]string(nil), r.CipherSuites...),
		ALPN:           append([]string(nil), r.ALPN...),
		SessionTickets: true,
	}
	if c.MinVersion == "" {
		c.MinVersion = "TLS1.2" // hardening: new floor
	}
	if versionRank(c.MinVersion) >= 0 && versionRank(c.MinVersion) < versionRank("TLS1.2") {
		return Outcome{Status: "error", Err: "v2: min_version below TLS1.2 not allowed"}
	}
	if c.MaxVersion == "" {
		c.MaxVersion = "TLS1.3"
	}
	if len(c.CipherSuites) == 0 {
		c.CipherSuites = []string{"TLS_AES_128_GCM_SHA256"}
	}
	if len(c.ALPN) == 0 {
		// REGRESSION: v1 defaulted to ["http/1.1"]; v2 rejects.
		return Outcome{Status: "error", Err: "v2: alpn must not be empty"}
	}
	if r.SessionTickets != nil {
		c.SessionTickets = *r.SessionTickets
	}
	if err := validateCommon(r, c); err != nil {
		return Outcome{Status: "error", Err: "v2: " + err.Error()}
	}
	return Outcome{Status: "ok", Config: c}
}
