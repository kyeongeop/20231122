package tlscfg

// Snapshot v1: baseline parser. Defaults: min TLS1.0, max TLS1.3,
// ALPN defaults to ["http/1.1"], session tickets default on.

// ParseV1 is the frozen v1 snapshot of the TLS config parser.
func ParseV1(raw []byte) Outcome {
	r, err := decodeRecord(raw)
	if err != nil {
		return Outcome{Status: "error", Err: "v1: " + err.Error()}
	}
	c := &Config{
		MinVersion:     r.MinVersion,
		MaxVersion:     r.MaxVersion,
		CipherSuites:   append([]string(nil), r.CipherSuites...),
		ALPN:           append([]string(nil), r.ALPN...),
		SessionTickets: true,
	}
	if c.MinVersion == "" {
		c.MinVersion = "TLS1.0"
	}
	if c.MaxVersion == "" {
		c.MaxVersion = "TLS1.3"
	}
	if len(c.CipherSuites) == 0 {
		c.CipherSuites = []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
	}
	if len(c.ALPN) == 0 {
		c.ALPN = []string{"http/1.1"}
	}
	if r.SessionTickets != nil {
		c.SessionTickets = *r.SessionTickets
	}
	if err := validateCommon(r, c); err != nil {
		return Outcome{Status: "error", Err: "v1: " + err.Error()}
	}
	return Outcome{Status: "ok", Config: c}
}
