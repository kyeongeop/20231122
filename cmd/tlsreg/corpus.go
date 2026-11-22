package main

// Corpus for the TLS configuration regression experiment. The last-but-one
// entry is the truncated control record: it must fail in BOTH snapshots, and
// the harness must keep processing the records after it.
func buildCorpus() []string {
	return []string{
		`{"id":"rec-001","min_version":"TLS1.2","max_version":"TLS1.3","cipher_suites":["TLS_AES_128_GCM_SHA256"],"alpn":["h2","http/1.1"],"session_tickets":true}`,
		`{"id":"rec-002","min_version":"TLS1.2","cipher_suites":["TLS_AES_256_GCM_SHA384"]}`,
		`{"id":"rec-003","min_version":"TLS1.0","max_version":"TLS1.2","alpn":["http/1.1"]}`,
		`{"id":"rec-004","min_version":"TLS1.3","cipher_suites":["TLS_AES_128_GCM_SHA256","TLS_CHACHA20_POLY1305_SHA256"],"alpn":["h2"]}`,
		`{"id":"rec-005","min_version":"TLS1.2","cipher_suites":["TLS_FAKE_CIPHER_NOT_REAL"],"alpn":["h2"]}`,
		`{"id":"rec-006","min_version":"TLS1.3","max_version":"TLS1.3","cipher_suites":["TLS_AES_256_GCM_SHA384"],"alpn":["h2"],"session_tickets":false}`,
		`{"id":"rec-007","min_version":"TLS1.3","max_version":"TLS1.2","alpn":["h2"]}`,
		`{"id":"rec-ctl-truncated","min_version":"TLS1.2","cipher_suites":["TLS_AES_128_GCM_SHA256"],"alpn":["h`,
		`{"id":"rec-009","max_version":"TLS1.3","alpn":["http/1.1"],"session_tickets":true}`,
		`{"id":"rec-010"}`,
	}
}
