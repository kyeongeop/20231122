package inspect

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	caseID        = "WH-2026-1122"
	demoSecret    = "whsec_demo_5f3a9c1e"
	primaryBody   = `{"id":"evt_01JQ7M4B9K","type":"invoice.paid","amount":129900,"currency":"CNY","received_at":"2026-11-22T14:31:07.903Z"}`
	snapshotABody = `{"id":"evt_01JQ7N2D1S","type":"subscription.updated","plan":"team","seats":18}`
	snapshotBBody = `{"id":"evt_01JQ7P9A4M","type":"payment.succeeded","amount":8800,"currency":"CNY"}`
	exceptionBody = `{"id":"evt_01JQ7Q8C2R","type":"refund.failed","amount":4200,"currency":"CNY"}`
)

type seedSpec struct {
	ID             string
	Kind           string
	Name           string
	Extension      string
	MediaType      string
	Version        string
	SourceLocator  string
	CapturedAt     string
	Body           string
	Headers        map[string]string
	Signature      string
	Canonicalizer  string
	VerifierSource string
	SourceLine     int
	SourceExcerpt  string
	EnforceTime    bool
	ObservedAt     time.Time
	Exception      bool
	SortOrder      int
}

func (s *Store) seed(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO cases (id, title, target, case_owner, opened_at)
		VALUES (?, ?, ?, ?, ?)`, caseID, "Webhook 签名验证", "acme/payments · billing-ingress",
		"security-trace", "2026-11-22T14:30:00Z")
	if err != nil {
		return err
	}

	specs := demoSepcs()
	for _, spec := range specs {
		if err := s.insertSeedObject(ctx, spec); err != nil {
			return fmt.Errorf("seed %s: %w", spec.ID, err)
		}
	}
	if err := s.seedFuzzRun(ctx); err != nil {
		return err
	}
	if err := s.seedTemporaryState(); err != nil {
		return err
	}
	if _, err := s.RunAll(ctx); err != nil {
		return fmt.Errorf("initial verification batch: %w", err)
	}
	return nil
}

func demoSepcs() []seedSpec {
	observed := time.Date(2026, 11, 22, 14, 31, 8, 0, time.UTC)
	boundaryObserved := time.Date(2026, 11, 22, 14, 36, 8, 0, time.UTC)
	return []seedSpec{
		{
			ID: "obj-unknown-ext", Kind: "unknown_extension", Name: "invoice.paid.whk",
			Extension: ".whk", MediaType: "application/x-unknown", Version: "raw capture",
			SourceLocator: "capture/2026-11-22T14-31-08Z/invoice.paid.whk",
			CapturedAt:    "2026-11-22T14:31:08.041Z", Body: primaryBody,
			Headers: map[string]string{
				"content-type":        "application/octet-stream",
				"x-request-id":        "req_01JQ7M4B9K8S",
				"x-webhook-signature": "t=1795357868,v1=" + demoSignature(primaryBody),
				"x-webhook-timestamp": "1795357868",
			},
			Signature:     "t=1795357868,v1=" + demoSignature(primaryBody),
			Canonicalizer: "stripe-v1", VerifierSource: "raw-capture-profile@sha256:8c4d",
			SourceLine: 1, SourceExcerpt: "// Extension is metadata. Verify the exact bytes received.",
			ObservedAt: observed, SortOrder: 1,
		},
		{
			ID: "obj-snapshot-v182", Kind: "snapshot", Name: "verify.go",
			Extension: ".go", MediaType: "text/x-go", Version: "v1.8.2",
			SourceLocator: "git://acme/payments@76ea91f/internal/webhook/verify.go",
			CapturedAt:    "2026-11-22T14:33:19Z", Body: snapshotABody,
			Headers: map[string]string{
				"content-type":        "application/json",
				"x-request-id":        "req_01JQ7N2D1S4T",
				"x-webhook-signature": "t=1795357802,v1=" + signedAt(snapshotABody, 1795357802),
				"x-webhook-timestamp": "1795357802",
			},
			Signature:     "t=1795357802,v1=" + signedAt(snapshotABody, 1795357802),
			Canonicalizer: "stripe-v1", VerifierSource: "snapshot:v1.8.2",
			SourceLine:    64,
			SourceExcerpt: "if !hmac.Equal(expected, provided) {\n\treturn ErrSignatureMismatch\n}\nreturn nil",
			ObservedAt:    observed, SortOrder: 3,
		},
		{
			ID: "obj-snapshot-v200rc1", Kind: "snapshot", Name: "verify.go",
			Extension: ".go", MediaType: "text/x-go", Version: "v2.0.0-rc1",
			SourceLocator: "git://acme/payments@c2d8f0a/internal/webhook/verify.go",
			CapturedAt:    "2026-11-22T14:33:22Z", Body: snapshotBBody,
			Headers: map[string]string{
				"content-type":        "application/json",
				"x-request-id":        "req_01JQ7P9A4M2B",
				"x-webhook-signature": "t=1795357868,v1=" + signedAt(snapshotBBody, 1795357868),
				"x-webhook-timestamp": "1795357868",
			},
			Signature:     "t=1795357868,v1=" + signedAt(snapshotBBody, 1795357868),
			Canonicalizer: "stripe-v1", VerifierSource: "snapshot:v2.0.0-rc1",
			SourceLine:    87,
			SourceExcerpt: "skew := now.Sub(time.Unix(ts, 0))\nif skew > 300*time.Second {\n\treturn ErrTimestampOutsideTolerance\n}\nreturn verifyHMAC(body, sig, secret)",
			EnforceTime:   true, ObservedAt: boundaryObserved, SortOrder: 4,
		},
		{
			ID: "obj-exception", Kind: "exception", Name: "refund.failed.whk",
			Extension: ".whk", MediaType: "application/x-unknown", Version: "raw capture",
			SourceLocator: "capture/2026-11-22T14-34-02Z/refund.failed.whk",
			CapturedAt:    "2026-11-22T14:34:02.119Z", Body: exceptionBody,
			Headers: map[string]string{
				"content-type":        "application/octet-stream",
				"x-request-id":        "req_01JQ7Q8C2R7V",
				"x-webhook-signature": "t=1795358042,v1=ghp_not_a_digest",
				"x-webhook-timestamp": "1795358042",
			},
			Signature:     "t=1795358042,v1=ghp_not_a_digest",
			Canonicalizer: "stripe-v1", VerifierSource: "raw-capture-profile@sha256:8c4d",
			SourceLine: 1, SourceExcerpt: "// Invalid signature envelopes are isolated, not retried in place.",
			ObservedAt: time.Date(2026, 11, 22, 14, 34, 2, 0, time.UTC),
			Exception:  true, SortOrder: 2,
		},
	}
}

func (s *Store) insertSeedObject(ctx context.Context, spec seedSpec) error {
	hash := sha256.Sum256([]byte(spec.Body))
	isException := 0
	if spec.Exception {
		isException = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO objects
		(id, case_id, kind, name, extension, media_type, version, source_locator,
		captured_at, size_bytes, sha256, status, is_exception, summary, sort_order)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		spec.ID, caseID, spec.Kind, spec.Name, spec.Extension, spec.MediaType, spec.Version,
		spec.SourceLocator, spec.CapturedAt, len(spec.Body), hex.EncodeToString(hash[:]),
		VerdictPending, isException, "等待复验", spec.SortOrder)
	if err != nil {
		return err
	}
	headers, err := json.Marshal(spec.Headers)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO snapshots
		(id, object_id, version, captured_at, body, headers_json, signature, signature_alg,
		canonicalizer, verifier_source, source_line, source_excerpt)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"snap-"+spec.ID, spec.ID, spec.Version, spec.CapturedAt, spec.Body, string(headers),
		spec.Signature, "HMAC-SHA256", spec.Canonicalizer, spec.VerifierSource,
		spec.SourceLine, spec.SourceExcerpt)
	return err
}

func (s *Store) seedFuzzRun(ctx context.Context) error {
	artifact := []byte("t=1795357868,v1=")
	digest := sha256.Sum256(artifact)
	_, err := s.db.ExecContext(ctx, `INSERT INTO fuzz_runs
		(id, target, engine, corpus_entries, executions, crashes, artifact_sha256,
		artifact_hex, status, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"fuzz-20261122-01", "VerifyWebhookCanonicalizer", "libFuzzer", 18, 18422, 0,
		hex.EncodeToString(digest[:]), hex.EncodeToString(artifact), "clean",
		"边界语料被保留；无崩溃。截断签名由解析阶段拒绝，不影响其余对象。",
		"2026-11-22T14:35:41Z")
	return err
}

func (s *Store) seedTemporaryState() error {
	root := filepath.Join(os.TempDir(), "webhook-provenance", "replay-01JQ7P9A4M")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	path := filepath.Join(root, "boundary-replay.log")
	if err := os.WriteFile(path, []byte("temporary replay marker\n"), 0o600); err != nil {
		return err
	}
	_, err := s.db.ExecContext(context.Background(), `INSERT OR REPLACE INTO temp_state
		(id, path, reason, bytes, created_at) VALUES (?, ?, ?, ?, ?)`,
		"tmp-replay-boundary", root, "300s 边界复验工作目录", len("temporary replay marker\n"),
		"2026-11-22T14:35:53Z")
	return err
}

func demoSignature(body string) string {
	return signedAt(body, 1795357868)
}

func signedAt(body string, timestamp int64) string {
	mac := hmac.New(sha256.New, []byte(demoSecret))
	fmt.Fprintf(mac, "%d.%s", timestamp, body)
	return hex.EncodeToString(mac.Sum(nil))
}
