package redact

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedactLocalizedSpans(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		want       string
		wantKind   string
		wantOffset int
	}{
		{
			name:       "authorization",
			input:      "upstream rejected: Authorization: Bearer abc.def.ghi123 for tenant 7",
			want:       "upstream rejected: Authorization: Bearer [REDACTED:AUTHORIZATION] for tenant 7",
			wantKind:   "AUTHORIZATION",
			wantOffset: len("upstream rejected: Authorization: Bearer "),
		},
		{
			name:       "json token",
			input:      `{"tenant":"acme","password":"hunter2","request_id":"r-9"}`,
			want:       `{"tenant":"acme","password":"[REDACTED:JSON_SECRET]","request_id":"r-9"}`,
			wantKind:   "JSON_SECRET",
			wantOffset: len(`{"tenant":"acme","password":"`),
		},
		{
			name:       "query api key",
			input:      "GET /v1/items?api_key=abc123secret&limit=10 failed",
			want:       "GET /v1/items?api_key=[REDACTED:KEY_VALUE_SECRET]&limit=10 failed",
			wantKind:   "KEY_VALUE_SECRET",
			wantOffset: len("GET /v1/items?api_key="),
		},
		{
			name:       "database uri",
			input:      "dial failed postgres://app:s3cr3t@db.internal:5432/prod",
			want:       "dial failed postgres://[REDACTED:URI_USERINFO]@db.internal:5432/prod",
			wantKind:   "URI_USERINFO",
			wantOffset: len("dial failed postgres://"),
		},
		{
			name:       "unicode prefix uses byte offsets",
			input:      "错误：password=秘密值; id=7",
			want:       "错误：password=[REDACTED:KEY_VALUE_SECRET]; id=7",
			wantKind:   "KEY_VALUE_SECRET",
			wantOffset: len("错误：password="),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact([]byte(tt.input))
			if string(got.Redacted) != tt.want {
				t.Fatalf("redacted mismatch\n got: %q\nwant: %q", got.Redacted, tt.want)
			}
			if len(got.Spans) != 1 {
				t.Fatalf("want 1 span, got %d (%v)", len(got.Spans), Summary(got.Spans))
			}
			if got.Spans[0].Kind != tt.wantKind || got.Spans[0].SourceOffset != tt.wantOffset {
				t.Fatalf("span = %+v, want kind=%s offset=%d", got.Spans[0], tt.wantKind, tt.wantOffset)
			}
			if len(got.Remaining) != 0 {
				t.Fatalf("remaining leaks: %v", Summary(got.Remaining))
			}
			if !bytes.HasPrefix(got.Redacted, []byte(tt.input[:tt.wantOffset])) {
				t.Fatalf("prefix was not preserved")
			}
		})
	}
}

func TestRedactPrivateKeyAndMultipleSecrets(t *testing.T) {
	input := "request failed\npassword=pw-123\ntoken: tok-456\n" +
		"-----BEGIN RSA PRIVATE KEY-----\nAAAA\nBBBB\n-----END RSA PRIVATE KEY-----\ntrailer"
	got := Redact([]byte(input))
	redacted := string(got.Redacted)
	for _, leaked := range []string{"pw-123", "tok-456", "AAAA", "BBBB"} {
		if strings.Contains(redacted, leaked) {
			t.Fatalf("secret %q leaked in %q", leaked, redacted)
		}
	}
	if len(got.Spans) != 3 {
		t.Fatalf("want 3 spans, got %d: %s", len(got.Spans), Summary(got.Spans))
	}
	if !strings.HasSuffix(redacted, "\ntrailer") {
		t.Fatalf("suffix not preserved: %q", redacted)
	}
}

func TestNoSensitiveDataIsByteIdentical(t *testing.T) {
	input := []byte("plain failure: timeout after 30s, code=E_TIMEOUT")
	got := Redact(input)
	if !bytes.Equal(got.Redacted, input) {
		t.Fatalf("unexpected modification: %q", got.Redacted)
	}
	if len(got.Spans) != 0 || len(got.Remaining) != 0 {
		t.Fatalf("unexpected spans: %v / %v", got.Spans, got.Remaining)
	}
}

func TestLineAndColumn(t *testing.T) {
	input := []byte("line one\npassword=seven\nlast")
	got := Redact(input)
	if len(got.Spans) != 1 {
		t.Fatalf("want one span, got %v", Summary(got.Spans))
	}
	if got.Spans[0].Line != 2 || got.Spans[0].Column != 10 {
		t.Fatalf("line/column = %d/%d, want 2/10", got.Spans[0].Line, got.Spans[0].Column)
	}
}

func TestInvalidUTF8DoesNotBreakOffsets(t *testing.T) {
	input := append([]byte{0xff, 0xfe, ' ', 'p'}, []byte("assword=abc\n")...)
	got := Redact(input)
	if len(got.Spans) != 1 {
		t.Fatalf("want one span, got %v", Summary(got.Spans))
	}
	if got.Spans[0].SourceOffset != 12 {
		t.Fatalf("offset = %d, want 12", got.Spans[0].SourceOffset)
	}
	if !bytes.HasPrefix(got.Redacted, []byte{0xff, 0xfe}) {
		t.Fatalf("invalid prefix changed")
	}
}
