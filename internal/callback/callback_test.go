package callback

import "testing"

func TestParseLegacyAndV2(t *testing.T) {
	legacy := []byte("code=abc&state=st&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb")
	cb, err := Parse("application/x-www-form-urlencoded", legacy)
	if err != nil || cb.Format != FormatLegacy {
		t.Fatalf("legacy parse: %v format=%v", err, cb.Format)
	}
	if cb.Code != "abc" || cb.RedirectURI != "https://app.example.com/cb" {
		t.Fatalf("legacy field mapping wrong: %+v", cb)
	}

	v2 := []byte(`{"code":"abc","state":"st","iss":"https://idp.example.com/","response_mode":"form_post","token_hash":"h"}`)
	cb2, err := Parse("application/json", v2)
	if err != nil || cb2.Format != FormatV2 {
		t.Fatalf("v2 parse: %v format=%v", err, cb2.Format)
	}
	if cb2.Issuer != "https://idp.example.com/" || cb2.TokenHash != "h" {
		t.Fatalf("v2 field mapping wrong: %+v", cb2)
	}

	// Content-Type 缺失但内容明显是 JSON 时，仍按新格式处理。
	cb3, err := Parse("", v2)
	if err != nil || cb3.Format != FormatV2 {
		t.Fatalf("json sniff: %v format=%v", err, cb3.Format)
	}
}

func TestLegacyAliases(t *testing.T) {
	cb, err := Parse("application/x-www-form-urlencoded",
		[]byte("code=x&state=s&redirect_url=https%3A%2F%2Fx.test%2Fcb&resp_mode=query"))
	if err != nil {
		t.Fatal(err)
	}
	if cb.RedirectURI != "https://x.test/cb" || cb.ResponseMode != "query" {
		t.Fatalf("alias normalization failed: %+v", cb)
	}
}

func TestCancellationShortCircuits(t *testing.T) {
	v := NewValidator(policyForTest())
	cb, _ := Parse("application/x-www-form-urlencoded",
		[]byte("error=access_denied&state=state-cancel"))
	out := v.Validate("t", cb)
	if out.Decision.Verdict != VerdictCancelled {
		t.Fatalf("want CANCELLED, got %s", out.Decision.Verdict)
	}
	if out.TriggerPoint != StageCancellation {
		t.Fatalf("trigger point wrong: %s", out.TriggerPoint)
	}
	if len(out.Events) != 2 {
		t.Fatalf("cancel evidence chain must have 2 events, got %d", len(out.Events))
	}
}

func TestDeterministicDenials(t *testing.T) {
	v := NewValidator(policyForTest())
	cases := []struct {
		name string
		body string
		ct   string
		code string
	}{
		{"open redirect", "code=x&state=state-ok-legacy&redirect_uri=https://evil.test/cb",
			"application/x-www-form-urlencoded", "redirect_uri.not_in_allowlist"},
		{"replay", "code=x&state=state-consumed&redirect_uri=https%3A%2F%2Fapp.example.com%2Foauth%2Fcallback",
			"application/x-www-form-urlencoded", "state.replayed"},
		{"duplicate", "code=x&state=state-ok-legacy&state=state-other&redirect_uri=https%3A%2F%2Fapp.example.com%2Foauth%2Fcallback",
			"application/x-www-form-urlencoded", "parse.duplicate_parameter"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cb, err := Parse(tc.ct, []byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			out := v.Validate("t", cb)
			if out.Decision.Verdict != VerdictDeny || out.Decision.ReasonCode != tc.code {
				t.Fatalf("want DENY/%s, got %s/%s", tc.code,
					out.Decision.Verdict, out.Decision.ReasonCode)
			}
		})
	}
}

func TestFuzzInputsNeverPanic(t *testing.T) {
	v := NewValidator(policyForTest())
	brace := "{"
	inputs := [][]byte{
		nil, {}, []byte(brace), []byte("%zz"), []byte("&&&"),
		[]byte("code=\x00&state=\xff"), make([]byte, 5000),
		[]byte(`{"state":["nested","array"]}`),
	}
	for _, in := range inputs {
		for _, ct := range []string{"application/json", "application/x-www-form-urlencoded"} {
			cb, err := Parse(ct, in)
			if err != nil {
				continue
			}
			out := v.Validate("fuzz", cb)
			if out.Decision.Verdict == "" {
				t.Fatal("empty verdict")
			}
		}
	}
}

func policyForTest() *Policy {
	p := DefaultPolicy()
	p.AllowedRedirectURIs["https://app.example.com/oauth/callback"] = struct{}{}
	p.AllowedIssuers["https://idp.example.com/"] = struct{}{}
	p.StateBinding["state-ok-legacy"] = StateRecord{
		SessionID: "s1", RedirectURI: "https://app.example.com/oauth/callback",
	}
	p.StateBinding["state-cancel"] = StateRecord{SessionID: "s2", Cancelled: true}
	p.StateBinding["state-consumed"] = StateRecord{
		SessionID: "s3", Consumed: true,
		RedirectURI: "https://app.example.com/oauth/callback",
	}
	return p
}
