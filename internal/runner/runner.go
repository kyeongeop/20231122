package runner

import (
	"encoding/json"
	"fmt"
	"os"

	"oauthreview/internal/callback"
	"oauthreview/internal/evidence"
)

// Envelope 是语料库用例的磁盘封装，保留原始 Content-Type 与来源标签。
type Envelope struct {
	CaseID      string `json:"case_id"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
	Source      string `json:"source"`
	// Expect 允许语料声明预期结论，用于自动核对。
	Expect string `json:"expect"`
}

// LoadEnvelope 读取单个用例文件。
func LoadEnvelope(path string) (*Envelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("decode envelope %s: %w", path, err)
	}
	if e.CaseID == "" {
		return nil, fmt.Errorf("envelope %s missing case_id", path)
	}
	if e.Source == "" {
		e.Source = "curated"
	}
	return &e, nil
}

// NewPolicy 构造演示/复核环境下的固定可信策略。
func NewPolicy() *callback.Policy {
	p := callback.DefaultPolicy()
	p.AllowedRedirectURIs["https://app.example.com/oauth/callback"] = struct{}{}
	p.AllowedRedirectURIs["https://app.example.com/oauth/callback?tab=secure"] = struct{}{}
	p.AllowedIssuers["https://idp.example.com/"] = struct{}{}
	p.StateBinding["state-ok-legacy"] = callback.StateRecord{
		SessionID: "sess-1001", RedirectURI: "https://app.example.com/oauth/callback",
	}
	p.StateBinding["state-ok-v2"] = callback.StateRecord{
		SessionID: "sess-1002", RedirectURI: "https://app.example.com/oauth/callback",
	}
	p.StateBinding["state-cancel"] = callback.StateRecord{
		SessionID: "sess-1003", Cancelled: true,
		RedirectURI: "https://app.example.com/oauth/callback",
	}
	p.StateBinding["state-consumed"] = callback.StateRecord{
		SessionID: "sess-1004", Consumed: true,
		RedirectURI: "https://app.example.com/oauth/callback",
	}
	p.StateBinding["state-other-uri"] = callback.StateRecord{
		SessionID: "sess-1005", RedirectURI: "https://app.example.com/other",
	}
	return p
}

// Replay 执行单条用例：解析 -> 校验 -> 证据入库，返回自动结论。
func Replay(store *evidence.Store, e *Envelope) (*callback.Outcome, error) {
	body := []byte(e.Body)
	cb, err := callback.Parse(e.ContentType, body)
	if err != nil {
		if perr := store.RecordParseFailure(e.CaseID, e.ContentType, e.Source, body, err); perr != nil {
			return nil, perr
		}
		return nil, fmt.Errorf("parse failed (evidence retained): %w", err)
	}
	v := callback.NewValidator(NewPolicy())
	out := v.Validate(e.CaseID, cb)
	out.RawRetained = true
	if err := store.RecordCase(e.CaseID, e.ContentType, e.Source, cb, out); err != nil {
		return nil, err
	}
	return out, nil
}
