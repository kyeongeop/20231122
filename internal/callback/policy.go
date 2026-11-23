package callback

import "net/url"

// Policy 承载回调校验依赖的可信配置。
type Policy struct {
	// AllowedRedirectURIs 是注册到授权服务器的精确 redirect_uri 白名单。
	AllowedRedirectURIs map[string]struct{}
	// AllowedIssuers 是新格式回调允许的 iss 白名单。
	AllowedIssuers map[string]struct{}
	// AllowedResponseModes 限制 response_mode，防止 fragment/form 混淆。
	AllowedResponseModes map[string]struct{}
	// StateBinding 把 state 值映射到服务端会话绑定记录。
	StateBinding map[string]StateRecord
	// MaxCodeLength 限制授权码长度，吸收超长/畸形输入。
	MaxCodeLength int
}

// StateRecord 是服务端保存的 state 绑定证据。
type StateRecord struct {
	SessionID   string
	Consumed    bool
	Cancelled   bool
	RedirectURI string
}

// DefaultPolicy 构造带安全默认值的策略。
func DefaultPolicy() *Policy {
	return &Policy{
		AllowedRedirectURIs:  map[string]struct{}{},
		AllowedIssuers:       map[string]struct{}{},
		AllowedResponseModes: map[string]struct{}{"query": {}, "form_post": {}},
		StateBinding:         map[string]StateRecord{},
		MaxCodeLength:        256,
	}
}

func (p *Policy) redirectURIAllowed(raw string) (bool, string) {
	if raw == "" {
		return false, "redirect_uri.missing"
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return false, "redirect_uri.unparseable"
	}
	if parsed.Scheme != "https" && parsed.Hostname() != "localhost" {
		return false, "redirect_uri.insecure_scheme"
	}
	if _, ok := p.AllowedRedirectURIs[raw]; !ok {
		return false, "redirect_uri.not_in_allowlist"
	}
	return true, "redirect_uri.exact_match"
}

func (p *Policy) issuerAllowed(iss string) (bool, string) {
	if iss == "" {
		return false, "issuer.missing"
	}
	if _, ok := p.AllowedIssuers[iss]; !ok {
		return false, "issuer.not_in_allowlist"
	}
	return true, "issuer.allowlist_match"
}
