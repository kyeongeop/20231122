package callback

import "time"

// Format 表示回调格式。
type Format string

const (
	FormatLegacy  Format = "legacy" // 旧格式：application/x-www-form-urlencoded
	FormatV2      Format = "v2"     // 新格式：application/json (RFC 风格)
	FormatUnknown Format = "unknown"
)

// Stage 标识校验流水线中的触发位置。
type Stage string

const (
	StageParse        Stage = "parse"
	StageState        Stage = "state_binding"
	StageRedirectURI  Stage = "redirect_uri"
	StageCode         Stage = "authorization_code"
	StageIssuer       Stage = "issuer"
	StageResponseMode Stage = "response_mode"
	StageSignature    Stage = "signature"
	StagePermission   Stage = "permission"
	StageCancellation Stage = "cancellation"
)

// Verdict 是机器可复核的自动结论。
type Verdict string

const (
	VerdictAllow         Verdict = "ALLOW"
	VerdictDeny          Verdict = "DENY"
	VerdictCancelled     Verdict = "CANCELLED"
	VerdictIndeterminate Verdict = "INDETERMINATE"
)

// Decision 记录一次权限判断及其依据。
type Decision struct {
	Verdict     Verdict
	Stage       Stage
	ReasonCode  string
	ReasonHuman string
}

// Callback 是与格式无关的规范化回调视图。
type Callback struct {
	Format       Format
	Raw          []byte
	ContentType  string
	Code         string
	State        string
	Error        string
	ErrorDesc    string
	RedirectURI  string
	Issuer       string
	ResponseMode string
	TokenHash    string
	Fields       map[string]string
	ParsedAt     time.Time
}

// Event 是流水线中每个检查点留下的结构化日志事件。
type Event struct {
	Seq        int       `json:"seq"`
	CaseID     string    `json:"case_id"`
	Stage      Stage     `json:"stage"`
	Check      string    `json:"check"`
	Passed     bool      `json:"passed"`
	Verdict    Verdict   `json:"verdict"`
	ReasonCode string    `json:"reason_code,omitempty"`
	Detail     string    `json:"detail,omitempty"`
	Evidence   string    `json:"evidence,omitempty"` // sha256 指针，指向保留的原始证据
	At         time.Time `json:"at"`
}

// Outcome 是一次完整校验的可复核结果。
type Outcome struct {
	CaseID        string
	Format        Format
	TriggerPoint  Stage
	Decision      Decision
	PermissionLog string // 权限判断规则名，例如 rule.redirect_uri.exact_match
	Events        []Event
	InputHash     string
	RawRetained   bool
}
