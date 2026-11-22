package model

// Trigger 标识决策发生的代码位置，用于攻击输入与日志证据的对应。
type Trigger struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Function string `json:"function"`
}

// RejectionResponse 是攻击输入携带的拒绝响应模板。
type RejectionResponse struct {
	Status   int    `json:"status"`
	Fragment string `json:"fragment"`
	Body     string `json:"body"`
}

// AttackInput 是重建任务的原始输入：配额计数、并发请求与拒绝响应。
type AttackInput struct {
	TenantID           string            `json:"tenant_id"`
	QuotaCount         int               `json:"quota_count"`
	ConcurrentRequests int               `json:"concurrent_requests"`
	RejectionResponse  RejectionResponse `json:"rejection_response"`
}

// InputEvidence 保留原始输入及其哈希证据。
type InputEvidence struct {
	SHA256        string   `json:"sha256"`
	DigestScope   string   `json:"digest_scope"`
	Bytes         int      `json:"bytes"`
	Truncated     bool     `json:"truncated"`
	Raw           string   `json:"raw"`
	MissingFields []string `json:"missing_fields"`
	ParseError    string   `json:"parse_error"`
}

// Permission 记录权限判断点的结论。
type Permission struct {
	Decision   string  `json:"decision"`
	Authorized bool    `json:"authorized"`
	Reason     string  `json:"reason"`
	Policy     string  `json:"policy"`
	Trigger    Trigger `json:"trigger"`
}

// Attempt 是单个并发请求的判定尝试。
type Attempt struct {
	Ordinal    int     `json:"ordinal"`
	RequestID  string  `json:"request_id"`
	Decision   string  `json:"decision"`
	HTTPStatus int     `json:"http_status"`
	Reason     string  `json:"reason"`
	Response   string  `json:"response"`
	Trigger    Trigger `json:"trigger"`
	At         string  `json:"at"`
}

// LogEntry 是一条审计日志证据。
type LogEntry struct {
	Seq     int    `json:"seq"`
	At      string `json:"at"`
	Level   string `json:"level"`
	Event   string `json:"event"`
	Attempt int    `json:"attempt"`
	Message string `json:"message"`
}

// Summary 汇总一次重建的计数结果。
type Summary struct {
	ExpectedAllowed int  `json:"expected_allowed"`
	Allowed         int  `json:"allowed"`
	Denied          int  `json:"denied"`
	Errors          int  `json:"errors"`
	BypassDetected  bool `json:"bypass_detected"`
}

// Record 是一条可独立复核的完整重建记录。
// 字段顺序即导出与重载时保持的规范顺序。
type Record struct {
	Ordinal      int           `json:"ordinal"`
	RunID        string        `json:"run_id"`
	Scenario     string        `json:"scenario"`
	Mode         string        `json:"mode"`
	CreatedAt    string        `json:"created_at"`
	AttackInput  AttackInput   `json:"attack_input"`
	Input        InputEvidence `json:"input"`
	Permission   Permission    `json:"permission"`
	Summary      Summary       `json:"summary"`
	Attempts     []Attempt     `json:"attempts"`
	Logs         []LogEntry    `json:"logs"`
	RecordSHA256 string        `json:"record_sha256"`
}

// ExportFile 是 evidence.json 的顶层结构。
type ExportFile struct {
	Schema    string   `json:"schema"`
	Generator string   `json:"generator"`
	Records   []Record `json:"records"`
}
