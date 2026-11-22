package model

// Verdict 是一条来源检查记录的最终结论。
type Verdict string

const (
	// VerdictTrusted 来源可信且系统调用在白名单内。
	VerdictTrusted Verdict = "trusted"
	// VerdictRejected 来源不可信或系统调用不在白名单内。
	VerdictRejected Verdict = "rejected"
	// VerdictUndecidable 证据不足，无法判断的边界情况。
	VerdictUndecidable Verdict = "undecidable"
	// VerdictError 处理过程中发生异常，已隔离并继续后续记录。
	VerdictError Verdict = "error"
)

// Source 是受信任的白名单发布源登记项。
type Source struct {
	ID     string
	Name   string
	PubKey string // 期望的签名公钥指纹（SHA-256 截断展示）
}

// Syscall 是白名单中的单个系统调用条目。
type Syscall struct {
	Number int    // 系统调用号
	Name   string // 系统调用名
	Risk   string // 风险等级：low / medium / high
}

// Snapshot 是一个版本的白名单快照（不可变，带版本与内容指纹）。
type Snapshot struct {
	Version     string
	SourceID    string
	Signature   string // 快照自带的签名字段
	IssuedAt    string
	Syscalls    []Syscall
	Fingerprint string // 内容规范化后 SHA-256，由 store 层计算填充
}

// EvidenceStep 记录处理流水线中的一个可回溯步骤。
type EvidenceStep struct {
	Seq    int    `json:"seq"`
	Stage  string `json:"stage"`
	Detail string `json:"detail"`
	Input  string `json:"input"`  // 该步骤看到的原始输入片段（截断保留）
	Output string `json:"output"` // 该步骤产出
}

// Record 是一条待检查的“系统调用白名单来源”输入。
type Record struct {
	ID         string `json:"id"`
	Raw        string `json:"raw"` // 原始输入（信封原文，逐字节保留）
	SourceID   string `json:"source_id"`
	Signature  string `json:"signature"`
	Version    string `json:"version"` // 声明依据的白名单版本
	SyscallNo  int    `json:"syscall_no"`
	Truncated  bool   `json:"truncated"` // 输入是否在传输中被截断
	ParseError string `json:"parse_error,omitempty"`
}

// Finding 是一条记录检查后完整结论，含证据链。
type Finding struct {
	RecordID        string
	Verdict         Verdict
	Reason          string
	Matched         *Syscall // 命中的白名单条目（未命中为 nil）
	SnapshotVersion string
	Steps           []EvidenceStep
	Evidence        map[string]string // 关键证据：raw 哈希、截断长度、签名比对等
}
