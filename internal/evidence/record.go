package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"quotabypass/internal/model"
)

// recordView 固定参与哈希的字段顺序，与 Record 的 JSON 顺序一致。
type recordView struct {
	Ordinal     int                 `json:"ordinal"`
	RunID       string              `json:"run_id"`
	Scenario    string              `json:"scenario"`
	Mode        string              `json:"mode"`
	CreatedAt   string              `json:"created_at"`
	AttackInput model.AttackInput   `json:"attack_input"`
	Input       model.InputEvidence `json:"input"`
	Permission  model.Permission    `json:"permission"`
	Summary     model.Summary       `json:"summary"`
	Attempts    []model.Attempt     `json:"attempts"`
	Logs        []model.LogEntry    `json:"logs"`
}

// canonicalRecord 返回排除 record_sha256 的紧凑规范化 JSON。
func canonicalRecord(rec model.Record) ([]byte, error) {
	v := recordView{
		Ordinal: rec.Ordinal, RunID: rec.RunID, Scenario: rec.Scenario,
		Mode: rec.Mode, CreatedAt: rec.CreatedAt, AttackInput: rec.AttackInput,
		Input: rec.Input, Permission: rec.Permission, Summary: rec.Summary,
		Attempts: rec.Attempts, Logs: rec.Logs,
	}
	return json.Marshal(v)
}

// FingerprintRecord 计算记录的 SHA-256 指纹（紧凑 JSON，无多余空白）。
func FingerprintRecord(rec model.Record) string {
	raw, err := canonicalRecord(rec)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// VerifyRecord 重新计算指纹并与记录携带值比对。
func VerifyRecord(rec model.Record) error {
	got := FingerprintRecord(rec)
	if got != rec.RecordSHA256 {
		return ErrHashMismatch
	}
	return nil
}
