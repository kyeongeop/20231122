package quota

// 六个标准场景的原始输入，字段顺序与参考证据中的 raw 完全一致。
const (
	RawBaseline = `{"tenant_id":"tenant-blue","quota_count":4,"concurrent_requests":24,"rejection_response":{"status":429,"fragment":"quota_exceeded","body":"{\"error\":\"quota_exceeded\",\"retry_after\":1}"}}`

	RawAttackMissingFragment = `{"tenant_id":"tenant-red","quota_count":4,"concurrent_requests":24,"rejection_response":{"status":429,"body":"{\"error\":\"quota_exceeded\"}"}}`

	RawCapacityPressure = `{"tenant_id":"tenant-green","quota_count":3,"concurrent_requests":64,"rejection_response":{"status":503,"fragment":"capacity","body":"{\"error\":\"capacity\",\"retry_after\":2}"}}`
)

// ScenarioSpec 描述一个待重建场景。
type ScenarioSpec struct {
	Name string
	Mode string
	Raw  []byte
}

// DefaultScenarios 返回六个标准场景，顺序固定即导出顺序。
func DefaultScenarios() []ScenarioSpec {
	oversized := make([]byte, MaxInputBytes)
	for i := range oversized {
		oversized[i] = ' '
	}
	// 前缀复制 baseline，再以空格填充到硬上限（与参考 raw 形态一致）。
	copy(oversized, RawBaseline)

	return []ScenarioSpec{
		{Name: "baseline-complete", Mode: ModeFixed, Raw: []byte(RawBaseline)},
		{Name: "attack-missing-fragment", Mode: ModeVulnerable, Raw: []byte(RawAttackMissingFragment)},
		{Name: "control-missing-fragment", Mode: ModeFixed, Raw: []byte(RawAttackMissingFragment)},
		{Name: "capacity-pressure", Mode: ModeFixed, Raw: []byte(RawCapacityPressure)},
		{Name: "empty-input", Mode: ModeFixed, Raw: []byte{}},
		{Name: "oversized-input", Mode: ModeFixed, Raw: oversized},
	}
}
