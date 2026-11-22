package quota

const (
	ModeFixed      = "fixed"
	ModeVulnerable = "vulnerable"

	// MaxInputBytes 是攻击输入硬上限（1 MiB + 1），与参考证据一致。
	MaxInputBytes = 1048577

	// FragmentField 是缺失片段的字段路径。
	FragmentField = "rejection_response.fragment"
)
