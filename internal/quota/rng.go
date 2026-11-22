package quota

import "math/rand/v2"

// seededRNG 包装 rand/v2 的确定性 PCG 源，保证并发调度可复现。
type seededRNG struct {
	src *rand.Rand
}

func newSeededRNG(seed int64) *seededRNG {
	// uint64 种子由 int64 扩展，保持跨平台一致。
	return &seededRNG{src: rand.New(rand.NewPCG(uint64(seed), uint64(seed)^0x9e3779b97f4a7c15))}
}

func (r *seededRNG) int63n(n int64) int64 {
	return r.src.Int64N(n)
}
