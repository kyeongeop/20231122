// Package resource models bounded processing budgets and the deterministic
// degradation ladder used when memory or token budgets are exhausted. The
// ladder has four levels; every transition is recorded as evidence.
package resource

import (
	"fmt"
	"runtime"
)

// Degradation levels, low to high pressure.
const (
	LevelNormal  = 0 // full processing, every frame kept
	LevelReduced = 1 // skip payload retention, keep headers + checksums
	LevelSampled = 2 // process every Nth frame, checkpoint more often
	LevelBailout = 3 // stop at the next checkpoint and persist partial state
)

// Budget is the work allowance for one run.
type Budget struct {
	MaxTokens int64
	MaxBytes  int64
	// SampleEvery is used at LevelSampled: only frames with
	// frameIndex % SampleEvery == 0 are processed.
	SampleEvery int64
}

// DefaultBudget is generous on purpose; tests tighten it to force each
// degradation level deterministically.
func DefaultBudget() Budget {
	return Budget{MaxTokens: 1_000_000, MaxBytes: 256 << 20, SampleEvery: 4}
}

// Monitor tracks consumption and decides the current level.
type Monitor struct {
	budget      Budget
	tokens      int64
	bytes       int64
	level       int
	transitions []Transition
	emitted     int
}

// Transition is one level change with a reason.
type Transition struct {
	From   int
	To     int
	Reason string
	Detail string
}

// NewMonitor builds a monitor at LevelNormal.
func NewMonitor(b Budget) *Monitor {
	if b.SampleEvery <= 0 {
		b.SampleEvery = 4
	}
	return &Monitor{budget: b, level: LevelNormal}
}

// Level reports the current degradation level.
func (m *Monitor) Level() int { return m.level }

// TokensUsed / BytesUsed expose consumption.
func (m *Monitor) TokensUsed() int64 { return m.tokens }
func (m *Monitor) BytesUsed() int64  { return m.bytes }

// Transitions returns a copy of all level changes.
func (m *Monitor) Transitions() []Transition {
	out := make([]Transition, len(m.transitions))
	copy(out, m.transitions)
	return out
}

// NewTransitions returns level changes observed since the previous call and
// advances the emission cursor, so callers never double-record evidence.
func (m *Monitor) NewTransitions() []Transition {
	out := append([]Transition(nil), m.transitions[m.emitted:]...)
	m.emitted = len(m.transitions)
	return out
}

func (m *Monitor) move(to int, reason string, detail string) {
	if to == m.level {
		return
	}
	m.transitions = append(m.transitions, Transition{From: m.level, To: to, Reason: reason, Detail: detail})
	m.level = to
}

// Consume accounts for work and recomputes the level. It never blocks or
// panics: pressure is expressed through the ladder so the pipeline can keep
// making checkpoints instead of crashing.
func (m *Monitor) Consume(tokens, payloadBytes int64) {
	m.tokens += tokens
	m.bytes += payloadBytes

	tokenRatio := safeRatio(m.tokens, m.budget.MaxTokens)
	byteRatio := safeRatio(m.bytes, m.budget.MaxBytes)
	pressure := tokenRatio
	if byteRatio > pressure {
		pressure = byteRatio
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	heapRatio := safeRatio(int64(ms.HeapAlloc), int64(ms.Sys))
	if heapRatio > pressure {
		pressure = heapRatio
	}

	switch {
	case pressure >= 1.0:
		m.move(LevelBailout, "budget_exhausted",
			fmt.Sprintf("tokens=%d/%d bytes=%d/%d heap=%.2f", m.tokens, m.budget.MaxTokens, m.bytes, m.budget.MaxBytes, heapRatio))
	case pressure >= 0.75:
		m.move(LevelSampled, "pressure_high",
			fmt.Sprintf("pressure=%.2f sampling every %d frames", pressure, m.budget.SampleEvery))
	case pressure >= 0.5:
		m.move(LevelReduced, "pressure_medium",
			fmt.Sprintf("pressure=%.2f dropping payload retention", pressure))
	default:
		m.move(LevelNormal, "pressure_released", fmt.Sprintf("pressure=%.2f", pressure))
	}
}

// ShouldProcess applies the sampling rule at LevelSampled.
func (m *Monitor) ShouldProcess(frameIndex int64) bool {
	if m.level != LevelSampled {
		return true
	}
	return frameIndex%m.budget.SampleEvery == 0
}

// MustBailout reports whether processing should stop at the next checkpoint.
func (m *Monitor) MustBailout() bool { return m.level == LevelBailout }

// Replay restores consumption and the degradation level after a process
// restart. It sets the emission cursor to the end so historical transitions
// already persisted as evidence are not recorded again.
func (m *Monitor) Replay(tokens, bytes int64, level int) {
	m.tokens = tokens
	m.bytes = bytes
	if level >= LevelNormal && level <= LevelBailout {
		m.level = level
	}
	m.emitted = len(m.transitions)
}

func safeRatio(used, max int64) float64 {
	if max <= 0 {
		return 0
	}
	return float64(used) / float64(max)
}
