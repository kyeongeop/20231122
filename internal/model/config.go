package model

import "errors"

// Config controls detector semantics and resource budgets.
type Config struct {
	// ValidityWindowMs is how long an issued code remains consumable.
	ValidityWindowMs int64 `json:"validity_window_ms"`
	// ClockGapThresholdMs flags a reference-clock jump between consecutive
	// records of the same device when the jump exceeds this value.
	ClockGapThresholdMs int64 `json:"clock_gap_threshold_ms"`
	// MaxEvents is the event-processing budget per resume segment. Zero means
	// unlimited. Exhaustion pauses the pipeline instead of dropping work.
	MaxEvents int `json:"max_events"`
	// MaxTrackedIssues bounds in-memory issue state. When the bound is reached
	// the pipeline degrades: only durable SQLite state is used and the event is
	// re-processed on resume, never silently skipped.
	MaxTrackedIssues int `json:"max_tracked_issues"`
	// BatchSize is the number of events committed per SQLite transaction.
	BatchSize int `json:"batch_size"`
}

// DefaultConfig returns conservative production-style defaults.
func DefaultConfig() Config {
	return Config{
		ValidityWindowMs:    5 * 60 * 1000,
		ClockGapThresholdMs: 30 * 1000,
		MaxEvents:           0,
		MaxTrackedIssues:    100_000,
		BatchSize:           256,
	}
}

// Validate checks configuration sanity.
func (c Config) Validate() error {
	if c.ValidityWindowMs <= 0 {
		return errors.New("validity_window_ms must be positive")
	}
	if c.ClockGapThresholdMs <= 0 {
		return errors.New("clock_gap_threshold_ms must be positive")
	}
	if c.MaxEvents < 0 {
		return errors.New("max_events must be non-negative")
	}
	if c.MaxTrackedIssues <= 0 {
		return errors.New("max_tracked_issues must be positive")
	}
	if c.BatchSize <= 0 {
		return errors.New("batch_size must be positive")
	}
	return nil
}

// PauseReason explains why a segment ended early.
const (
	PauseBudgetExhausted = "budget_exhausted" // event budget for the segment ran out
	PauseMemoryPressure  = "memory_pressure"  // issue-state limit hit; degrade to durable path
	PauseFaultInjected   = "fault_injected"   // deterministic test fault
	PauseCompleted       = "completed"        // whole input stream consumed
)
