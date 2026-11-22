package model

import "testing"

func TestEventValidation(t *testing.T) {
	good := Event{
		Sequence: 1, DeviceID: "a", Code: "C", UserID: "u",
		Kind: KindIssue, ObservedAt: 1,
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
	if good.ReferenceAt() != 1 {
		t.Fatalf("reference time without offset = %d", good.ReferenceAt())
	}
	withOffset := good
	withOffset.ObservedAt = 100
	withOffset.OffsetMs = 50
	if withOffset.ReferenceAt() != 150 {
		t.Fatalf("reference time = %d, want 150", withOffset.ReferenceAt())
	}

	mutators := map[string]func(*Event){
		"negative sequence":  func(e *Event) { e.Sequence = -1 },
		"empty device":       func(e *Event) { e.DeviceID = "" },
		"empty code":         func(e *Event) { e.Code = "" },
		"empty user":         func(e *Event) { e.UserID = "" },
		"unknown kind":       func(e *Event) { e.Kind = "nope" },
		"negative timestamp": func(e *Event) { e.ObservedAt = -1 },
	}
	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			bad := good
			mutate(&bad)
			if err := bad.Validate(); err == nil {
				t.Fatalf("%s: expected validation error", name)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	mutators := map[string]func(*Config){
		"window":     func(c *Config) { c.ValidityWindowMs = 0 },
		"threshold":  func(c *Config) { c.ClockGapThresholdMs = 0 },
		"max events": func(c *Config) { c.MaxEvents = -1 },
		"max issues": func(c *Config) { c.MaxTrackedIssues = 0 },
		"batch":      func(c *Config) { c.BatchSize = 0 },
	}
	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("%s: expected validation error", name)
			}
		})
	}
}

func TestIssueKey(t *testing.T) {
	if IssueKey("C", "u") == IssueKey("C", "v") {
		t.Fatal("distinct users collapsed into one key")
	}
	if IssueKey("C", "u") != IssueKey("C", "u") {
		t.Fatal("identical inputs produced different keys")
	}
}
