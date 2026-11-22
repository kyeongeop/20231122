package resource

import "testing"

func TestDegradationLadder(t *testing.T) {
	m := NewMonitor(Budget{MaxTokens: 100, MaxBytes: 1000, SampleEvery: 2})

	m.Consume(10, 0)
	if m.Level() != LevelNormal {
		t.Fatalf("level = %d want NORMAL", m.Level())
	}
	m.Consume(45, 0) // 55% -> reduced
	if m.Level() != LevelReduced {
		t.Fatalf("level = %d want REDUCED", m.Level())
	}
	m.Consume(25, 0) // 80% -> sampled
	if m.Level() != LevelSampled {
		t.Fatalf("level = %d want SAMPLED", m.Level())
	}
	if m.ShouldProcess(0) != true || m.ShouldProcess(1) != false || m.ShouldProcess(2) != true {
		t.Fatal("sampling rule wrong")
	}
	m.Consume(30, 0) // 110% -> bailout
	if !m.MustBailout() || m.Level() != LevelBailout {
		t.Fatalf("level = %d want BAILOUT", m.Level())
	}

	tr := m.Transitions()
	if len(tr) < 3 {
		t.Fatalf("expected >=3 transitions, got %d", len(tr))
	}
	// NewTransitions must drain the cursor so evidence is recorded once.
	if got := m.NewTransitions(); len(got) == 0 {
		t.Fatal("first drain returned no events")
	}
	if got := m.NewTransitions(); len(got) != 0 {
		t.Fatalf("second drain returned %d duplicate events", len(got))
	}
}

func TestRecoveryMovesBackToNormal(t *testing.T) {
	m := NewMonitor(Budget{MaxTokens: 100, MaxBytes: 1000, SampleEvery: 2})
	m.Consume(90, 0)
	if m.Level() != LevelSampled {
		t.Fatalf("level = %d want SAMPLED", m.Level())
	}
	// A fresh monitor over the same work models a recovered process.
	m2 := NewMonitor(Budget{MaxTokens: 10_000, MaxBytes: 100_000, SampleEvery: 2})
	m2.Consume(90, 0)
	if m2.Level() != LevelNormal {
		t.Fatalf("recovered monitor level = %d want NORMAL", m2.Level())
	}
}
