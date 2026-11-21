package model

import "testing"

func TestCanonicalPath(t *testing.T) {
	cases := map[string]string{
		"/deploy//api/":        "/deploy/api",
		"/deploy/./api/../api": "/deploy/api",
		"/":                    "/",
	}
	for input, expected := range cases {
		actual, err := CanonicalPath(input)
		if err != nil {
			t.Fatalf("CanonicalPath(%q): %v", input, err)
		}
		if actual != expected {
			t.Fatalf("CanonicalPath(%q)=%q want %q", input, actual, expected)
		}
	}
	for _, input := range []string{"", "relative/path", "/bad?query=1"} {
		if _, err := CanonicalPath(input); err == nil {
			t.Fatalf("CanonicalPath(%q) unexpectedly succeeded", input)
		}
	}
}

func TestConflictThenCancel(t *testing.T) {
	engine := NewEngine()
	first := engine.Apply(Op{ID: "a", Kind: OpSubmit, Alias: "/deploy/api", Target: "/srv/blue"})
	if first.Outcome != "activated" {
		t.Fatalf("first outcome=%s", first.Outcome)
	}
	second := engine.Apply(Op{ID: "b", Kind: OpSubmit, Alias: "/deploy//api/", Target: "/srv/green/"})
	if second.Outcome != "conflict" || len(second.ConflictWith) != 1 {
		t.Fatalf("second=%+v", second)
	}
	if problems := engine.Validate(); len(problems) != 0 {
		t.Fatalf("invariant failures: %v", problems)
	}
	cancel := engine.Apply(Op{ID: "c", Kind: OpCancel, CancelID: "b"})
	if cancel.Outcome != "canceled" {
		t.Fatalf("cancel=%+v", cancel)
	}
	state := engine.Snapshot()
	if len(state.ActiveMappings) != 1 || state.ActiveMappings[0].Target != "/srv/blue" {
		t.Fatalf("active mappings=%+v", state.ActiveMappings)
	}
}

func TestOrderInvariantResolution(t *testing.T) {
	run := func(reverse bool) string {
		engine := NewEngine()
		blue := Op{ID: "blue", Kind: OpSubmit, Alias: "/deploy/api", Target: "/srv/blue"}
		green := Op{ID: "green", Kind: OpSubmit, Alias: "/deploy//api/", Target: "/srv/green/"}
		if reverse {
			engine.Apply(green)
			engine.Apply(blue)
		} else {
			engine.Apply(blue)
			engine.Apply(green)
		}
		engine.Apply(Op{ID: "cancel-green", Kind: OpCancel, CancelID: "green"})
		return engine.ResolutionDigest()
	}
	if run(false) != run(true) {
		t.Fatal("resolution depends on submission order")
	}
}

func TestDuplicateSubmissionDoesNotResurrect(t *testing.T) {
	engine := NewEngine()
	blue := Op{ID: "blue", Kind: OpSubmit, Alias: "/deploy/api", Target: "/srv/blue"}
	green := Op{ID: "green", Kind: OpSubmit, Alias: "/deploy//api/", Target: "/srv/green/"}
	engine.Apply(blue)
	engine.Apply(green)
	cancel := Op{ID: "cancel-green", Kind: OpCancel, CancelID: "green"}
	engine.Apply(cancel)
	before := engine.StateJSON()
	for _, op := range []Op{blue, green, cancel} {
		result := engine.Apply(op)
		if result.Outcome != "duplicate_noop" {
			t.Fatalf("duplicate %s outcome=%s", op.ID, result.Outcome)
		}
	}
	if string(before) != string(engine.StateJSON()) {
		t.Fatal("duplicate replay mutated state")
	}
}

func TestOperationIDCollision(t *testing.T) {
	engine := NewEngine()
	engine.Apply(Op{ID: "same", Kind: OpSubmit, Alias: "/a", Target: "/one"})
	result := engine.Apply(Op{ID: "same", Kind: OpSubmit, Alias: "/b", Target: "/two"})
	if result.Outcome != "id_collision" {
		t.Fatalf("outcome=%s", result.Outcome)
	}
	if len(engine.Snapshot().Submissions) != 1 {
		t.Fatal("id collision changed submissions")
	}
}
