package harness

import (
	"testing"

	"github.com/kyeongeop/20231122/internal/scenario"
)

func FuzzSmuggle(f *testing.F) {
	// Seed with the scenario corpus (attacks, empty, boundary pair).
	for _, sc := range scenario.All() {
		input := sc.Build()
		if len(input) <= 1<<20 {
			f.Add(input)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on input %q: %v", data, r)
			}
		}()
		for _, v := range Check(data) {
			t.Errorf("invariant violation: %s", v)
		}
	})
}
