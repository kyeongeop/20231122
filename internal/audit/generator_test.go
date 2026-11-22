package audit

import (
	"strings"
	"testing"
)

func TestGeneratePairsEachBoundary(t *testing.T) {
	samples, err := Generate(1)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sides := map[string]map[string]bool{}
	attacks, boundaries := 0, 0
	for _, smp := range samples {
		switch smp.Scenario {
		case "missing-fragment-attack":
			attacks++
		case "extreme-boundary":
			boundaries++
			if sides[smp.Boundary] == nil {
				sides[smp.Boundary] = map[string]bool{}
			}
			sides[smp.Boundary][smp.Side] = true
			if smp.Input == "" {
				t.Errorf("boundary sample %s has empty input", smp.SampleKey)
			}
		default:
			t.Fatalf("unknown scenario %q", smp.Scenario)
		}
	}
	if attacks == 0 {
		t.Fatal("expected attack samples")
	}
	if boundaries == 0 || boundaries%2 != 0 {
		t.Fatalf("boundary samples must come in below/above pairs, got %d", boundaries)
	}
	for boundary, pair := range sides {
		if !pair["below"] || !pair["above"] {
			t.Errorf("boundary %q missing a side: %v", boundary, pair)
		}
	}
}

func TestDigitBudgetBoundaryFlips(t *testing.T) {
	samples, _ := Generate(1)
	for _, smp := range samples {
		if smp.Boundary != "24 digits" {
			continue
		}
		digits := strings.Count(smp.ParamValue, "9")
		switch smp.Side {
		case "below":
			if digits != 23 {
				t.Errorf("below expects 23 digits, got %d", digits)
			}
		case "above":
			if digits != 25 {
				t.Errorf("above expects 25 digits, got %d", digits)
			}
		}
	}
}
