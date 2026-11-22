package main

import (
	"testing"

	"depthlab/internal/graphql"
)

func TestSeedTriggersDepthViolation(t *testing.T) {
	seed := []byte("query Deep { viewer { friends { friends { friends { name } } } } }\n")
	if !fuzzQuery(seed) {
		trace := graphql.Analyze(string(seed), graphql.DefaultLimit)
		t.Fatalf("seed did not trigger the depth violation: first=%+v depth=%s",
			trace.FirstError, trace.Steps[3].Result)
	}
}
