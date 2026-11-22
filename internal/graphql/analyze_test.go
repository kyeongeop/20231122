package graphql

import (
	"encoding/json"
	"strings"
	"testing"
)

const deepQuery = "query Deep { viewer { friends { friends { friends { name } } } } }"

func TestTruncatedRecordStopsAtSyntax(t *testing.T) {
	truncated := deepQuery[:strings.Index(deepQuery, "name")+2]
	trace := Analyze(truncated, 4)
	if trace.FirstError == nil {
		t.Fatal("expected a failure")
	}
	if trace.FirstError.Seq != 3 || trace.FirstError.Stage != "syntax" {
		t.Fatalf("first error = %+v, want seq 3 syntax", trace.FirstError)
	}
	if trace.FirstError.Code != "UNCLOSED_DELIMITER" {
		t.Fatalf("first error code = %q, want UNCLOSED_DELIMITER", trace.FirstError.Code)
	}
	if len(trace.Steps) != 5 {
		t.Fatalf("step count = %d, want 5", len(trace.Steps))
	}
}

func TestRecoveredControlReachesDepthPolicy(t *testing.T) {
	trace := Analyze(deepQuery, 4)
	if trace.FirstError == nil {
		t.Fatal("expected a depth failure")
	}
	if trace.FirstError.Seq != 5 || trace.FirstError.Stage != "policy" {
		t.Fatalf("first error = %+v, want seq 5 policy", trace.FirstError)
	}
	if trace.FirstError.Code != "DEPTH_LIMIT_EXCEEDED" {
		t.Fatalf("first error code = %q, want DEPTH_LIMIT_EXCEEDED", trace.FirstError.Code)
	}
	var final state
	if err := json.Unmarshal(trace.Steps[3].Result, &final); err != nil {
		t.Fatal(err)
	}
	if final.MaxDepth != 5 {
		t.Fatalf("max depth = %d, want 5", final.MaxDepth)
	}
}

func TestUnterminatedStringFailsAtTokenize(t *testing.T) {
	trace := Analyze(`query { viewer(name: "cut`, 4)
	if trace.FirstError == nil || trace.FirstError.Seq != 2 {
		t.Fatalf("first error = %+v, want tokenize", trace.FirstError)
	}
	if trace.FirstError.Code != "LEXICAL_ERROR" {
		t.Fatalf("first error code = %q, want LEXICAL_ERROR", trace.FirstError.Code)
	}
}

func TestShallowQueryIsAllowed(t *testing.T) {
	trace := Analyze("query { viewer { name } }", 4)
	if trace.FirstError != nil {
		t.Fatalf("unexpected failure: %+v", trace.FirstError)
	}
}
