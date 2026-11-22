package depthjson

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	deep := strings.Repeat("[", 200) + strings.Repeat("]", 200)
	deepObj := strings.Repeat(`{"k":`, 150) + `1` + strings.Repeat(`}`, 150)
	truncated := `{"a": [1, 2, {"b": "cut off`

	cases := []struct {
		name  string
		input string
		depth int
		want  Kind
	}{
		{"empty object", `{}`, 0, KindOK},
		{"nested within limit", `{"a":{"b":[1,2,{"c":null}]}}`, 0, KindOK},
		{"scalars", `[1, -2.5e3, "x", true, false, null]`, 0, KindOK},
		{"deep array blocked", deep, 0, KindDepth},
		{"deep object blocked", deepObj, 0, KindDepth},
		{"deep allowed with higher limit", deep, 256, KindOK},
		{"truncated", truncated, 0, KindTruncated},
		{"truncated literal", `tru`, 0, KindTruncated},
		{"empty input", ``, 0, KindTruncated},
		{"bad syntax", `{"a": }`, 0, KindSyntax},
		{"trailing data", `{} {}`, 0, KindTrailingData},
		{"bad escape", `"\x"`, 0, KindSyntax},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate([]byte(tc.input), tc.depth)
			if tc.want == KindOK {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want %s, got ok", tc.want)
			}
			if err.Kind != tc.want {
				t.Fatalf("want kind %s, got %s (%v)", tc.want, err.Kind, err)
			}
			if err.Offset < 0 || err.Offset > len(tc.input) {
				t.Fatalf("offset %d out of range", err.Offset)
			}
		})
	}
}

func TestDepthTriggerLocation(t *testing.T) {
	input := `{"payload":{"a":{"a":{"a":1}}}}`
	err := Validate([]byte(input), 3)
	if err == nil || err.Kind != KindDepth {
		t.Fatalf("want depth error, got %v", err)
	}
	if err.Depth != 3 {
		t.Fatalf("want depth 3, got %d", err.Depth)
	}
	if !strings.HasPrefix(err.Path, "$.payload") {
		t.Fatalf("path should point into payload, got %s", err.Path)
	}
	loc := err.Location()
	if !strings.Contains(loc, "offset=") || !strings.Contains(loc, "path=") {
		t.Fatalf("location missing fields: %s", loc)
	}
}

// FuzzValidate is the libFuzzer-style coverage-guided fuzz target
// (Go native fuzzing engine). Run with:
//
//	go test -fuzz=FuzzValidate -fuzztime=30s ./internal/depthjson/
//
// It asserts the validator never panics, never returns an out-of-range
// offset, and agrees with itself on the depth boundary.
func FuzzValidate(f *testing.F) {
	seeds := []string{
		`{}`, `[]`, `null`, `"s"`, `1.5e10`,
		`{"a":[1,2,{"b":true}]}`,
		strings.Repeat("[", 500),
		strings.Repeat(`{"k":`, 500),
		`{"a": [1, 2, {"b": "cut off`,
		`"`,
		`{"\u0041": 1}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		err := Validate(data, DefaultMaxDepth)
		if err == nil {
			return
		}
		if err.Offset < 0 || err.Offset > len(data) {
			t.Fatalf("offset %d out of range for %d-byte input", err.Offset, len(data))
		}
		if err.Depth < 0 || err.Depth > DefaultMaxDepth {
			t.Fatalf("depth %d out of range", err.Depth)
		}
		switch err.Kind {
		case KindDepth, KindTruncated, KindSyntax, KindTrailingData:
		default:
			t.Fatalf("unknown kind %q", err.Kind)
		}
	})
}
