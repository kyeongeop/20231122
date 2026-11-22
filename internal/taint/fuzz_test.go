package taint

import (
	"bytes"
	"testing"

	"taintlab/internal/invariants"
)

func FuzzExecute(f *testing.F) {
	f.Add(loadSample(f))
	f.Add([]byte(`{"schema_version":"taintlab/v1","source":{"label":"x","value":255,"tainted":true},"operations":[{"seq":1,"kind":"trunc","width_bits":8}],"boundary":{"min":-128,"max":127},"permission":{"required_token":-1}}`))
	f.Add([]byte("{"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte("A"), MaxInputBytes+1))

	f.Fuzz(func(t *testing.T, input []byte) {
		result := Execute(input)
		if err := invariants.Check(result); err != nil {
			t.Fatalf("invariant failed: %v", err)
		}
		fromReader, err := ExecuteReader(bytes.NewReader(input))
		if err != nil {
			t.Fatalf("reader failed: %v", err)
		}
		if err := invariants.Check(fromReader); err != nil {
			t.Fatalf("reader invariant failed: %v", err)
		}
	})
}
