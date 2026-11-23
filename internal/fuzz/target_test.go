package fuzz

import "testing"

// FuzzTarget mirrors the libFuzzer entry point for developers who prefer the
// native Go toolchain. Both harnesses exercise the same Target function, so a
// reproducer found by either engine can be replayed by the other.
func FuzzTarget(f *testing.F) {
	seeds := []string{
		`{"schema_version":1,"sample_id":"x","title":"t","attack_class":"c","clocks":[],"events":[],"note":"","input_sha256":"","created_at":"2026-11-23T00:00:00Z"}`,
		`not-json`,
		`{"schema_version":1}`,
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if Target([]byte(input)) != 0 {
			t.Fatalf("target reported a defect for input %q", input)
		}
	})
}
