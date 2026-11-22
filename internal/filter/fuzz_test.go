// FuzzFilenameUnicodeBypass is the coverage-guided fuzz target. It is
// compatible with Go's native fuzzer (go test -fuzz) and, via the
// libfuzzer build tag shim in libfuzzer.go, with a real libFuzzer
// engine linked through clang -fsanitize=fuzzer.
package filter

import "testing"

func FuzzFilenameUnicodeBypass(f *testing.F) {
	// Seeds are non-crashing; bypass inputs are discovered during
	// fuzzing and preserved as evidence under artifacts/evidence/.
	seeds := []string{
		"payload.exe",
		"readme.txt",
		"report..exe",
		"dir//payload.exe",
		"pay\xc3load.exe",
		"normal-file_123.tar.gz",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		v := Classify(name)
		if v.Bypass() {
			t.Fatalf("unicode filter bypass: %q accepted by validator but canonicalizes to dangerous %q",
				name, Canonicalize(name))
		}
	})
}

// FuzzHardenedNoBypass asserts the invariant of the hardened filter:
// it must never accept a name the oracle considers dangerous. This
// target is expected to stay green.
func FuzzHardenedNoBypass(f *testing.F) {
	f.Add("payload.exe")
	f.Add("readme.txt")
	f.Fuzz(func(t *testing.T, name string) {
		if ValidateHardened(name) && OracleDangerous(name) {
			t.Fatalf("hardened filter accepted dangerous name %q", name)
		}
	})
}
