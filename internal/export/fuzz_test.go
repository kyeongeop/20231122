package export

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzBundleRoundTrip builds a bundle from fuzzed evidence blobs and then
// independently verifies every manifest hash. Tampering one byte after the
// fact must be detected.
func FuzzBundleRoundTrip(f *testing.F) {
	f.Add([]byte("capture-a"), []byte("capture-b"), []byte("{\"ok\":true}"))
	f.Fuzz(func(t *testing.T, a, b, report []byte) {
		if len(a) > 4096 || len(b) > 4096 || len(report) > 4096 {
			return
		}
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "a.sqlite")
		if err := os.WriteFile(dbPath, []byte("sqlite-ish"), 0o644); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "bundle.tar")
		if _, err := Build(Options{
			RunID:      "run-fuzz",
			SQLitePath: dbPath,
			ReportJSON: report,
			ReportSHA:  "ignored-at-build",
			OutPath:    out,
			ExtraFiles: map[string][]byte{"a.bin": a, "b.bin": b},
		}); err != nil {
			t.Fatal(err)
		}
		if err := VerifyBundle(out); err != nil {
			t.Fatalf("fresh bundle failed verification: %v", err)
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 0 {
			tampered := append([]byte(nil), raw...)
			tampered[len(tampered)-1] ^= 0x01
			bad := filepath.Join(dir, "bad.tar")
			if err := os.WriteFile(bad, tampered, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := VerifyBundle(bad); err == nil {
				t.Fatal("tampered bundle was accepted")
			}
		}
	})
}
