package manifest_test

import (
	"os"
	"strings"
	"testing"

	"example.com/migration-review/internal/manifest"
	"example.com/migration-review/internal/model"
)

func TestParseCurrentAndLegacyFormats(t *testing.T) {
	current := readFixture(t, "../../testdata/migrations/new-add-orders.json")
	legacy := readFixture(t, "../../testdata/attack/legacy-drop-audit.json")

	cur, err := manifest.Parse(current, "new-add-orders.json")
	if err != nil {
		t.Fatalf("parse current: %v", err)
	}
	old, err := manifest.Parse(legacy, "legacy-drop-audit.json")
	if err != nil {
		t.Fatalf("parse legacy: %v", err)
	}
	if cur.Format != model.FormatCurrent || cur.ID != "orders-v2" || len(cur.Statements) != 2 {
		t.Fatalf("unexpected current manifest: %#v", cur)
	}
	if old.Format != model.FormatLegacyJSON || len(old.Statements) != 2 {
		t.Fatalf("unexpected legacy manifest: %#v", old)
	}
	if !strings.Contains(old.Statements[1].SQL, "DROP TABLE audit_log") {
		t.Fatalf("legacy semicolon split failed: %q", old.Statements[1].SQL)
	}
	if old.SourceSHA256 != model.SHA256Hex(legacy) || len(old.Raw) != len(legacy) {
		t.Fatal("legacy raw evidence was not retained")
	}
	if !strings.Contains(string(old.Normalized), `"source_format": "legacy-v1"`) {
		t.Fatalf("legacy normalization missing source format: %s", old.Normalized)
	}
}

func TestParseLegacySQLAndQuotedSemicolon(t *testing.T) {
	input := []byte("-- old\nCREATE TABLE notes (body TEXT);\nINSERT INTO notes VALUES ('a;b');")
	m, err := manifest.Parse(input, "old.sql")
	if err != nil {
		t.Fatalf("parse legacy SQL: %v", err)
	}
	if m.Format != model.FormatLegacySQL || len(m.Statements) != 2 {
		t.Fatalf("unexpected parse: format=%s statements=%d", m.Format, len(m.Statements))
	}
	if !strings.Contains(m.Statements[1].SQL, "'a;b'") {
		t.Fatalf("quoted semicolon was split: %q", m.Statements[1].SQL)
	}
}

func TestRejectEmptyAndOversized(t *testing.T) {
	if _, err := manifest.Parse(nil, "empty"); err == nil {
		t.Fatal("expected empty input error")
	}
	if _, err := manifest.Parse([]byte("   \n"), "empty"); err == nil {
		t.Fatal("expected whitespace input error")
	}
	if _, err := manifest.Parse(make([]byte, (4<<20)+1), "large"); err == nil {
		t.Fatal("expected size limit error")
	}
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}
