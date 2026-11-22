package filter

import "testing"

func TestValidatorBasics(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"readme.txt", true},
		{"payload.exe", false},
		{"PAYLOAD.EXE", false},
		{"../etc/passwd", false},
		{"bad\x01name", false},
		{"", false},
	}
	for _, c := range cases {
		if got := Validate(c.name); got != c.ok {
			t.Errorf("Validate(%q) = %v, want %v", c.name, got, c.ok)
		}
	}
}

func TestOracleCatchesUnicodeBypasses(t *testing.T) {
	bypasses := []string{
		"payload．ｅｘｅ",     // fullwidth dot + fullwidth ext
		"photo․exe",       // one-dot-leader U+2024
		"invoice‮exe.jpg", // U+202E RTL override
		"paylоad.exe",     // Cyrillic о (already ASCII ext here)
		"setup.еxe",       // Cyrillic е in extension
		"update.exe ",     // trailing space (Windows strips)
		"update.exe.",     // trailing dot
		"con.txt",         // reserved device name
		"dir­x‑y.txt",     // soft/non-breaking hyphen, no traversal
	}
	for _, n := range bypasses[:8] {
		if !OracleDangerous(n) {
			t.Errorf("OracleDangerous(%q) = false, want true", n)
		}
	}
	if OracleDangerous(bypasses[8]) {
		t.Errorf("OracleDangerous(%q) = true, want false", bypasses[8])
	}
}

func TestHardenedValidator(t *testing.T) {
	dangerous := []string{
		"payload．ｅｘｅ", "photo․exe", "invoice‮exe.jpg",
		"setup.еxe", "update.exe ", "con.txt", "..\\x",
	}
	for _, n := range dangerous {
		if ValidateHardened(n) {
			t.Errorf("ValidateHardened(%q) = true, want false", n)
		}
	}
	if !ValidateHardened("readme.txt") {
		t.Error("ValidateHardened(readme.txt) = false, want true")
	}
}

func TestBypassVerdict(t *testing.T) {
	v := Classify("payload．ｅｘｅ")
	if !v.ValidatorOK || !v.OracleDanger || !v.Bypass() {
		t.Errorf("expected bypass verdict, got %+v", v)
	}
	v = Classify("readme.txt")
	if !v.ValidatorOK || v.OracleDanger || v.Bypass() {
		t.Errorf("expected clean verdict, got %+v", v)
	}
}
