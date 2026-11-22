// Package filter implements the filename validator under test and the
// canonicalization oracle used to detect Unicode-based filter bypasses.
package filter

import (
	"strings"
	"unicode"
)

// blockedExts is the deny-list enforced by the naive validator.
var blockedExts = map[string]bool{
	".exe": true, ".bat": true, ".cmd": true, ".com": true,
	".scr": true, ".js": true, ".vbs": true, ".ps1": true,
	".sh": true, ".dll": true, ".msi": true, ".hta": true,
	".jar": true,
}

// reservedNames are DOS device names that must never be used as filenames.
var reservedNames = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true,
}

// bidiControls are directional formatting runes. Their presence in a
// filename is treated as dangerous per se (visual spoofing), matching
// real-world defenses against RTL-override disguises.
func hasBidiControl(name string) bool {
	for _, r := range name {
		if r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 {
			return true
		}
	}
	return false
}

// Verdict is the outcome of validating one filename.
type Verdict struct {
	Name         string
	ValidatorOK  bool // naive filter accepts the name
	OracleDanger bool // canonicalized name is dangerous
	Degraded     bool // cheap degraded path was used
}

// Bypass reports a filter bypass: the validator accepted a name that the
// oracle considers dangerous after canonicalization.
func (v Verdict) Bypass() bool { return v.ValidatorOK && v.OracleDanger }

// Validate is the naive filter under test. It lowercases ASCII, rejects
// C0 controls, ".." and names ending in a blocked extension. It performs
// no Unicode canonicalization, which is the weakness the fuzzer exploits.
func Validate(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r < 0x20 {
			return false
		}
	}
	if strings.Contains(name, "..") {
		return false
	}
	lower := strings.ToLower(name)
	for ext := range blockedExts {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	return true
}

// confusables maps homoglyph runes (Cyrillic/Greek lookalikes) to the ASCII
// letters they imitate in extension names.
var confusables = map[rune]rune{
	'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x',
	'ѕ': 's', 'ј': 'j', 'і': 'i', 'һ': 'h', 'ԁ': 'd', 'Ь': 'b',
	'ν': 'v', 'τ': 't', 'ι': 'i', 'ο': 'o', 'α': 'a', 'ρ': 'p',
	'ｍ': 'm', '＇': '\'',
}

// Canonicalize applies the oracle normalization: fullwidth folding,
// confusable mapping, case folding, removal of format/control runes
// (incl. U+202E RTL override, ZWSP, BOM) and Windows-style trimming of
// trailing dots and spaces.
func Canonicalize(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r == 0 || unicode.Is(unicode.Cc, r):
			continue
		case unicode.Is(unicode.Cf, r):
			continue // U+202E, U+200B..U+200F, U+FEFF, ...
		case r == '　':
			r = ' '
		case r >= '！' && r <= '～':
			r -= 0xFEE0 // fullwidth -> ASCII
		}
		if c, ok := confusables[r]; ok {
			r = c
		}
		if c, ok := confusables[unicode.ToLower(r)]; ok {
			r = c
		}
		b.WriteRune(unicode.ToLower(r))
	}
	out := b.String()
	// One-dot-leader and friends collapse to a real dot.
	out = strings.ReplaceAll(out, "․", ".")
	out = strings.ReplaceAll(out, "‥", "..")
	return strings.TrimRight(out, ". ")
}

// OracleDangerous reports whether the canonicalized name is dangerous.
func OracleDangerous(name string) bool {
	if hasBidiControl(name) {
		return true
	}
	c := Canonicalize(name)
	if c == "" {
		return false
	}
	if strings.Contains(c, "..") {
		return true
	}
	base := c
	if i := strings.LastIndexAny(c, "/\\"); i >= 0 {
		base = c[i+1:]
	}
	stem := base
	if i := strings.IndexByte(base, '.'); i >= 0 {
		stem = base[:i]
	}
	if reservedNames[stem] {
		return true
	}
	for ext := range blockedExts {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return false
}

// ValidateHardened is the fixed filter: canonicalize first, then apply
// the same deny-list policy. The fuzz invariant asserts it never accepts
// a name the oracle considers dangerous.
func ValidateHardened(name string) bool {
	if OracleDangerous(name) {
		return false
	}
	return Validate(Canonicalize(name))
}

// Classify runs the full (expensive) path: naive validator plus oracle.
func Classify(name string) Verdict {
	return Verdict{
		Name:         name,
		ValidatorOK:  Validate(name),
		OracleDanger: OracleDangerous(name),
	}
}

// ClassifyDegraded is the cheap degraded path used under resource
// pressure: ASCII-only suffix check, no Unicode canonicalization.
func ClassifyDegraded(name string) Verdict {
	v := Verdict{Name: name, ValidatorOK: Validate(name), Degraded: true}
	lower := strings.ToLower(name)
	for ext := range blockedExts {
		if strings.HasSuffix(lower, ext) {
			v.OracleDanger = true
			break
		}
	}
	return v
}
