package audit

import (
	"fmt"

	"ckaudit/internal/store"
)

type GenSpec struct {
	Name     string
	Boundary string
	Below    string
	Above    string
	Build    func(value string) string
}

func secureBase() string {
	return "sid=abc123; Secure; HttpOnly; Path=/; SameSite=Strict"
}

func boundarySpecs() []GenSpec {
	return []GenSpec{
		{
			Name: "maxage_zero", Boundary: "Max-Age=0",
			Below: "-1", Above: "1",
			Build: func(v string) string {
				return fmt.Sprintf("sid=abc123; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=%s", v)
			},
		},
		{
			Name: "maxage_i32", Boundary: "Max-Age=2147483647",
			Below: "2147483646", Above: "2147483648",
			Build: func(v string) string {
				return fmt.Sprintf("sid=abc123; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=%s", v)
			},
		},
		{
			Name: "maxage_digit_budget", Boundary: "24 digits",
			Below: string(repeat('9', 23)), Above: string(repeat('9', 25)),
			Build: func(v string) string {
				return fmt.Sprintf("sid=abc123; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=%s", v)
			},
		},
		{
			Name: "attr_count_limit", Boundary: "32 attributes",
			Below: "31", Above: "33",
			Build: func(v string) string {
				return buildAttrCountCookie(v)
			},
		},
		{
			Name: "name_length", Boundary: "256 byte name",
			Below: "255", Above: "257",
			Build: func(v string) string {
				return buildNameLenCookie(v)
			},
		},
		{
			Name: "value_length", Boundary: "4096 byte value",
			Below: "4095", Above: "4097",
			Build: func(v string) string {
				return buildValueLenCookie(v)
			},
		},
		{
			Name: "semicolon_depth", Boundary: "32 semicolons",
			Below: "31", Above: "33",
			Build: func(v string) string {
				return buildSemicolonCookie(v)
			},
		},
	}
}

func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func buildAttrCountCookie(countVal string) string {
	var n int
	fmt.Sscanf(countVal, "%d", &n)
	c := "sid=abc123; Secure; HttpOnly; Path=/; SameSite=Strict"
	for i := 0; i < n-5; i++ {
		c += fmt.Sprintf("; x%d=1", i)
	}
	return c
}

func buildNameLenCookie(countVal string) string {
	var n int
	fmt.Sscanf(countVal, "%d", &n)
	return fmt.Sprintf("%s=v; Secure; HttpOnly; Path=/; SameSite=Strict", string(repeat('n', n)))
}

func buildValueLenCookie(countVal string) string {
	var n int
	fmt.Sscanf(countVal, "%d", &n)
	return fmt.Sprintf("sid=%s; Secure; HttpOnly; Path=/; SameSite=Strict", string(repeat('v', n)))
}

func buildSemicolonCookie(countVal string) string {
	var n int
	fmt.Sscanf(countVal, "%d", &n)
	c := "sid=abc123"
	for i := 0; i < n; i++ {
		c += ";"
	}
	return c + "; Secure; HttpOnly"
}

type attackCase struct {
	key   string
	input string
}

func attackCases() []attackCase {
	return []attackCase{
		{"missing_secure", "sid=abc123; HttpOnly; Path=/; SameSite=Strict"},
		{"missing_httponly", "sid=abc123; Secure; Path=/; SameSite=Strict"},
		{"missing_samesite", "sid=abc123; Secure; HttpOnly; Path=/"},
		{"missing_pair", "Secure; HttpOnly; Path=/"},
		{"empty_name", "=value; Secure; HttpOnly"},
		{"empty_value", "sid=; Secure; HttpOnly; Path=/; SameSite=Strict"},
		{"samesite_none_no_secure", "sid=abc123; SameSite=None; Path=/"},
		{"samesite_unknown", "sid=abc123; Secure; SameSite=Banana; Path=/"},
		{"samesite_empty", "sid=abc123; Secure; SameSite=; Path=/"},
		{"host_prefix_violations", "__Host-sid=v; Secure; Domain=example.com; Path=/home"},
		{"secure_prefix_no_secure", "__Secure-sid=v; HttpOnly; Path=/"},
		{"domain_empty", "sid=abc123; Secure; Domain=; Path=/"},
		{"domain_leading_dot", "sid=abc123; Secure; Domain=.example.com; Path=/"},
		{"path_empty", "sid=abc123; Secure; Path=; SameSite=Strict"},
		{"maxage_bad", "sid=abc123; Secure; Max-Age=soon; Path=/"},
		{"maxage_negative", "sid=abc123; Secure; Max-Age=-3600; Path=/"},
		{"lifetime_redundant", "sid=abc123; Secure; Max-Age=60; Expires=Wed, 21 Oct 2099 07:28:00 GMT; Path=/"},
		{"session_cookie", "sid=abc123; Secure; HttpOnly; SameSite=Strict"},
		{"duplicate_samesite", "sid=abc123; Secure; SameSite=Strict; SameSite=None; Path=/"},
		{"attribute_casing", "sid=abc123; sEcUrE; hTTpOnLy; sAmEsItE=lAx; path=/"},
		{"tab_and_spacing", "  sid  =  abc  ;  Secure ; HttpOnly ; Path=/ "},
		{"semicolons_only", ";;;;;"},
		{"truncated_attr", "sid=abc123; Secure; HttpOnl; Path=/"},
		{"control_bytes", "sid=abc\x00\x01\x02; Secure; Path=/"},
		{"oversized_cookie", "sid=" + string(repeat('A', 8200)) + "; Secure; Path=/"},
	}
}

func Generate(runID int64) ([]store.Sample, error) {
	var out []store.Sample

	for _, ac := range attackCases() {
		out = append(out, store.Sample{
			RunID: runID, SampleKey: "attack/" + ac.key,
			Scenario: "missing-fragment-attack", Boundary: "",
			Side: "", ParamValue: "", Input: ac.input,
		})
	}

	for _, spec := range boundarySpecs() {
		base := store.Sample{
			RunID: runID, Scenario: "extreme-boundary", Boundary: spec.Boundary,
		}
		lo := base
		lo.SampleKey = "boundary/" + spec.Name + "/below"
		lo.Side = "below"
		lo.ParamValue = spec.Below
		lo.Input = spec.Build(spec.Below)
		hi := base
		hi.SampleKey = "boundary/" + spec.Name + "/above"
		hi.Side = "above"
		hi.ParamValue = spec.Above
		hi.Input = spec.Build(spec.Above)
		out = append(out, lo, hi)
	}
	return out, nil
}
