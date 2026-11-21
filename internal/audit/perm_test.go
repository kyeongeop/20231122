package audit

import (
	"testing"
)

func TestClassifyModeRules(t *testing.T) {
	cases := []struct {
		name string
		path string
		mode uint32
		uid  int
		want string
	}{
		{"setuid", "usr/bin/su", 0o4755, 0, RuleSetUID},
		{"setgid", "usr/bin/sg", 0o2755, 0, RuleSetGID},
		{"world-writable", "home/u/f", 0o666, 1000, RuleWorldWritable},
		{"all-permissive", "tmp/x", 0o777, 0, RuleAllPermissive},
		{"root-writable", "sbin/x", 0o722, 0, RuleRootWritable},
		{"shadow", "etc/shadow", 0o644, 0, RuleShadowExposed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyMode(tc.path, tc.mode, tc.uid, 0, false)
			for _, f := range got {
				if f.Rule == tc.want {
					return
				}
			}
			t.Fatalf("rule %s not found in %+v", tc.want, got)
		})
	}
}

func TestClassifyModeClean(t *testing.T) {
	if got := ClassifyMode("etc/passwd", 0o755, 0, 0, false); len(got) != 0 {
		t.Fatalf("unexpected findings: %+v", got)
	}
}

// FuzzClassifyMode is the libFuzzer-style (Go native fuzzing) target for the
// permission classifier: it must never panic and must stay deterministic.
func FuzzClassifyMode(f *testing.F) {
	f.Add("etc/shadow", uint32(0o644), 0, 0, false)
	f.Add("usr/bin/su", uint32(0o4755), 0, 0, false)
	f.Add("tmp", uint32(0o777), 0, 0, true)
	f.Fuzz(func(t *testing.T, path string, mode uint32, uid, gid int, isDir bool) {
		a := ClassifyMode(path, mode, uid, gid, isDir)
		b := ClassifyMode(path, mode, uid, gid, isDir)
		if len(a) != len(b) {
			t.Fatalf("non-deterministic: %d vs %d", len(a), len(b))
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("non-deterministic finding: %+v vs %+v", a[i], b[i])
			}
		}
	})
}

// FuzzHeaderName feeds arbitrary bytes at the raw tar header parser.
func FuzzHeaderName(f *testing.F) {
	blk := make([]byte, 512)
	copy(blk, "etc/shadow")
	copy(blk[100:], "0000644\x00")
	f.Add(blk)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, block []byte) {
		name, err := HeaderName(block)
		if len(block) < 512 {
			if err == nil {
				t.Fatalf("short block accepted: %q", name)
			}
			return
		}
		if err != nil {
			t.Fatalf("512-byte block rejected: %v", err)
		}
		if len(name) > 100 {
			t.Fatalf("name longer than field: %d", len(name))
		}
		if _, err := HeaderMode(block); err == nil {
			// mode parse succeeded; nothing to assert beyond no-panic
		}
	})
}
