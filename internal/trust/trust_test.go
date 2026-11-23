package trust

import "testing"

func TestDecideRules(t *testing.T) {
	b := DefaultBoundary()
	cases := []struct {
		name, remote, xff, action, rule string
	}{
		{"trusted proxy with xff", "10.1.2.10", "203.0.113.50", ActionAllow, "R1-trusted-proxy"},
		{"trusted proxy no xff", "192.168.7.3", "", ActionAllow, "R1-trusted-no-xff"},
		{"trusted proxy bad xff", "10.1.2.10", "not-an-ip", ActionDeny, "R2-malformed-xff"},
		{"spoof attempt", "203.0.113.9", "10.0.0.5", ActionDeny, "R3-xff-spoof"},
		{"direct client", "198.51.100.7", "", ActionAllow, "R4-direct-client"},
		{"blocked client via proxy", "10.1.2.10", "10.2.3.4", ActionDeny, "R5-blocked-client"},
		{"garbage peer", "garbage", "", ActionDeny, "R0-bad-peer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := b.Decide(c.remote, c.xff)
			if d.Action != c.action || d.Rule != c.rule {
				t.Fatalf("got %s/%s, want %s/%s", d.Action, d.Rule, c.action, c.rule)
			}
			if d.Location == "" || d.Location == "unknown" {
				t.Fatal("trigger location not captured")
			}
		})
	}
}

// FuzzDecide throws arbitrary peer/header strings at the boundary:
// it must never panic and must always return a defined action.
func FuzzDecide(f *testing.F) {
	f.Add("10.1.2.10", "203.0.113.50")
	f.Add("203.0.113.9", "10.0.0.5")
	f.Add("", "")
	f.Add("::1", "fe80::1, 10.0.0.1")
	f.Fuzz(func(t *testing.T, remote, xff string) {
		d := DefaultBoundary().Decide(remote, xff)
		if d.Action != ActionAllow && d.Action != ActionDeny {
			t.Fatalf("undefined action %q", d.Action)
		}
		if d.Rule == "" {
			t.Fatal("no rule recorded")
		}
	})
}
