package replay

import (
	"path/filepath"
	"testing"

	"trustaudit/internal/record"
	"trustaudit/internal/store"
	"trustaudit/internal/trust"
)

// TestFirstErrorState seeds a log where record 2 records a wrong action
// and record 3 is also wrong; replay must point at record 2, not just
// report a mismatch count.
func TestFirstErrorState(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rows := [][]byte{
		record.EncodeV1(record.Record{TS: 1, Remote: "10.1.2.10", XFF: "203.0.113.50", Action: "allow"}),
		record.EncodeV2(record.Record{TS: 2, Remote: "203.0.113.9", XFF: "10.0.0.5", Action: "allow"}), // wrong: replay says deny
		record.EncodeV2(record.Record{TS: 3, Remote: "198.51.100.7", Action: "deny"}),                  // wrong: replay says allow
	}
	for _, raw := range rows {
		if _, err := st.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Recover(); err != nil {
		t.Fatal(err)
	}
	rep, err := Replay(st, trust.DefaultBoundary())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total != 3 || rep.Mismatched != 2 {
		t.Fatalf("unexpected totals: %+v", rep)
	}
	if rep.FirstError == nil {
		t.Fatal("first error not reported")
	}
	if rep.FirstError.LogID != 2 || rep.FirstError.Recorded != "allow" ||
		rep.FirstError.Recomputed != "deny" || rep.FirstError.Rule != "R3-xff-spoof" {
		t.Fatalf("wrong first error: %+v", rep.FirstError)
	}
	// correlation must be complete on every entry
	for _, e := range rep.Entries {
		if e.Evidence.SHA256 == "" || e.Trigger.Rule == "" || e.Trigger.Location == "" ||
			e.Judgment.Action == "" {
			t.Fatalf("incomplete correlation: %+v", e)
		}
	}
}
