package store

import (
	"path/filepath"
	"testing"

	"trustaudit/internal/record"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestRecoverQuarantinesTruncatedTail(t *testing.T) {
	st := openTemp(t)
	good1 := record.EncodeV1(record.Record{TS: 1, Remote: "10.1.2.10", XFF: "203.0.113.50", Action: "allow"})
	good2 := record.EncodeV2(record.Record{TS: 2, Remote: "198.51.100.7", Action: "allow"})
	bad := record.EncodeV2(record.Record{TS: 3, Remote: "10.1.2.10", XFF: "8.8.8.8", Action: "allow"})
	bad = bad[:len(bad)/2]
	for _, raw := range [][]byte{good1, good2, bad} {
		if _, err := st.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := st.Recover()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Salvaged != 2 || rep.Quarantined != 1 || rep.FirstBadLogID != 3 {
		t.Fatalf("unexpected recovery report: %+v", rep)
	}
	ev, err := st.EvidenceRows()
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0].LogID != 3 || ev[0].Kind != "truncated-record" {
		t.Fatalf("evidence not preserved: %+v", ev)
	}
	if len(ev[0].Raw) != len(bad) || ev[0].SHA256 == "" {
		t.Fatal("raw bytes or hash missing from evidence")
	}
	entries, err := st.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if entries[2].Status != StatusQuarantine {
		t.Fatalf("tail status = %s", entries[2].Status)
	}
}

func TestRecoverCleanLog(t *testing.T) {
	st := openTemp(t)
	raw := record.EncodeV1(record.Record{TS: 1, Remote: "10.1.2.10", Action: "allow"})
	if _, err := st.Append(raw); err != nil {
		t.Fatal(err)
	}
	rep, err := st.Recover()
	if err != nil {
		t.Fatal(err)
	}
	if rep.FirstBadLogID != 0 || rep.Salvaged != 1 {
		t.Fatalf("clean log misreported: %+v", rep)
	}
}
