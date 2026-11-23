package audit

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPipelineEndToEnd(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	clock := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	p := &Pipeline{Store: store, Now: clock, ToolVersion: "test", RulesVersion: "test-rules"}
	objects := []Object{
		{Label: "v1", Kind: "snapshot-v1", Raw: "PRT1:0a1b2c3d:1798761600"},
		{Label: "v2", Kind: "snapshot-v2", Raw: MintV2("user42", clock.Add(time.Hour).Unix())},
		{Label: "ext", Kind: "unknown-extension", Raw: "PRTX:9f3a:legacy"},
		{Label: "edge", Kind: "boundary", Raw: MintV2("edge01", clock.Unix())},
		{Label: "bad", Kind: "corrupt", Raw: MintV2("bad/id", clock.Add(time.Hour).Unix())},
		{Label: "after-error", Kind: "snapshot-v1", Raw: "PRT1:deadbeef:1700000000"},
	}
	runID, err := p.Run(objects)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	want := map[string]string{
		"v1": VerdictValid, "v2": VerdictValid, "ext": VerdictUnknownExtension,
		"edge": VerdictUndecidable, "bad": VerdictError, "after-error": VerdictExpired,
	}
	for label, verdict := range want {
		var got string
		err := store.db.QueryRow(
			`SELECT c.verdict FROM conclusions c
			 JOIN objects o ON o.id = c.object_id
			 WHERE o.run_id=? AND o.label=?`, runID, label).Scan(&got)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if got != verdict {
			t.Errorf("%s: got %q want %q", label, got, verdict)
		}
	}
	var cleanupOK bool
	if err := store.db.QueryRow(`SELECT cleanup_ok FROM runs WHERE id=?`, runID).Scan(&cleanupOK); err != nil {
		t.Fatal(err)
	}
	if !cleanupOK {
		t.Error("temporary state was not cleaned up")
	}
	// Undecidable conclusion must preserve key evidence.
	var n int
	err = store.db.QueryRow(
		`SELECT COUNT(*) FROM evidence e
		 JOIN conclusions c ON c.id = e.conclusion_id
		 JOIN objects o ON o.id = c.object_id
		 WHERE o.run_id=? AND o.label='edge' AND e.key IN ('audit_clock','expiry_utc')`,
		runID).Scan(&n)
	if err != nil || n != 2 {
		t.Errorf("boundary evidence incomplete: n=%d err=%v", n, err)
	}
}
