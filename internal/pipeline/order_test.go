package pipeline

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"truncstream/internal/resource"
	"truncstream/internal/store"
)

func TestReloadPreservesFieldOrder(t *testing.T) {
	capA, capB := buildCaptures(t, 12, false)
	path := filepath.Join(t.TempDir(), "order.sqlite")
	cfg := Config{RunID: "r", ObjectID: "obj-x", CaptureA: capA, CaptureB: capB,
		Budget: resource.DefaultBudget(), SuspendAfter: 3}

	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	p := New(st)
	pa, pb, err := p.Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Process(cfg, pa, pb); err != nil {
		t.Fatal(err)
	}
	cp1, state1, err := st.LatestCheckpoint("r")
	if err != nil {
		t.Fatal(err)
	}
	st.Close()

	st2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	cp2, state2, err := st2.LatestCheckpoint("r")
	if err != nil {
		t.Fatal(err)
	}
	if cp1.StateSHA256 != cp2.StateSHA256 {
		t.Fatalf("checkpoint hash changed across reload")
	}

	// Marshal the reloaded struct: field order must follow the struct
	// declaration exactly, with no random map ordering leaking through.
	raw1, err := json.MarshalIndent(state1, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := json.MarshalIndent(state2, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw1) != string(raw2) {
		t.Fatalf("state JSON differs across reload:\n%s\n%s", raw1, raw2)
	}
	wantOrder := []string{
		`"run_id"`, `"next_seq"`, `"consumed_frames"`, `"accumulator"`,
		`"seen_checkpoints"`, `"degrade_level"`, `"input_fingerprint"`, `"stage"`,
	}
	text := string(raw1)
	last := -1
	for _, key := range wantOrder {
		idx := strings.Index(text, key)
		if idx <= last {
			t.Fatalf("field %s out of order in %s", key, text)
		}
		last = idx
	}

	// The report document must keep its own fixed field order on reload.
	p2 := New(st2)
	if _, err := p2.Process(cfg, pa, pb); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p2.Finalize(cfg, pa, pb); err != nil {
		t.Fatal(err)
	}
	reportJSON, _, err := st2.GetReport("r")
	if err != nil {
		t.Fatal(err)
	}
	reportOrder := []string{
		`"object_id"`, `"device_a_offset_ms"`, `"device_b_offset_ms"`,
		`"pair_count"`, `"matched_count"`, `"metric_mismatches"`,
		`"only_in_a"`, `"only_in_b"`, `"pairs"`, `"input_fingerprint"`,
	}
	last = -1
	for _, key := range reportOrder {
		idx := strings.Index(reportJSON, key)
		if idx <= last {
			t.Fatalf("report field %s out of order", key)
		}
		last = idx
	}
}
