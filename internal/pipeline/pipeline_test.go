package pipeline

import (
	"path/filepath"
	"testing"
	"time"

	"unicodebypass/internal/store"
)

func openTemp(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func runOnce(t *testing.T, db *store.DB, cfg Config, resume bool) Result {
	t.Helper()
	p, _, err := NewProcessor(db, cfg, Generate(), resume)
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.Process()
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func finalDigest(t *testing.T, db *store.DB) string {
	t.Helper()
	st, err := db.Prepare(`SELECT digest FROM checkpoints ORDER BY rowid DESC LIMIT 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	row, err := st.QueryRow(1)
	if err != nil || row == nil {
		t.Fatalf("no checkpoint: %v", err)
	}
	return row[0]
}

// Pause/resume must produce the same cumulative digest as one
// uninterrupted run over the same deterministic corpus.
func TestPauseResumeDeterministic(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Deadline = time.Minute
	db1 := openTemp(t)
	res := runOnce(t, db1, cfg, false)
	if !res.Done {
		t.Fatalf("uninterrupted run did not finish: %+v", res)
	}
	want := finalDigest(t, db1)

	db2 := openTemp(t)
	cfgPause := cfg
	cfgPause.PauseAfter = 50
	res = runOnce(t, db2, cfgPause, false)
	if !res.Paused {
		t.Fatalf("expected pause, got %+v", res)
	}
	res = runOnce(t, db2, cfg, true)
	if !res.Done {
		t.Fatalf("resumed run did not finish: %+v", res)
	}
	if got := finalDigest(t, db2); got != want {
		t.Fatalf("digest mismatch after resume:\n got %s\nwant %s", got, want)
	}
}

// Oversize names must trigger the degraded path and be recorded.
func TestDegradationRecorded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DegradeLen = 256 // everything padded to >=256 degrades
	db := openTemp(t)
	res := runOnce(t, db, cfg, false)
	if !res.Done {
		t.Fatalf("expected completion, got %+v", res)
	}
	st, err := db.Prepare(`SELECT count(*) FROM degradations`)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	n, err := st.QueryInt()
	if err != nil || n == 0 {
		t.Fatalf("expected degradation events, got %d (%v)", n, err)
	}
}

// Each segment must record exactly one sample on each boundary side.
func TestBoundarySamples(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PauseAfter = 40
	db := openTemp(t)
	runOnce(t, db, cfg, false)
	cfg.PauseAfter = 0
	runOnce(t, db, cfg, true)

	st, err := db.Prepare(`SELECT segment, side, len FROM boundary_samples`)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	type key struct{ seg, side string }
	seen := map[key]int{}
	for {
		row, err := st.QueryRow(3)
		if err != nil {
			t.Fatal(err)
		}
		if row == nil {
			break
		}
		seen[key{row[0], row[1]}]++
	}
	for _, k := range []key{
		{"pre-pause", "before"}, {"pre-pause", "after"},
		{"post-resume", "before"}, {"post-resume", "after"},
	} {
		if seen[k] != 1 {
			t.Errorf("boundary sample %v: got %d rows, want 1", k, seen[k])
		}
	}
}
