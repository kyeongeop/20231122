package ledger

import (
	"os"
	"path/filepath"
	"testing"

	"pathaliaslab/internal/model"
)

func TestOpenForVerificationDoesNotRewriteDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	scenario := []byte(`{"name":"test"}`)
	if err := store.BeginRun("test", "test", "test", scenario); err != nil {
		t.Fatal(err)
	}
	engine := model.NewEngine()
	before := engine.StateJSON()
	op := model.Op{ID: "a", Kind: model.OpSubmit, Alias: "/a", Target: "/b"}
	result := engine.Apply(op)
	after := engine.StateJSON()
	input := []byte(`{"id":"a","kind":"submit","alias":"/a","target":"/b"}`)
	resultJSON := []byte(`{"op_id":"a","kind":"submit","outcome":"activated","accepted":true}`)
	head, err := store.AddStep("test", 1, input, before, resultJSON, after)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "activated" {
		t.Fatalf("outcome=%s", result.Outcome)
	}
	if err := store.FinishRun("test", "passed", after, engine.ResolutionDigest(), head, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := SHA256(first)

	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyEvidenceChain("test"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if SHA256(second) != hash {
		t.Fatal("read-only verification changed the database file")
	}
}
