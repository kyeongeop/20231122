package experiment

import (
	"os"
	"path/filepath"
	"testing"

	"cacheleak.local/experiment/internal/model"
)

func TestVulnerableCacheKeyOmitsSnapshot(t *testing.T) {
	fixture := NewFixture()
	root := t.TempDir()
	snapshots, err := fixture.Materialize(root)
	if err != nil {
		t.Fatal(err)
	}
	harness := NewHarness(root, snapshots)
	first := harness.Serve(model.RequestInput{
		Method: "GET", Path: opaquePath, SnapshotID: "snap-v1", Submit: 1,
	})
	if first.Error != nil || first.Result.CacheStatus != "MISS" || first.Result.Leaked {
		t.Fatalf("first request: %+v", first)
	}
	second := harness.Serve(model.RequestInput{
		Method: "GET", Path: opaquePath, SnapshotID: "snap-v2", Submit: 1,
	})
	if second.Error != nil {
		t.Fatal(second.Error)
	}
	if second.Result.CacheStatus != "HIT" || second.Result.ServedSnapshot != "snap-v1" ||
		!second.Result.Leaked || second.Result.BodySHA256 != first.Result.BodySHA256 {
		t.Fatalf("expected stale v1 response, got %+v", second.Result)
	}
	if second.Result.BodySHA256 == second.Result.ExpectedSHA256 {
		t.Fatal("stale body unexpectedly matched the v2 snapshot")
	}
}

func TestErrorDoesNotStopFollowingObject(t *testing.T) {
	fixture := NewFixture()
	root := t.TempDir()
	snapshots, err := fixture.Materialize(root)
	if err != nil {
		t.Fatal(err)
	}
	harness := NewHarness(root, snapshots)
	missing := harness.Serve(model.RequestInput{
		Method: "GET", Path: partialPath, SnapshotID: "snap-v2",
	})
	if missing.Error == nil || missing.Result.CacheStatus != "ERROR" {
		t.Fatalf("expected isolated missing-object error: %+v", missing)
	}
	next := harness.Serve(model.RequestInput{
		Method: "GET", Path: tailPath, SnapshotID: "snap-v1",
	})
	if next.Error != nil || next.Result.CacheStatus != "MISS" || next.Result.StatusCode != 200 {
		t.Fatalf("following object was not processed: %+v", next)
	}
}

func TestUnknownExtensionMaterializesAsOpaqueBytes(t *testing.T) {
	fixture := NewFixture()
	root := t.TempDir()
	if _, err := fixture.Materialize(root); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(root, "snap-v1", "static", "opaque.q7x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 || filepath.Ext("opaque.q7x") != model.UnknownExt {
		t.Fatal("unknown-extension fixture was not materialized")
	}
	for _, obj := range fixture.Objects {
		if obj.Extension == model.UnknownExt && (obj.KnownExtension || obj.MIME != model.UnknownMIME) {
			t.Fatalf("unknown extension misclassified: %+v", obj)
		}
	}
}
