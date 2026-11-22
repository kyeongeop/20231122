package inspect

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestUnknownExtensionUsesRawBytes(t *testing.T) {
	body := []byte(primaryBody)
	outcome := VerifyWebhook(VerifyInput{
		ObjectID: "unknown-ext", Body: body,
		Headers: map[string]string{
			"content-type": "application/octet-stream", "x-webhook-timestamp": "1795357868",
		},
		Signature:     "t=1795357868,v1=" + signedAt(primaryBody, 1795357868),
		SignatureAlg:  "HMAC-SHA256",
		Canonicalizer: "stripe-v1",
		Secret:        []byte(demoSecret),
		ObservedAt:    time.Date(2026, 11, 22, 14, 31, 8, 0, time.UTC),
	})
	if outcome.Err != nil {
		t.Fatalf("verify returned error: %v", outcome.Err)
	}
	if outcome.Result.Verdict != VerdictVerified {
		t.Fatalf("verdict = %q, want %q", outcome.Result.Verdict, VerdictVerified)
	}
	if outcome.Result.Confidence != "high" {
		t.Fatalf("confidence = %q, want high", outcome.Result.Confidence)
	}
}

func TestTimestampBoundaryIsIndeterminate(t *testing.T) {
	outcome := VerifyWebhook(VerifyInput{
		ObjectID: "boundary", Body: []byte(snapshotBBody),
		Headers: map[string]string{
			"content-type": "application/json", "x-webhook-timestamp": "1795357868",
		},
		Signature:     "t=1795357868,v1=" + signedAt(snapshotBBody, 1795357868),
		SignatureAlg:  "HMAC-SHA256",
		Canonicalizer: "stripe-v1",
		Secret:        []byte(demoSecret),
		ObservedAt:    time.Date(2026, 11, 22, 14, 36, 8, 0, time.UTC),
		ClockDriftMS:  ClockDriftBoundMS,
		EnforceTime:   true,
	})
	if outcome.Err != nil {
		t.Fatalf("verify returned error: %v", outcome.Err)
	}
	if outcome.Result.Verdict != VerdictIndeterminate {
		t.Fatalf("verdict = %q, want indeterminate", outcome.Result.Verdict)
	}
	if outcome.Result.BoundaryNote == "" {
		t.Fatal("expected boundary note to be retained")
	}
}

func TestMalformedEnvelopeIsIsolatedAndDoesNotStopBatch(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "inspect.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = store.CleanupTemporary(context.Background())
		_ = store.Close()
	})
	if err := store.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Case(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[string]string{}
	for _, object := range snapshot.Objects {
		statuses[object.ID] = object.Status
		if object.Conclusion == nil || len(object.Conclusion.EvidenceIDs) == 0 {
			t.Errorf("object %s has no traceable conclusion", object.ID)
		}
		if len(object.Evidence) == 0 || len(object.Steps) == 0 {
			t.Errorf("object %s is missing evidence or steps", object.ID)
		}
	}
	if statuses["obj-exception"] != VerdictError {
		t.Errorf("exception status = %q, want error", statuses["obj-exception"])
	}
	if statuses["obj-snapshot-v182"] != VerdictVerified {
		t.Errorf("v1.8.2 status = %q, want verified; batch may have stopped", statuses["obj-snapshot-v182"])
	}
	if statuses["obj-snapshot-v200rc1"] != VerdictIndeterminate {
		t.Errorf("v2.0.0-rc1 status = %q, want indeterminate", statuses["obj-snapshot-v200rc1"])
	}
}

func TestCleanupRemovesOnlyTemporaryState(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "inspect.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := store.Case(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Temporary) == 0 {
		t.Fatal("expected seeded temporary state")
	}
	removed, err := store.CleanupTemporary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if removed == 0 {
		t.Fatal("expected temporary state to be removed")
	}
	after, err := store.Case(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Temporary) != 0 {
		t.Fatalf("temporary state remains: %+v", after.Temporary)
	}
	if len(after.Objects) != len(before.Objects) || after.Stats.Evidence != before.Stats.Evidence {
		t.Fatal("cleanup removed persisted evidence")
	}
}
