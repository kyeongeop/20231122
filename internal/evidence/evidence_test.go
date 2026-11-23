package evidence

import (
	"path/filepath"
	"testing"

	"oauthreview/internal/callback"
)

func TestRecordAndQuery(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	body := []byte("code=x&state=state-cancel&error=access_denied")
	cb, perr := callback.Parse("application/x-www-form-urlencoded", body)
	if perr != nil {
		t.Fatal(perr)
	}
	out := callback.NewValidator(testPolicy()).Validate("E1", cb)
	if err := store.RecordCase("E1", "application/x-www-form-urlencoded",
		"test", cb, out); err != nil {
		t.Fatal(err)
	}
	// 原始证据不可覆盖。
	if err := store.RecordCase("E1", "application/x-www-form-urlencoded",
		"test", cb, out); err != ErrCaseExists {
		t.Fatalf("want ErrCaseExists, got %v", err)
	}

	rows, err := store.ListCases()
	if err != nil || len(rows) != 1 {
		t.Fatalf("list: %v rows=%d", err, len(rows))
	}
	r := rows[0]
	if string(r.RawInput) != string(body) || r.Verdict != "CANCELLED" {
		t.Fatalf("evidence integrity broken: %+v", r)
	}
	if len(r.Events) != 2 {
		t.Fatalf("event chain lost: %d", len(r.Events))
	}
	if r.Review != nil {
		t.Fatal("review should be absent before human confirmation")
	}

	if err := store.SaveReview("E1", "alice", true, "confirmed"); err != nil {
		t.Fatal(err)
	}
	rows, _ = store.ListCases()
	if rows[0].Review == nil || !rows[0].Review.Confirmed {
		t.Fatal("human review not persisted")
	}
}

func TestParseFailureRetained(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	body := []byte("{broken")
	if err := store.RecordParseFailure("E2", "application/json", "test",
		body, callback.ErrEmptyBody); err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListCases()
	if err != nil || len(rows) != 1 || rows[0].Verdict != "DENY" {
		t.Fatalf("parse failure not retained: %v %+v", err, rows)
	}
}

func testPolicy() *callback.Policy {
	p := callback.DefaultPolicy()
	p.StateBinding["state-cancel"] = callback.StateRecord{
		SessionID: "s", Cancelled: true,
	}
	return p
}
