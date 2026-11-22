package record

import "testing"

func TestParseV1(t *testing.T) {
	r, err := Parse([]byte(`{"id":"r1","subject":"alice","action":"read","payload":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.Format != FormatV1 || r.ID != "r1" || r.Subject != "alice" || r.Action != "read" {
		t.Fatalf("bad v1 normalize: %+v", r)
	}
}

func TestParseV2(t *testing.T) {
	r, err := Parse([]byte(`{"version":2,"record_id":"r2","principal":"bob","op":"write","body":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.Format != FormatV2 || r.ID != "r2" || r.Subject != "bob" || r.Action != "write" {
		t.Fatalf("bad v2 normalize: %+v", r)
	}
}

func TestParseMissingFields(t *testing.T) {
	if _, err := Parse([]byte(`{"id":"r1"}`)); err == nil {
		t.Fatal("want error for v1 without action")
	}
	if _, err := Parse([]byte(`{"version":2,"record_id":"r2"}`)); err == nil {
		t.Fatal("want error for v2 without op")
	}
}

func TestJudge(t *testing.T) {
	if got := Judge(Record{Action: "read"}); got != Allow {
		t.Fatalf("read should be allowed, got %s", got)
	}
	if got := Judge(Record{Action: "delete"}); got != DenyPolicy {
		t.Fatalf("delete should be denied, got %s", got)
	}
}
