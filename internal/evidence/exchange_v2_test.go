package evidence_test

import (
	"bytes"
	"strings"
	"testing"

	"quotabypass/internal/evidence"
	"quotabypass/internal/model"
	"quotabypass/internal/quota"
)

func allRecords(t *testing.T) []model.Record {
	t.Helper()
	specs := quota.DefaultScenarios()
	records := make([]model.Record, 0, len(specs))
	for i, sc := range specs {
		records = append(records, quota.NewRunner(sc.Mode).Run(sc.Name, i, sc.Raw))
	}
	return records
}

func TestJSONLRoundTripPreservesOrderAndHash(t *testing.T) {
	records := allRecords(t)
	var buf bytes.Buffer
	if err := evidence.WriteJSONL(&buf, records); err != nil {
		t.Fatal(err)
	}
	got, err := evidence.ReadJSONL(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(records) {
		t.Fatalf("reloaded %d, want %d", len(got), len(records))
	}
	for i := range records {
		if got[i].RecordSHA256 != records[i].RecordSHA256 ||
			got[i].Ordinal != records[i].Ordinal ||
			got[i].Scenario != records[i].Scenario {
			t.Fatalf("record %d drift", i)
		}
	}
}

func TestJSONLRejectsTamperingAndReordering(t *testing.T) {
	records := allRecords(t)
	var buf bytes.Buffer
	if err := evidence.WriteJSONL(&buf, records); err != nil {
		t.Fatal(err)
	}

	tampered := bytes.ReplaceAll(buf.Bytes(),
		[]byte(`"bypass_detected":false`), []byte(`"bypass_detected":true`))
	if _, err := evidence.ReadJSONL(bytes.NewReader(tampered)); err == nil {
		t.Fatal("tampered record must be rejected")
	}

	reordered := bytes.ReplaceAll(buf.Bytes(),
		[]byte(`"scenario":`), []byte(`"zz_scenario":`))
	if _, err := evidence.ReadJSONL(bytes.NewReader(reordered)); err == nil {
		t.Fatal("field rename/order drift must be rejected")
	}

	if _, err := evidence.ReadJSONL(strings.NewReader("")); err == nil {
		t.Fatal("empty stream must be rejected")
	}
}

func TestExportFileRoundTrip(t *testing.T) {
	records := allRecords(t)
	var buf bytes.Buffer
	if err := evidence.WriteExportFile(&buf, records); err != nil {
		t.Fatal(err)
	}
	head := buf.String()
	got, err := evidence.ReadExportFile(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(records) {
		t.Fatalf("export file record count drift")
	}
	if !strings.Contains(head, `"schema": "quota-bypass.export/v1"`) {
		t.Fatalf("export schema marker missing; head=%q", head[:min(80, len(head))])
	}
}

func TestFingerprintStable(t *testing.T) {
	rec := allRecords(t)[1]
	if evidence.FingerprintRecord(rec) != rec.RecordSHA256 {
		t.Fatal("fingerprint not reproducible")
	}
	bad := rec
	bad.RecordSHA256 = "deadbeef"
	if err := evidence.VerifyRecord(bad); err == nil {
		t.Fatal("bad fingerprint must fail verification")
	}
}
