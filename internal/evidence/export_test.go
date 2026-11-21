package evidence

import "testing"

func TestCompare(t *testing.T) {
	vulnCode := int64(77)
	fixedReject := int64(78)
	zero := int64(0)

	got := compare(
		Run{VerdictLabel: "ROTATION_FAILURE_REPRODUCED", VerdictCode: &vulnCode},
		Run{VerdictLabel: "STALE_KEY_REJECTED", VerdictCode: &fixedReject},
		"attack")
	if !got.FixedConfirmsBug {
		t.Fatalf("attack should confirm the fix: %+v", got)
	}

	benign := compare(
		Run{VerdictLabel: "FRAME_ACCEPTED", VerdictCode: &zero},
		Run{VerdictLabel: "FRAME_ACCEPTED", VerdictCode: &zero},
		"benign")
	if benign.FixedConfirmsBug || benign.Summary == "" {
		t.Fatalf("benign comparison wrong: %+v", benign)
	}
}
