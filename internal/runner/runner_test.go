package runner

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		phase    string
		exit     int
		wantCode int
		wantLbl  string
	}{
		{PhaseVuln, 77, 77, LabelRotationFailure},
		{PhaseVuln, 133, 77, LabelRotationFailure},
		{PhaseVuln, 0, 0, LabelAccepted},
		{PhaseFixed, 78, 78, LabelStaleRejected},
		{PhaseFixed, 0, 0, LabelAccepted},
		{PhaseFixed, 99, 99, LabelCrashed},
	}
	for _, c := range cases {
		code, label := Classify(c.phase, c.exit)
		if code != c.wantCode || label != c.wantLbl {
			t.Fatalf("Classify(%s,%d)=(%d,%s) want (%d,%s)",
				c.phase, c.exit, code, label, c.wantCode, c.wantLbl)
		}
	}
}
