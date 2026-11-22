package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"truncstream/internal/reconcile"
	"truncstream/internal/store"
	"truncstream/internal/stream"
)

// DeterministicReport re-encodes a value with sorted keys and fixed
// indentation so two independent runs hash identically.
func DeterministicReport(v any) (string, error) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// Finalize performs reconciliation after the frame loop and persists the
// report. It must produce identical output whether or not the run was
// suspended in between.
func (p *Pipeline) Finalize(cfg Config, pa, pb stream.ParseResult) (reconcile.Report, string, error) {
	row, err := p.st.GetRun(cfg.RunID)
	if err != nil {
		return reconcile.Report{}, "", err
	}
	report, err := reconcile.Run(pa, pb)
	if err != nil {
		return reconcile.Report{}, "", err
	}
	text, err := DeterministicReport(report)
	if err != nil {
		return reconcile.Report{}, "", err
	}
	sum := sha256.Sum256([]byte(text))
	reportHash := hex.EncodeToString(sum[:])
	if _, err := p.st.SaveReport(cfg.RunID, text); err != nil {
		return reconcile.Report{}, "", err
	}
	if _, err := p.st.AddEvidence(cfg.RunID, store.EvidenceReport, []byte(reportHash)); err != nil {
		return reconcile.Report{}, "", err
	}
	if err := p.st.UpdateProgress(cfg.RunID, store.StateCompleted,
		row.TokensUsed, row.BytesUsed, row.DegradeLevel, row.LastCheckpointSeq); err != nil {
		return reconcile.Report{}, "", err
	}
	return report, reportHash, nil
}

// Diff captures the before/after comparison of an uninterrupted run versus a
// suspended-then-resumed run. Equal reports hash equal; any field drift is
// listed explicitly so a reviewer sees exactly what diverged.
type Diff struct {
	BaselineRunID  string   `json:"baseline_run_id"`
	ResumedRunID   string   `json:"resumed_run_id"`
	BaselineSHA256 string   `json:"baseline_sha256"`
	ResumedSHA256  string   `json:"resumed_sha256"`
	ReportsEqual   bool     `json:"reports_equal"`
	Differences    []string `json:"differences"`
}

// CompareReports loads two persisted reports and diffs them field by field
// using decoded values, then confirms the raw hashes.
func (p *Pipeline) CompareReports(baselineRunID, resumedRunID string) (Diff, error) {
	baseJSON, baseHash, err := p.st.GetReport(baselineRunID)
	if err != nil {
		return Diff{}, err
	}
	resJSON, resHash, err := p.st.GetReport(resumedRunID)
	if err != nil {
		return Diff{}, err
	}
	d := Diff{
		BaselineRunID:  baselineRunID,
		ResumedRunID:   resumedRunID,
		BaselineSHA256: baseHash,
		ResumedSHA256:  resHash,
		ReportsEqual:   baseHash == resHash,
		Differences:    []string{},
	}
	var base, resumed reconcile.Report
	if err := json.Unmarshal([]byte(baseJSON), &base); err != nil {
		return Diff{}, err
	}
	if err := json.Unmarshal([]byte(resJSON), &resumed); err != nil {
		return Diff{}, err
	}
	d.Differences = diffReports(base, resumed)
	diffJSON, _ := DeterministicReport(d)
	if _, err := p.st.AddEvidence(resumedRunID, store.EvidenceDiff, []byte(diffJSON)); err != nil {
		return Diff{}, err
	}
	return d, nil
}

// CompareAcrossStores diffs reports held in two separate artifacts, used by
// the demo where baseline and resumable runs use distinct SQLite files.
func CompareAcrossStores(baseStore, resumedStore *store.Store, baselineRunID, resumedRunID string) (Diff, error) {
	baseJSON, baseHash, err := baseStore.GetReport(baselineRunID)
	if err != nil {
		return Diff{}, err
	}
	resJSON, resHash, err := resumedStore.GetReport(resumedRunID)
	if err != nil {
		return Diff{}, err
	}
	d := Diff{
		BaselineRunID:  baselineRunID,
		ResumedRunID:   resumedRunID,
		BaselineSHA256: baseHash,
		ResumedSHA256:  resHash,
		ReportsEqual:   baseHash == resHash,
		Differences:    []string{},
	}
	var base, resumed reconcile.Report
	if err := json.Unmarshal([]byte(baseJSON), &base); err != nil {
		return Diff{}, err
	}
	if err := json.Unmarshal([]byte(resJSON), &resumed); err != nil {
		return Diff{}, err
	}
	d.Differences = diffReports(base, resumed)
	diffJSON, _ := DeterministicReport(d)
	if _, err := resumedStore.AddEvidence(resumedRunID, store.EvidenceDiff, []byte(diffJSON)); err != nil {
		return Diff{}, err
	}
	return d, nil
}

func diffReports(a, b reconcile.Report) []string {
	var diffs []string
	check := func(name string, same bool) {
		if !same {
			diffs = append(diffs, name+" differs")
		}
	}
	check("object_id", a.ObjectID == b.ObjectID)
	check("device_a_offset_ms", a.DeviceAOffsetMs == b.DeviceAOffsetMs)
	check("device_b_offset_ms", a.DeviceBOffsetMs == b.DeviceBOffsetMs)
	check("pair_count", a.PairCount == b.PairCount)
	check("matched_count", a.MatchedCount == b.MatchedCount)
	check("metric_mismatches", a.MetricMismatches == b.MetricMismatches)
	check("input_fingerprint", a.InputFingerprint == b.InputFingerprint)
	check("only_in_a", equalSeq(a.OnlyA, b.OnlyA))
	check("only_in_b", equalSeq(a.OnlyB, b.OnlyB))
	if len(a.Pairs) != len(b.Pairs) {
		diffs = append(diffs, "pairs length differs")
		return diffs
	}
	for i := range a.Pairs {
		if a.Pairs[i] != b.Pairs[i] {
			diffs = append(diffs, "pair["+itoa64(int64(i))+"] differs")
		}
	}
	return diffs
}

func equalSeq(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
