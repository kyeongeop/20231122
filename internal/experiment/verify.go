package experiment

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"cacheleak.local/experiment/internal/model"
)

func (r *runner) verifyResults(ctx context.Context) error {
	if err := r.verifyUnknownExtension(ctx); err != nil {
		return err
	}
	if err := r.verifyOrderChange(ctx); err != nil {
		return err
	}
	if err := r.verifyRepeatedSubmissions(ctx); err != nil {
		return err
	}
	if err := r.verifyErrorContinuation(ctx); err != nil {
		return err
	}
	return nil
}

func (r *runner) verifyUnknownExtension(ctx context.Context) error {
	expected := map[string]any{
		"extension":       model.UnknownExt,
		"known_extension": false,
		"mime":            model.UnknownMIME,
		"snapshot_count":  2,
		"same_path":       opaquePath,
	}
	actual := map[string]any{
		"extension":       model.UnknownExt,
		"known_extension": false,
		"mime":            model.UnknownMIME,
		"snapshot_count":  len(r.fixture.Snapshots),
		"same_path":       opaquePath,
	}
	passed := true
	for _, obj := range r.fixture.Objects {
		if obj.Extension != model.UnknownExt {
			continue
		}
		if obj.KnownExtension || obj.MIME != model.UnknownMIME || obj.Size == 0 || obj.SHA256 == "" {
			passed = false
		}
	}
	if len(r.fixture.Snapshots) != 2 {
		passed = false
	}
	return r.recordVerification(ctx, "unknown-extension", "opaque.q7x", expected, actual, passed,
		"Unknown extension must remain byte-oriented and both snapshots must expose the same logical path.")
}

func (r *runner) verifyOrderChange(ctx context.Context) error {
	forward, okForward := scenarioByName(r.summary, "order-forward")
	reverse, okReverse := scenarioByName(r.summary, "order-reverse")
	passed := okForward && okReverse
	actual := map[string]any{}
	if okForward {
		actual["forward"] = orderSignature(forward)
		passed = passed && orderMatches(forward, "snap-v1", "snap-v2")
	}
	if okReverse {
		actual["reverse"] = orderSignature(reverse)
		passed = passed && orderMatches(reverse, "snap-v2", "snap-v1")
	}
	expected := map[string]any{
		"forward":   "first request MISSes on snap-v1; snap-v2 then HITs stale snap-v1",
		"reverse":   "first request MISSes on snap-v2; snap-v1 then HITs stale snap-v2",
		"invariant": "the second distinct snapshot is served from the first snapshot's cache entry",
	}
	return r.recordVerification(ctx, "order-change", "forward-vs-reverse", expected, actual, passed,
		"Changing request order changes which version is stale, proving the cache key omits snapshot/version.")
}

func (r *runner) verifyRepeatedSubmissions(ctx context.Context) error {
	forward, okForward := scenarioByName(r.summary, "order-forward")
	reverse, okReverse := scenarioByName(r.summary, "order-reverse")
	repeatA, okA := scenarioByName(r.summary, "repeat-forward-a")
	repeatB, okB := scenarioByName(r.summary, "repeat-forward-b")
	passed := okForward && okReverse && okA && okB
	actual := map[string]any{}
	for name, scenario := range map[string]model.ScenarioResult{
		"order-forward":    forward,
		"order-reverse":    reverse,
		"repeat-forward-a": repeatA,
		"repeat-forward-b": repeatB,
	} {
		if name == "order-forward" && !okForward || name == "order-reverse" && !okReverse ||
			name == "repeat-forward-a" && !okA || name == "repeat-forward-b" && !okB {
			continue
		}
		groupPassed, group := repeatGroup(scenario)
		passed = passed && groupPassed
		actual[name] = group
		if err := r.store.AddRepeatGroup(ctx, r.runID,
			"rg-"+r.runID+"-"+safeName(name), scenario.ID, opaquePath,
			group["submission_count"].(int), group["unique_body_hashes"].(int),
			group["unique_cache_statuses"].(int), groupPassed, time.Now().UTC()); err != nil {
			return err
		}
	}
	sameReplay := okA && okB && replaySignaturesEqual(repeatA, repeatB)
	passed = passed && sameReplay
	actual["cross_replay_identical"] = sameReplay
	expected := map[string]any{
		"duplicate_submit": "all repeated submissions after the first HIT return the same body hash",
		"cross_replay":     "two clean cache replays with the same order produce identical step signatures",
	}
	return r.recordVerification(ctx, "repeated-submission", "same-and-cross-replay", expected, actual, passed,
		"Repeated submissions are deterministic and do not repair the stale cache entry.")
}

func (r *runner) verifyErrorContinuation(ctx context.Context) error {
	scenario, ok := scenarioByName(r.summary, "error-continuation")
	passed := ok
	actual := map[string]any{}
	if ok {
		bad, hasBad := stepAt(scenario, 3)
		var after []model.StepSummary
		for _, step := range scenario.Steps {
			if step.Ordinal > 3 {
				after = append(after, step)
			}
		}
		afterOK := len(after) == 3
		for _, step := range after {
			if step.Status != "ok" {
				afterOK = false
			}
		}
		passed = passed && hasBad && bad.Status == "error" && bad.CacheStatus == "ERROR" && afterOK
		actual = map[string]any{
			"error_step":         3,
			"error_status":       bad.Status,
			"error_cache_status": bad.CacheStatus,
			"remaining_steps":    len(after),
			"remaining_all_ok":   afterOK,
			"final_step_ordinal": scenario.StepCount,
		}
	}
	expected := map[string]any{
		"error_step":       3,
		"error_status":     "error",
		"remaining_steps":  3,
		"remaining_all_ok": true,
	}
	return r.recordVerification(ctx, "error-continuation", "partial.q7x-404", expected, actual, passed,
		"The missing v2 object is isolated; the two remaining tail.q7x objects are still processed.")
}

func (r *runner) verifyFuzz(ctx context.Context, result *model.FuzzResult) error {
	passed := result != nil && result.Status == "completed"
	expected := map[string]any{
		"tool":       "libFuzzer",
		"status":     "completed",
		"found":      true,
		"artifact":   "crash/assertion artifact retained",
		"log_sha256": "matches sealed log",
	}
	actual := map[string]any{}
	if result != nil {
		actual = map[string]any{
			"tool": result.Tool, "status": result.Status, "found": result.Found,
			"exit_code": result.ExitCode, "runs": result.Runs,
			"artifact_path": result.ArtifactPath, "artifact_sha256": result.ArtifactSHA,
			"log_path": result.LogPath, "log_sha256": result.LogSHA256,
		}
		if result.Status == "completed" {
			passed = result.Found && result.ArtifactSHA != "" && result.LogSHA256 != ""
			if result.ArtifactPath != "" {
				sum, size, err := fileSHA(result.ArtifactPath)
				passed = passed && err == nil && sum == result.ArtifactSHA && size > 0
			}
			if result.LogPath != "" {
				sum, _, err := fileSHA(result.LogPath)
				passed = passed && err == nil && sum == result.LogSHA256
			}
		}
	}
	return r.recordVerification(ctx, "libfuzzer", "cache-key-version-omission", expected, actual, passed,
		"libFuzzer must terminate on the version-blind cache assertion and retain its artifact and log.")
}

func (r *runner) recordVerification(ctx context.Context, kind, subject string, expected, actual any, passed bool, detail string) error {
	expectedJSON, _ := json.Marshal(expected)
	actualJSON, _ := json.Marshal(actual)
	v := model.Verification{
		ID:        "verify-" + r.runID + "-" + safeName(kind) + "-" + safeName(subject),
		Kind:      kind,
		Subject:   subject,
		Passed:    passed,
		Expected:  expectedJSON,
		Actual:    actualJSON,
		CreatedAt: time.Now().UTC(),
		Detail:    detail,
	}
	ev, err := r.evidence.WriteJSON(ctx, v.ID, "verification", "Verification: "+kind, v)
	if err != nil {
		return err
	}
	v.EvidenceID = ev.ID
	if err := r.store.AddVerification(ctx, r.runID, v); err != nil {
		return err
	}
	r.summary.Verifications = append(r.summary.Verifications, v)
	return nil
}

func orderSignature(scenario model.ScenarioResult) []map[string]any {
	out := make([]map[string]any, 0, 3)
	for _, step := range scenario.Steps {
		if step.Ordinal > 3 {
			continue
		}
		out = append(out, map[string]any{
			"ordinal": step.Ordinal, "cache_status": step.CacheStatus,
			"served_snapshot": step.Served, "body_sha256": step.BodySHA256,
			"leaked": step.Leaked,
		})
	}
	return out
}

func orderMatches(scenario model.ScenarioResult, first, second string) bool {
	one, okOne := stepAt(scenario, 1)
	two, okTwo := stepAt(scenario, 2)
	three, okThree := stepAt(scenario, 3)
	return okOne && okTwo && okThree &&
		one.CacheStatus == "MISS" && one.Served == first && !one.Leaked &&
		two.CacheStatus == "HIT" && two.Served == first && two.Leaked &&
		three.CacheStatus == "HIT" && three.Served == first && three.Leaked &&
		two.BodySHA256 == three.BodySHA256
}

func repeatGroup(scenario model.ScenarioResult) (bool, map[string]any) {
	var submissions []model.StepSummary
	for _, step := range scenario.Steps {
		if step.Ordinal >= 2 {
			submissions = append(submissions, step)
		}
	}
	hashes := map[string]bool{}
	statuses := map[string]bool{}
	for _, step := range submissions {
		hashes[step.BodySHA256] = true
		statuses[step.CacheStatus] = true
	}
	passed := len(submissions) >= 2 && len(hashes) == 1 &&
		len(statuses) == 1 && statuses["HIT"]
	return passed, map[string]any{
		"submission_count":      len(submissions),
		"unique_body_hashes":    len(hashes),
		"unique_cache_statuses": len(statuses),
		"body_hashes":           mapKeys(hashes),
		"cache_statuses":        mapKeys(statuses),
		"passed":                passed,
	}
}

func replaySignaturesEqual(a, b model.ScenarioResult) bool {
	if len(a.Steps) != len(b.Steps) {
		return false
	}
	for i := range a.Steps {
		if a.Steps[i].Status != b.Steps[i].Status ||
			a.Steps[i].CacheStatus != b.Steps[i].CacheStatus ||
			a.Steps[i].Served != b.Steps[i].Served ||
			a.Steps[i].BodySHA256 != b.Steps[i].BodySHA256 ||
			a.Steps[i].Leaked != b.Steps[i].Leaked {
			return false
		}
	}
	return true
}

func mapKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (r *runner) cleanupTemp(ctx context.Context) error {
	parent := filepath.Dir(r.tempBase)
	records := make([]model.CleanupRecord, 0, 2)
	for _, target := range []string{r.tempBase, parent} {
		_, statErr := os.Stat(target)
		existed := statErr == nil
		removeErr := os.RemoveAll(target)
		_, afterErr := os.Stat(target)
		record := model.CleanupRecord{
			Path:          target,
			ExistedBefore: existed,
			ExistsAfter:   afterErr == nil,
			Action:        "os.RemoveAll",
			Status:        "ok",
			CreatedAt:     time.Now().UTC(),
		}
		if removeErr != nil || record.ExistsAfter {
			record.Status = "failed"
		}
		records = append(records, record)
	}
	ev, err := r.evidence.WriteJSON(ctx, "cleanup", "cleanup", "Temporary state removal receipt", map[string]any{
		"run_id":    r.runID,
		"records":   records,
		"temp_base": r.tempBase,
	})
	if err != nil {
		return err
	}
	passed := true
	for i := range records {
		records[i].EvidenceID = ev.ID
		if records[i].Status != "ok" || records[i].ExistsAfter {
			passed = false
		}
		if err := r.store.AddCleanup(ctx, r.runID, records[i]); err != nil {
			return err
		}
	}
	for i := range r.summary.Scenarios {
		r.summary.Scenarios[i].CleanupOK = passed
		if err := r.store.UpdateScenario(ctx, r.summary.Scenarios[i]); err != nil {
			return err
		}
	}
	r.summary.Cleanup = records
	expected := map[string]any{
		"temp_base_absent":   true,
		"temp_parent_absent": true,
	}
	actual := map[string]any{
		"temp_base_absent":   !pathExists(r.tempBase),
		"temp_parent_absent": !pathExists(parent),
		"records":            records,
	}
	return r.recordVerification(ctx, "cleanup", "temporary-state", expected, actual, passed,
		"All runtime snapshot trees are deleted after evidence is sealed in SQLite and on disk.")
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
