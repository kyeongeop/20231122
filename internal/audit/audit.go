package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"cacheleak.local/experiment/internal/model"
	"cacheleak.local/experiment/internal/store"
)

type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

type Totals struct {
	Scenarios      int `json:"scenarios"`
	Steps          int `json:"steps"`
	Evidence       int `json:"evidence"`
	Verifications  int `json:"verifications"`
	RepeatedGroups int `json:"repeat_groups"`
}

type Report struct {
	Schema    string    `json:"schema"`
	RunID     string    `json:"run_id"`
	OK        bool      `json:"ok"`
	CheckedAt time.Time `json:"checked_at"`
	Totals    Totals    `json:"totals"`
	Checks    []Check   `json:"checks"`
}

func Verify(ctx context.Context, dbPath, runID string) (Report, error) {
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return Report{}, err
	}
	defer st.Close()
	if runID == "" {
		runID, err = st.LatestRunID(ctx)
		if err != nil {
			return Report{}, err
		}
	}
	summary, err := st.LoadSummary(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	objects, err := st.LoadObjects(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	steps, err := st.LoadSteps(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	scenarios, err := st.LoadScenarios(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	attachSteps(scenarios, steps)
	evidence, err := st.LoadEvidence(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	cleanup, err := st.LoadCleanup(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	verifications, err := st.LoadVerifications(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	repeatCount, err := st.CountRepeatGroups(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	fuzz, err := st.LoadFuzz(ctx, runID)
	if err != nil {
		return Report{}, err
	}

	report := Report{
		Schema:    "cacheleak.audit/v1",
		RunID:     runID,
		CheckedAt: time.Now().UTC(),
		Totals: Totals{
			Scenarios: len(scenarios), Steps: len(steps), Evidence: len(evidence),
			Verifications: len(verifications), RepeatedGroups: repeatCount,
		},
	}
	add := func(name string, passed bool, detail string) {
		report.Checks = append(report.Checks, Check{Name: name, Passed: passed, Detail: detail})
	}

	add("run-completed", summary.Status == "completed", "run status: "+summary.Status)
	add("two-snapshots", len(summary.Snapshots) == 2, fmt.Sprintf("snapshots=%d", len(summary.Snapshots)))
	add("unknown-extension", checkUnknownExtension(objects), "extension .q7x must be unregistered for both snapshots")
	add("object-hashes", checkObjectHashes(objects), "SQLite BLOB SHA-256 must match stored object metadata")
	add("evidence-files", checkEvidenceFiles(evidence), "every sealed file must exist, be read-only, and match SHA-256")
	add("step-timeline", checkSteps(steps), "every step must have input, before/after state, result, and ordered UTC timestamps")
	add("scenario-counts", checkScenarioCounts(scenarios, steps), "scenario counters must match SQLite step rows")
	add("order-forward", checkOrder(scenarios, "order-forward", "snap-v1", "snap-v2"), "v1 then v2 leaks v1")
	add("order-reverse", checkOrder(scenarios, "order-reverse", "snap-v2", "snap-v1"), "v2 then v1 leaks v2")
	add("repeat-submissions", repeatCount >= 4 && checkRepeat(scenarios), "duplicate submissions must stay HIT and deterministic")
	add("error-continuation", checkErrorContinuation(scenarios), "step after injected 404 must still run")
	add("recorded-verifications", allVerificationsPassed(verifications), "all SQLite verification rows must pass")
	add("cleanup-receipts", checkCleanup(cleanup), "cleanup rows must report no remaining path")
	add("temporary-state-absent", !anyPathExists(scenarioTempPaths(scenarios)), "all scenario temp roots must be gone")
	add("libfuzzer-artifact", checkFuzz(fuzz), "fuzzer log and crash artifact must be sealed and match hashes")

	report.OK = true
	for _, check := range report.Checks {
		if !check.Passed {
			report.OK = false
		}
	}
	return report, nil
}

func checkUnknownExtension(objects []model.StoredObject) bool {
	seen := map[string]bool{}
	for _, obj := range objects {
		if obj.Extension == model.UnknownExt {
			if obj.KnownExtension || obj.MIME != model.UnknownMIME {
				return false
			}
			seen[obj.SnapshotID] = true
		}
	}
	return seen["snap-v1"] && seen["snap-v2"]
}

func checkObjectHashes(objects []model.StoredObject) bool {
	if len(objects) < 5 {
		return false
	}
	for _, obj := range objects {
		sum := sha256.Sum256(obj.Body)
		if hex.EncodeToString(sum[:]) != obj.SHA256 || int64(len(obj.Body)) != obj.Size {
			return false
		}
	}
	return true
}

func checkEvidenceFiles(evidence []model.Evidence) bool {
	if len(evidence) < 10 {
		return false
	}
	for _, ev := range evidence {
		info, err := os.Stat(ev.Path)
		if err != nil || info.Size() != ev.Size || info.Mode().Perm()&0o222 != 0 {
			return false
		}
		sum, size, err := hashFile(ev.Path)
		if err != nil || sum != ev.SHA256 || size != ev.Size {
			return false
		}
	}
	return true
}

func checkSteps(steps []model.Step) bool {
	if len(steps) < 20 {
		return false
	}
	for _, step := range steps {
		if step.StartedAt.IsZero() || step.FinishedAt.Before(step.StartedAt) ||
			step.Input.Method == "" || step.Input.Path == "" ||
			step.StateBefore.Cache == nil || step.StateAfter.Cache == nil ||
			step.Result.StatusCode == 0 || step.Result.CacheStatus == "" ||
			step.EvidenceID == "" {
			return false
		}
	}
	return true
}

func checkScenarioCounts(scenarios []model.ScenarioResult, steps []model.Step) bool {
	if len(scenarios) != 5 {
		return false
	}
	byScenario := map[string]int{}
	for _, step := range steps {
		byScenario[step.ScenarioID]++
	}
	for _, scenario := range scenarios {
		if byScenario[scenario.ID] != scenario.StepCount || scenario.StepCount == 0 {
			return false
		}
	}
	return true
}

func checkOrder(scenarios []model.ScenarioResult, name, first, second string) bool {
	scenario, ok := findScenario(scenarios, name)
	if !ok {
		return false
	}
	one, okOne := findStep(scenario.Steps, 1)
	two, okTwo := findStep(scenario.Steps, 2)
	return okOne && okTwo &&
		one.Status == "ok" && one.CacheStatus == "MISS" && one.Served == first && !one.Leaked &&
		two.Status == "ok" && two.CacheStatus == "HIT" && two.Served == first &&
		two.Leaked && one.BodySHA256 == two.BodySHA256
}

func checkRepeat(scenarios []model.ScenarioResult) bool {
	for _, name := range []string{"order-forward", "order-reverse"} {
		scenario, ok := findScenario(scenarios, name)
		if !ok {
			return false
		}
		hash := ""
		count := 0
		for _, step := range scenario.Steps {
			if step.Ordinal < 2 {
				continue
			}
			if step.CacheStatus != "HIT" {
				return false
			}
			if hash == "" {
				hash = step.BodySHA256
			} else if hash != step.BodySHA256 {
				return false
			}
			count++
		}
		if count < 2 {
			return false
		}
	}
	return true
}

func checkErrorContinuation(scenarios []model.ScenarioResult) bool {
	scenario, ok := findScenario(scenarios, "error-continuation")
	if !ok {
		return false
	}
	bad, ok := findStep(scenario.Steps, 3)
	if !ok || bad.Status != "error" || bad.CacheStatus != "ERROR" {
		return false
	}
	after := 0
	for _, step := range scenario.Steps {
		if step.Ordinal > 3 {
			if step.Status != "ok" {
				return false
			}
			after++
		}
	}
	return after == 3
}

func allVerificationsPassed(verifications []model.Verification) bool {
	if len(verifications) < 6 {
		return false
	}
	for _, v := range verifications {
		if !v.Passed {
			return false
		}
	}
	return true
}

func checkCleanup(cleanup []model.CleanupRecord) bool {
	if len(cleanup) < 2 {
		return false
	}
	for _, record := range cleanup {
		if record.Status != "ok" || record.ExistsAfter {
			return false
		}
	}
	return true
}

func checkFuzz(fuzz *model.FuzzResult) bool {
	if fuzz == nil || fuzz.Status != "completed" || !fuzz.Found ||
		fuzz.ArtifactPath == "" || fuzz.LogPath == "" {
		return false
	}
	artifactSum, _, err := hashFile(fuzz.ArtifactPath)
	if err != nil || artifactSum != fuzz.ArtifactSHA {
		return false
	}
	logSum, _, err := hashFile(fuzz.LogPath)
	return err == nil && logSum == fuzz.LogSHA256
}

func findScenario(scenarios []model.ScenarioResult, name string) (model.ScenarioResult, bool) {
	for _, scenario := range scenarios {
		if scenario.Name == name {
			return scenario, true
		}
	}
	return model.ScenarioResult{}, false
}

func findStep(steps []model.StepSummary, ordinal int) (model.StepSummary, bool) {
	for _, step := range steps {
		if step.Ordinal == ordinal {
			return step, true
		}
	}
	return model.StepSummary{}, false
}

func scenarioTempPaths(scenarios []model.ScenarioResult) []string {
	paths := make([]string, 0, len(scenarios))
	for _, scenario := range scenarios {
		paths = append(paths, scenario.TempPath)
	}
	return paths
}

func anyPathExists(paths []string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func attachSteps(scenarios []model.ScenarioResult, steps []model.Step) {
	byScenario := make(map[string][]model.StepSummary)
	for _, step := range steps {
		byScenario[step.ScenarioID] = append(byScenario[step.ScenarioID], model.StepSummary{
			Ordinal: step.Ordinal, Status: step.Status, CacheStatus: step.Result.CacheStatus,
			Served: step.Result.ServedSnapshot, BodySHA256: step.Result.BodySHA256,
			Leaked: step.Result.Leaked, EvidenceID: step.EvidenceID, ErrorMessage: step.ErrorText,
		})
	}
	for index := range scenarios {
		scenarios[index].Steps = byScenario[scenarios[index].ID]
	}
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	h := sha256.New()
	size, err := io.Copy(h, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

func ResolveDB(workspace, explicit string) string {
	if explicit != "" {
		return explicit
	}
	return filepath.Join(workspace, "evidence.db")
}
