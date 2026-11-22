package experiment

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"cacheleak.local/experiment/internal/model"
	"cacheleak.local/experiment/internal/store"
)

type Options struct {
	Workspace string
	RunID     string
	FuzzMode  string
	FuzzRuns  int
	ClangXX   string
}

func DefaultOptions() Options {
	return Options{
		Workspace: "evidence",
		FuzzMode:  "auto",
		FuzzRuns:  2000,
	}
}

type runner struct {
	opts     Options
	runID    string
	store    *store.Store
	evidence *EvidenceManager
	fixture  Fixture
	summary  model.RunSummary
	tempBase string
}

func Run(ctx context.Context, opts Options) (model.RunSummary, error) {
	opts, root, runID, err := normalizeOptions(opts)
	if err != nil {
		return model.RunSummary{}, err
	}
	evidenceDir := filepath.Join(root, "evidence", runID)
	tempBase := filepath.Join(root, ".tmp", runID)
	dbPath := filepath.Join(root, "evidence.db")
	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		return model.RunSummary{}, fmt.Errorf("create evidence directory: %w", err)
	}
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return model.RunSummary{}, err
	}
	defer st.Close()

	r := &runner{
		opts:     opts,
		runID:    runID,
		store:    st,
		evidence: NewEvidenceManager(runID, evidenceDir, st),
		fixture:  NewFixture(),
		tempBase: tempBase,
		summary: model.RunSummary{
			Schema:          model.SchemaVersion,
			ID:              runID,
			Status:          "running",
			StartedAt:       time.Now().UTC(),
			DBPath:          dbPath,
			EvidenceDir:     evidenceDir,
			UnknownExt:      model.UnknownExt,
			KeyEvidencePath: filepath.Join(evidenceDir, "manifest.json"),
		},
	}
	if err := st.BeginRun(ctx, runID, dbPath, evidenceDir, r.publicOptions(), r.summary.StartedAt); err != nil {
		return model.RunSummary{}, err
	}
	defer cleanupBestEffort(tempBase)

	runErr := r.execute(ctx)
	finishAt := time.Now().UTC()
	if runErr != nil {
		r.summary.Status = "failed"
		r.summary.FinishedAt = finishAt
		_ = st.FinishRun(context.Background(), runID, "failed", r.summary, finishAt)
		return r.summary, runErr
	}
	r.summary.Status = "completed"
	r.summary.FinishedAt = finishAt
	r.summary.EvidenceCount = len(r.evidence.Records()) + 2
	r.summary.TempPathsLeft = countExisting([]string{tempBase, filepath.Dir(tempBase)})
	report, err := r.evidence.WriteJSON(ctx, "report", "report", "Replayable experiment report", r.summary)
	if err != nil {
		return r.summary, err
	}
	r.summary.KeyEvidencePath = report.Path
	if _, err := r.evidence.WriteManifest(ctx, map[string]any{
		"unknown_extension": model.UnknownExt,
		"run_status":        r.summary.Status,
		"report_sha256":     report.SHA256,
	}); err != nil {
		return r.summary, err
	}
	r.summary.EvidenceCount = len(r.evidence.Records())
	r.summary.KeyEvidencePath = filepath.Join(evidenceDir, "manifest.json")
	r.summary.FinishedAt = time.Now().UTC()
	if err := st.FinishRun(ctx, runID, "completed", r.summary, r.summary.FinishedAt); err != nil {
		return r.summary, err
	}
	return r.summary, nil
}

func (r *runner) execute(ctx context.Context) error {
	for _, snap := range r.fixture.Snapshots {
		if err := r.store.AddSnapshot(ctx, r.runID, snap); err != nil {
			return fmt.Errorf("store snapshot %s: %w", snap.ID, err)
		}
	}
	for _, obj := range r.fixture.Objects {
		if err := r.store.AddObject(ctx, r.runID, obj); err != nil {
			return fmt.Errorf("store object %s: %w", obj.Key, err)
		}
		if _, err := r.evidence.WriteBytes(ctx, "raw-"+obj.Key, "raw-object",
			"Original bytes from "+obj.SnapshotID, safeName(obj.Key)+".bin", obj.Body); err != nil {
			return err
		}
	}
	if _, err := r.evidence.WriteJSON(ctx, "snapshot-catalog", "snapshot-catalog",
		"Two immutable version snapshots used as controls", map[string]any{
			"snapshots":         r.fixture.Snapshots,
			"objects":           publicObjects(r.fixture.Objects),
			"unknown_extension": model.UnknownExt,
		}); err != nil {
		return err
	}

	plans := NewPlans()
	for _, plan := range plans {
		res, err := r.runScenario(ctx, plan)
		if err != nil {
			res.Status = "failed"
			res.ErrorDetail = err.Error()
			res.FinishedAt = time.Now().UTC()
			_ = r.store.UpdateScenario(context.Background(), res)
		}
		r.summary.Scenarios = append(r.summary.Scenarios, res)
	}
	r.summary.Snapshots = r.fixture.Snapshots
	r.summary.Objects = append([]model.StoredObject(nil), r.fixture.Objects...)

	if err := r.verifyResults(ctx); err != nil {
		return err
	}
	fuzzResult, err := RunLibFuzzer(ctx, r.opts, r.runID, r.tempBase, r.evidence)
	if err != nil {
		return err
	}
	r.summary.Fuzz = fuzzResult
	if err := r.store.AddFuzz(ctx, r.runID, *fuzzResult); err != nil {
		return err
	}
	if err := r.verifyFuzz(ctx, fuzzResult); err != nil {
		return err
	}
	if err := r.cleanupTemp(ctx); err != nil {
		return err
	}
	return nil
}

func (r *runner) runScenario(ctx context.Context, plan model.ScenarioPlan) (model.ScenarioResult, error) {
	scenarioID := "sc-" + r.runID + "-" + safeName(plan.Name)
	scenarioRoot := filepath.Join(r.tempBase, safeName(plan.Name))
	res := model.ScenarioResult{
		ID:        scenarioID,
		Name:      plan.Name,
		Order:     plan.Order,
		Status:    "running",
		TempPath:  scenarioRoot,
		StartedAt: time.Now().UTC(),
	}
	if err := r.store.AddScenario(ctx, r.runID, plan, res); err != nil {
		return res, fmt.Errorf("add scenario %s: %w", plan.Name, err)
	}
	snapshots, err := r.fixture.Materialize(scenarioRoot)
	if err != nil {
		res.FinishedAt = time.Now().UTC()
		return res, fmt.Errorf("materialize scenario %s: %w", plan.Name, err)
	}
	harness := NewHarness(scenarioRoot, snapshots)
	if plan.ResetCache {
		harness.Cache.Clear()
	}

	for index, spec := range plan.Requests {
		ordinal := index + 1
		step := model.Step{
			RunID:      r.runID,
			ScenarioID: scenarioID,
			Ordinal:    ordinal,
			ObjectKey:  spec.ObjectKey,
			Phase:      "request",
			Input: model.RequestInput{
				Method:     spec.Method,
				Path:       spec.Path,
				SnapshotID: spec.SnapshotID,
				Headers: map[string]string{
					"X-Snapshot": spec.SnapshotID,
				},
				Submit:   spec.Submit,
				RepeatOf: spec.RepeatOf,
			},
			StartedAt: time.Now().UTC(),
		}
		step.Input.Headers["X-Object-SHA256"] = objectSHA(r.fixture.Objects, spec.SnapshotID, spec.Path)
		outcome := safeServe(harness, step.Input)
		step.StateBefore = outcome.Before
		step.StateAfter = outcome.After
		step.Result = outcome.Result
		step.FinishedAt = time.Now().UTC()
		step.Status = "ok"
		if outcome.Error != nil || outcome.Result.Error != "" {
			step.Status = "error"
			step.ErrorText = outcome.Result.Error
			res.ErrorCount++
		} else if outcome.Result.Leaked {
			res.LeakCount++
		}
		ev, err := r.evidence.WriteJSON(ctx,
			fmt.Sprintf("step-%s-%02d", plan.Name, ordinal),
			"step",
			fmt.Sprintf("Input, state, and result for %s step %d", plan.Name, ordinal),
			step)
		if err != nil {
			return res, err
		}
		step.EvidenceID = ev.ID
		if err := r.store.AddStep(ctx, step); err != nil {
			return res, fmt.Errorf("store step %s/%d: %w", plan.Name, ordinal, err)
		}
		res.Steps = append(res.Steps, model.StepSummary{
			Ordinal:      step.Ordinal,
			Status:       step.Status,
			CacheStatus:  step.Result.CacheStatus,
			Served:       step.Result.ServedSnapshot,
			BodySHA256:   step.Result.BodySHA256,
			Leaked:       step.Result.Leaked,
			EvidenceID:   step.EvidenceID,
			ErrorMessage: step.ErrorText,
		})
	}
	res.StepCount = len(res.Steps)
	res.FinishedAt = time.Now().UTC()
	res.Status = "completed"
	if res.ErrorCount > 0 {
		res.Status = "completed-with-errors"
	}
	if err := r.store.UpdateScenario(ctx, res); err != nil {
		return res, err
	}
	return res, nil
}

func safeServe(harness *Harness, input model.RequestInput) (outcome ServeOutcome) {
	defer func() {
		if recovered := recover(); recovered != nil {
			outcome.Error = fmt.Errorf("panic while serving %s: %v", input.Path, recovered)
			outcome.Result.StatusCode = 500
			outcome.Result.CacheStatus = "ERROR"
			outcome.Result.Error = outcome.Error.Error()
			outcome.Before = harness.Cache.State(input.SnapshotID, harness.TempRoot)
			outcome.After = outcome.Before
		}
	}()
	return harness.Serve(input)
}

func (r *runner) publicOptions() map[string]any {
	return map[string]any{
		"schema":            model.SchemaVersion,
		"unknown_extension": model.UnknownExt,
		"fuzz_mode":         r.opts.FuzzMode,
		"fuzz_runs":         r.opts.FuzzRuns,
		"cache_key":         "METHOD + canonical request path (snapshot/version omitted)",
		"cleanup":           true,
	}
}

func normalizeOptions(opts Options) (Options, string, string, error) {
	if opts.Workspace == "" {
		opts.Workspace = "evidence"
	}
	if opts.FuzzMode == "" {
		opts.FuzzMode = "auto"
	}
	if opts.FuzzRuns <= 0 {
		opts.FuzzRuns = 2000
	}
	root, err := filepath.Abs(opts.Workspace)
	if err != nil {
		return opts, "", "", err
	}
	var random [4]byte
	if _, err := rand.Read(random[:]); err != nil {
		return opts, "", "", err
	}
	runID := opts.RunID
	if runID == "" {
		runID = "run-" + time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(random[:])
	}
	runID = safeName(runID)
	if runID == "" {
		return opts, "", "", fmt.Errorf("run id is empty after sanitization")
	}
	return opts, root, runID, nil
}

func publicObjects(objects []model.StoredObject) []map[string]any {
	out := make([]map[string]any, 0, len(objects))
	for _, obj := range objects {
		out = append(out, map[string]any{
			"key": obj.Key, "snapshot_id": obj.SnapshotID, "version": obj.Version,
			"logical_path": obj.LogicalPath, "extension": obj.Extension,
			"known_extension": obj.KnownExtension, "mime": obj.MIME,
			"size": obj.Size, "sha256": obj.SHA256, "captured_at": obj.CapturedAt,
		})
	}
	return out
}

func objectSHA(objects []model.StoredObject, snapshotID, logicalPath string) string {
	for _, obj := range objects {
		if obj.SnapshotID == snapshotID && obj.LogicalPath == logicalPath {
			return obj.SHA256
		}
	}
	return ""
}

func countExisting(paths []string) int {
	count := 0
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			count++
		}
	}
	return count
}

func cleanupBestEffort(tempBase string) {
	_ = os.RemoveAll(tempBase)
	_ = os.Remove(filepath.Dir(tempBase))
}

func scenarioByName(summary model.RunSummary, name string) (model.ScenarioResult, bool) {
	for _, scenario := range summary.Scenarios {
		if scenario.Name == name {
			return scenario, true
		}
	}
	return model.ScenarioResult{}, false
}

func stepAt(scenario model.ScenarioResult, ordinal int) (model.StepSummary, bool) {
	for _, step := range scenario.Steps {
		if step.Ordinal == ordinal {
			return step, true
		}
	}
	return model.StepSummary{}, false
}
