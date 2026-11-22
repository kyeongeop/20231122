package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"apiskew.local/apiskew/internal/domain"
	"apiskew.local/apiskew/internal/fuzzrun"
	"apiskew.local/apiskew/internal/store"
)

type DiscoverOptions struct {
	SessionID   string
	Fuzzer      string
	WorkDir     string
	Seconds     int
	MaxFindings int
	Seed        []byte
}

type DiscoverResult struct {
	Fuzzer         fuzzrun.Result `json:"fuzzer"`
	Imported       int            `json:"imported"`
	Duplicates     int            `json:"duplicates"`
	FalsePositives int            `json:"false_positives"`
	Invalid        int            `json:"invalid"`
	SampleIDs      []string       `json:"sample_ids"`
	Status         string         `json:"status"`
}

type ReplayOptions struct {
	SessionID string
	SampleID  string
	Engine    string
	Fuzzer    string
	WorkDir   string
	Repeat    int
}

type ReplayResult struct {
	SessionID string       `json:"session_id"`
	Runs      []ReplayItem `json:"runs"`
}

type ReplayItem struct {
	SampleID             string   `json:"sample_id"`
	Ordinal              int      `json:"ordinal"`
	Attempt              int      `json:"attempt"`
	Engine               string   `json:"engine"`
	Status               string   `json:"status"`
	V1Allow              bool     `json:"v1_allow"`
	V2Allow              bool     `json:"v2_allow"`
	PermissionDifference bool     `json:"permission_difference"`
	Comparable           bool     `json:"comparable"`
	EvidenceSHA256       string   `json:"evidence_sha256"`
	DriftFields          []string `json:"drift_fields,omitempty"`
}

type CompareResult struct {
	SessionID string          `json:"session_id"`
	Samples   []SampleCompare `json:"samples"`
}

type SampleCompare struct {
	SampleID             string   `json:"sample_id"`
	Ordinal              int      `json:"ordinal"`
	Attempts             int      `json:"attempts"`
	FirstAttempt         int      `json:"first_attempt"`
	LatestAttempt        int      `json:"latest_attempt"`
	V1Allow              bool     `json:"v1_allow"`
	V2Allow              bool     `json:"v2_allow"`
	PermissionDifference bool     `json:"permission_difference"`
	DriftFields          []string `json:"drift_fields"`
	Stable               bool     `json:"stable"`
	EvidenceSHA256       string   `json:"evidence_sha256"`
}

type FixResult struct {
	SessionID      string          `json:"session_id"`
	SampleID       string          `json:"sample_id"`
	InputSHA256    string          `json:"sample_sha256"`
	EvidenceSHA256 string          `json:"evidence_sha256"`
	StableRuns     int             `json:"stable_runs"`
	Evidence       domain.Evidence `json:"evidence"`
	Plan           domain.FixPlan  `json:"fix_plan"`
}

func Discover(ctx context.Context, st *store.Store, options DiscoverOptions) (DiscoverResult, error) {
	session, err := st.GetSession(ctx, options.SessionID)
	if err != nil {
		return DiscoverResult{}, err
	}
	_ = st.AddEvent(ctx, session.ID, "", "discover_started", struct {
		Fuzzer  string `json:"fuzzer"`
		WorkDir string `json:"work_dir"`
		Seconds int    `json:"seconds"`
	}{options.Fuzzer, options.WorkDir, options.Seconds})

	fuzzerResult, fuzzerErr := fuzzrun.Run(ctx, fuzzrun.Options{
		Binary:       options.Fuzzer,
		WorkDir:      options.WorkDir,
		Seconds:      options.Seconds,
		Scenario:     session.Scenario,
		Seed:         options.Seed,
		FindingLimit: options.MaxFindings,
	})
	importCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	status := "paused"
	if err := st.SetSessionStatus(importCtx, session.ID, status); err != nil {
		return DiscoverResult{}, err
	}
	result, importErr := importFindings(importCtx, st, session, fuzzerResult, options.MaxFindings)
	if importErr != nil {
		return result, importErr
	}
	result.Fuzzer = fuzzerResult
	result.Status = status
	if ctx.Err() != nil || fuzzerResult.Interrupted {
		reason := "fuzzer interrupted"
		if ctx.Err() != nil {
			reason = ctx.Err().Error()
		}
		_ = st.AddEvent(importCtx, session.ID, "", "discover_interrupted", struct {
			Reason      string `json:"reason"`
			Imported    int    `json:"imported"`
			FindingsDir string `json:"findings_dir"`
			CorpusDir   string `json:"corpus_dir"`
		}{reason, result.Imported, fuzzerResult.FindingsDir, fuzzerResult.CorpusDir})
	}
	_ = st.AddEvent(importCtx, session.ID, "", "discover_checkpoint", struct {
		Imported       int      `json:"imported"`
		Duplicates     int      `json:"duplicates"`
		FalsePositives int      `json:"false_positives"`
		Invalid        int      `json:"invalid"`
		SampleIDs      []string `json:"sample_ids"`
		FindingsDir    string   `json:"findings_dir"`
		CorpusDir      string   `json:"corpus_dir"`
		FuzzerSHA256   string   `json:"fuzzer_sha256"`
	}{
		Imported:       result.Imported,
		Duplicates:     result.Duplicates,
		FalsePositives: result.FalsePositives,
		Invalid:        result.Invalid,
		SampleIDs:      result.SampleIDs,
		FindingsDir:    fuzzerResult.FindingsDir,
		CorpusDir:      fuzzerResult.CorpusDir,
		FuzzerSHA256:   fuzzerResult.FuzzerSHA256,
	})
	if fuzzerErr != nil {
		return result, fuzzerErr
	}
	return result, nil
}

func importFindings(ctx context.Context, st *store.Store, session store.Session, fuzzerResult fuzzrun.Result, maxFindings int) (DiscoverResult, error) {
	result := DiscoverResult{SampleIDs: make([]string, 0)}
	items := make([]store.ImportItem, 0, len(fuzzerResult.Findings))
	existing, err := st.ListSamples(ctx, session.ID)
	if err != nil {
		return result, err
	}
	known := make(map[string]bool, len(existing))
	for _, sample := range existing {
		known[sample.InputSHA256] = true
	}
	for _, finding := range fuzzerResult.Findings {
		findingSHA := domain.SHA256Hex(finding.Input)
		if known[findingSHA] {
			result.Duplicates++
			continue
		}
		if maxFindings > 0 && len(items) >= maxFindings {
			break
		}
		evaluation, err := domain.Evaluate(session.Scenario, finding.Input, "libfuzzer+go")
		if err != nil {
			result.Invalid++
			_ = st.AddEvent(ctx, session.ID, "", "fuzzer_go_mismatch", struct {
				Finding string `json:"finding"`
				Reason  string `json:"reason"`
			}{finding.Path, err.Error()})
			continue
		}
		if !evaluation.Comparison.PermissionDifference {
			result.FalsePositives++
			_ = st.AddEvent(ctx, session.ID, "", "fuzzer_go_mismatch", struct {
				Finding   string `json:"finding"`
				SampleSHA string `json:"sample_sha256"`
				Reason    string `json:"reason"`
			}{finding.Path, evaluation.Evidence.SampleSHA256, "libFuzzer reported a difference but Go did not"})
			continue
		}
		evaluation.Evidence.Engine = "libfuzzer+go"
		evaluation.Evidence.DetectionSource = "libfuzzer"
		evaluation.Evidence.FuzzerSHA256 = fuzzerResult.FuzzerSHA256
		evaluation.Evidence.FuzzerCommand = fuzzerResult.Command
		evidenceJSON, err := evaluation.EvidenceJSON()
		if err != nil {
			return result, err
		}
		known[findingSHA] = true
		timestamp := time.Now().UTC().Format(time.RFC3339Nano)
		evidenceSHA := domain.SHA256Hex(evidenceJSON)
		items = append(items, store.ImportItem{
			Source: "libfuzzer",
			Input:  finding.Input,
			Attack: evaluation.Evidence.Attack,
			Run: store.Run{
				Engine:               "libfuzzer+go",
				Status:               "ok",
				V1Allow:              evaluation.Evidence.V1.Allow,
				V2Allow:              evaluation.Evidence.V2.Allow,
				V1Reason:             evaluation.Evidence.V1.Reason,
				V2Reason:             evaluation.Evidence.V2.Reason,
				V1Replica:            evaluation.Evidence.V1.SelectedReplica,
				V2Replica:            evaluation.Evidence.V2.SelectedReplica,
				PermissionDifference: evaluation.Comparison.PermissionDifference,
				Comparable:           true,
				FuzzerDetected:       true,
				EvidenceJSON:         string(evidenceJSON),
				EvidenceSHA256:       evidenceSHA,
				StartedAt:            timestamp,
				CompletedAt:          timestamp,
			},
			EventKind: "sample_imported",
			EventDetail: struct {
				Attempt     int    `json:"attempt"`
				Source      string `json:"source"`
				Finding     string `json:"finding"`
				EvidenceSHA string `json:"evidence_sha256"`
			}{1, "libfuzzer", finding.Path, evidenceSHA},
		})
	}
	outcomes, err := st.ImportSamples(ctx, session.ID, items)
	if err != nil {
		return result, err
	}
	for _, outcome := range outcomes {
		if !outcome.Inserted {
			result.Duplicates++
			continue
		}
		result.Imported++
		result.SampleIDs = append(result.SampleIDs, outcome.Sample.ID)
	}
	return result, nil
}

func Replay(ctx context.Context, st *store.Store, options ReplayOptions) (ReplayResult, error) {
	session, err := st.GetSession(ctx, options.SessionID)
	if err != nil {
		return ReplayResult{}, err
	}
	samples, err := selectSamples(ctx, st, session.ID, options.SampleID)
	if err != nil {
		return ReplayResult{}, err
	}
	if len(samples) == 0 {
		return ReplayResult{}, errors.New("no samples to replay")
	}
	repeat := options.Repeat
	if repeat <= 0 {
		repeat = 1
	}
	engine := options.Engine
	if engine == "" {
		engine = "go"
	}
	if engine != "go" && engine != "go+libfuzzer" {
		return ReplayResult{}, fmt.Errorf("unsupported replay engine %q", engine)
	}
	result := ReplayResult{SessionID: session.ID, Runs: make([]ReplayItem, 0)}
	for _, sample := range samples {
		for i := 0; i < repeat; i++ {
			item, err := replayOne(ctx, st, session, sample, engine, options)
			if err != nil {
				return result, err
			}
			result.Runs = append(result.Runs, item)
		}
	}
	return result, nil
}

func replayOne(ctx context.Context, st *store.Store, session store.Session, sample store.Sample, engine string, options ReplayOptions) (ReplayItem, error) {
	started := time.Now()
	evaluation, err := domain.Evaluate(session.Scenario, sample.Input, "go")
	if err != nil {
		return ReplayItem{}, err
	}
	status := "ok"
	comparable := true
	fuzzerDetected := false
	if engine == "go+libfuzzer" {
		if options.Fuzzer == "" {
			return ReplayItem{}, errors.New("fuzzer binary is required for go+libfuzzer replay")
		}
		oracle, oracleErr := fuzzrun.VerifyOne(ctx, options.Fuzzer, options.WorkDir, session.Scenario, sample.Input)
		if oracleErr != nil {
			status = "oracle_error"
			comparable = false
		} else {
			fuzzerDetected = oracle.Detected
			if fuzzerDetected != evaluation.Comparison.PermissionDifference {
				status = "oracle_mismatch"
				comparable = false
			}
		}
		evaluation.Evidence.Engine = "go+libfuzzer"
		evaluation.Evidence.DetectionSource = "libfuzzer-replay"
		evaluation.Evidence.FuzzerCommand = oracle.Command
		if oracleErr == nil {
			evaluation.Evidence.FuzzerSHA256, _ = fuzzrun.FileSHA256(options.Fuzzer)
		}
	}
	run, err := saveRun(ctx, st, session.ID, sample.ID, evaluation, engine, status, comparable, fuzzerDetected, started)
	if err != nil {
		return ReplayItem{}, err
	}
	_ = st.AddEvent(ctx, session.ID, sample.ID, "sample_replayed", struct {
		Attempt     int    `json:"attempt"`
		Engine      string `json:"engine"`
		Status      string `json:"status"`
		DurationMS  int64  `json:"duration_ms"`
		EvidenceSHA string `json:"evidence_sha256"`
	}{run.Attempt, engine, status, time.Since(started).Milliseconds(), run.EvidenceSHA256})
	return ReplayItem{
		SampleID:             sample.ID,
		Ordinal:              sample.Ordinal,
		Attempt:              run.Attempt,
		Engine:               engine,
		Status:               status,
		V1Allow:              evaluation.Evidence.V1.Allow,
		V2Allow:              evaluation.Evidence.V2.Allow,
		PermissionDifference: evaluation.Comparison.PermissionDifference,
		Comparable:           comparable,
		EvidenceSHA256:       run.EvidenceSHA256,
	}, nil
}

func saveRun(ctx context.Context, st *store.Store, sessionID, sampleID string, evaluation domain.Evaluation, engine, status string, comparable, fuzzerDetected bool, started time.Time) (store.Run, error) {
	evidenceJSON, err := evaluation.EvidenceJSON()
	if err != nil {
		return store.Run{}, err
	}
	completed := time.Now().UTC()
	evidenceSHA := domain.SHA256Hex(evidenceJSON)
	return st.AddRun(ctx, store.Run{
		SessionID:            sessionID,
		SampleID:             sampleID,
		Engine:               engine,
		Status:               status,
		V1Allow:              evaluation.Evidence.V1.Allow,
		V2Allow:              evaluation.Evidence.V2.Allow,
		V1Reason:             evaluation.Evidence.V1.Reason,
		V2Reason:             evaluation.Evidence.V2.Reason,
		V1Replica:            evaluation.Evidence.V1.SelectedReplica,
		V2Replica:            evaluation.Evidence.V2.SelectedReplica,
		PermissionDifference: evaluation.Comparison.PermissionDifference,
		Comparable:           comparable,
		FuzzerDetected:       fuzzerDetected,
		EvidenceJSON:         string(evidenceJSON),
		EvidenceSHA256:       evidenceSHA,
		StartedAt:            started.UTC().Format(time.RFC3339Nano),
		CompletedAt:          completed.UTC().Format(time.RFC3339Nano),
		DurationMS:           completed.Sub(started).Milliseconds(),
	})
}

func Compare(ctx context.Context, st *store.Store, sessionID, sampleID string) (CompareResult, error) {
	session, err := st.GetSession(ctx, sessionID)
	if err != nil {
		return CompareResult{}, err
	}
	samples, err := selectSamples(ctx, st, session.ID, sampleID)
	if err != nil {
		return CompareResult{}, err
	}
	result := CompareResult{SessionID: session.ID, Samples: make([]SampleCompare, 0, len(samples))}
	for _, sample := range samples {
		runs, err := st.ListRuns(ctx, session.ID, sample.ID)
		if err != nil {
			return CompareResult{}, err
		}
		if len(runs) == 0 {
			result.Samples = append(result.Samples, SampleCompare{
				SampleID: sample.ID,
				Ordinal:  sample.Ordinal,
				Stable:   false,
			})
			continue
		}
		first := runs[0]
		latest := runs[len(runs)-1]
		left, err := decodeEvidence(first.EvidenceJSON)
		if err != nil {
			return CompareResult{}, err
		}
		changed := make(map[string]bool)
		for _, run := range runs[1:] {
			evidence, err := decodeEvidence(run.EvidenceJSON)
			if err != nil {
				return CompareResult{}, err
			}
			for _, field := range domain.CompareFingerprints(left, evidence) {
				changed[field] = true
			}
		}
		drift := domain.OrderedFingerprintFields(changed)
		result.Samples = append(result.Samples, SampleCompare{
			SampleID:             sample.ID,
			Ordinal:              sample.Ordinal,
			Attempts:             len(runs),
			FirstAttempt:         first.Attempt,
			LatestAttempt:        latest.Attempt,
			V1Allow:              latest.V1Allow,
			V2Allow:              latest.V2Allow,
			PermissionDifference: latest.PermissionDifference,
			DriftFields:          drift,
			Stable:               len(drift) == 0,
			EvidenceSHA256:       latest.EvidenceSHA256,
		})
	}
	return result, nil
}

func Fix(ctx context.Context, st *store.Store, sessionID, sampleID string) (FixResult, error) {
	session, err := st.GetSession(ctx, sessionID)
	if err != nil {
		return FixResult{}, err
	}
	sample, err := st.GetSample(ctx, session.ID, sampleID)
	if err != nil {
		return FixResult{}, err
	}
	runs, err := st.ListRuns(ctx, session.ID, sample.ID)
	if err != nil {
		return FixResult{}, err
	}
	if len(runs) == 0 {
		return FixResult{}, errors.New("sample has no replay evidence; run replay first")
	}
	var baseline domain.Evidence
	stableRuns := 0
	var latestJSON []byte
	for i := 0; i < 3; i++ {
		evaluation, err := domain.Evaluate(session.Scenario, sample.Input, "go-fix-check")
		if err != nil {
			return FixResult{}, err
		}
		raw, err := evaluation.EvidenceJSON()
		if err != nil {
			return FixResult{}, err
		}
		if i == 0 {
			baseline = evaluation.Evidence
			latestJSON = raw
			stableRuns = 1
			continue
		}
		if domain.SHA256Hex(raw) != domain.SHA256Hex(latestJSON) {
			return FixResult{}, errors.New("repeated Go evaluation was not deterministic")
		}
		stableRuns++
	}
	stored, err := decodeEvidence(runs[len(runs)-1].EvidenceJSON)
	if err != nil {
		return FixResult{}, err
	}
	if drift := domain.CompareFingerprints(stored, baseline); len(drift) != 0 {
		return FixResult{}, fmt.Errorf("stored evidence drifted: %s", domain.JoinFields(drift))
	}
	evaluation, err := domain.Evaluate(session.Scenario, sample.Input, "go-fix-check")
	if err != nil {
		return FixResult{}, err
	}
	planJSON, err := json.MarshalIndent(evaluation.FixPlan, "", "  ")
	if err != nil {
		return FixResult{}, err
	}
	_ = st.AddEvent(ctx, session.ID, sample.ID, "fix_plan_generated", struct {
		RootCause string `json:"root_cause"`
		RuleID    string `json:"rule_id"`
		Verified  bool   `json:"verified"`
		PlanSHA   string `json:"plan_sha256"`
	}{evaluation.FixPlan.RootCause, evaluation.FixPlan.RuleID, evaluation.FixPlan.Verified, domain.SHA256Hex(planJSON)})
	return FixResult{
		SessionID:      session.ID,
		SampleID:       sample.ID,
		InputSHA256:    sample.InputSHA256,
		EvidenceSHA256: runs[len(runs)-1].EvidenceSHA256,
		StableRuns:     stableRuns,
		Evidence:       baseline,
		Plan:           evaluation.FixPlan,
	}, nil
}

func selectSamples(ctx context.Context, st *store.Store, sessionID, sampleID string) ([]store.Sample, error) {
	if sampleID == "" || sampleID == "all" {
		return st.ListSamples(ctx, sessionID)
	}
	sample, err := st.GetSample(ctx, sessionID, sampleID)
	if err != nil {
		return nil, err
	}
	return []store.Sample{sample}, nil
}

func decodeEvidence(raw string) (domain.Evidence, error) {
	var evidence domain.Evidence
	if err := json.Unmarshal([]byte(raw), &evidence); err != nil {
		return domain.Evidence{}, err
	}
	return evidence, nil
}
