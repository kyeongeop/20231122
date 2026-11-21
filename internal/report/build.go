package report

import (
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"pathaliaslab/internal/ledger"
)

func Build(l *ledger.Ledger, dbPath, artifactDir string) (Report, error) {
	runs, err := l.Runs()
	if err != nil {
		return Report{}, err
	}
	checks, err := l.Checks()
	if err != nil {
		return Report{}, err
	}
	replays, err := l.Replays()
	if err != nil {
		return Report{}, err
	}
	artifacts, err := l.Artifacts()
	if err != nil {
		return Report{}, err
	}
	integrity, err := l.IntegrityCheck()
	if err != nil {
		return Report{}, err
	}
	sqliteVersion, _ := l.Meta("sqlite_version")

	report := Report{
		Schema:         "pathalias-experiment-report/v1",
		GeneratedAtUTC: time.Now().UTC().Format(time.RFC3339),
		Runtime: RuntimeInfo{
			GoVersion: runtime.Version(), SQLiteVersion: sqliteVersion,
		},
		Evidence: EvidenceInfo{
			DatabasePath:  filepath.ToSlash(dbPath),
			Integrity:     integrity,
			ArtifactFiles: make([]string, 0),
		},
	}
	chainValid := true
	for _, run := range runs {
		if err := l.VerifyEvidenceChain(run.RunID); err != nil {
			chainValid = false
		}
	}
	report.Evidence.EvidenceChainValid = chainValid
	for _, artifact := range artifacts {
		report.Evidence.ArtifactFiles = append(report.Evidence.ArtifactFiles, artifact.Path)
	}
	sort.Strings(report.Evidence.ArtifactFiles)

	for _, run := range runs {
		steps, err := l.Steps(run.RunID)
		if err != nil {
			return Report{}, err
		}
		summary := RunSummary{
			RunID: run.RunID, Scenario: run.ScenarioName, Role: run.Role,
			Status: run.Status, StepCount: run.StepCount, InputSHA256: run.InputSHA256,
			FinalStateSHA256: run.FinalStateSHA256, ResolutionSHA256: run.ResolutionSHA256,
			EventSHA256: run.EventSHA256, Steps: make([]StepEvidence, 0, len(steps)),
		}
		for _, step := range steps {
			summary.Steps = append(summary.Steps, StepEvidence{
				StepNo: step.StepNo, OpID: step.OpID, Kind: step.Kind,
				Input: step.InputJSON, StateBefore: step.StateBeforeJSON,
				RecordedResult: step.ResultJSON, StateAfter: step.StateAfterJSON,
				StateBeforeSHA256: step.StateBeforeSHA256, ResultSHA256: step.ResultSHA256,
				StateAfterSHA256: step.StateAfterSHA256, EvidenceSHA256: step.EvidenceSHA256,
			})
		}
		report.Runs = append(report.Runs, summary)
	}
	for _, check := range checks {
		report.Checks = append(report.Checks, CheckSummary{
			RunID: check.RunID, Name: check.CheckName, Scope: check.Scope,
			Expected: check.Expected, Actual: check.Actual, Passed: check.Passed,
			Detail: check.Detail,
		})
	}
	for _, replay := range replays {
		report.Replays = append(report.Replays, ReplaySummary{
			SourceRunID: replay.SourceRunID, ReplayRunID: replay.ReplayRunID,
			InputMatch: replay.InputMatch, StateMatch: replay.StateMatch,
			ResultMatch: replay.ResultMatch, Passed: replay.Passed, Detail: replay.Detail,
		})
	}
	report.Fuzz = collectFuzz(artifactDir)
	report.Runtime.LibFuzzer = report.Fuzz.Available
	report.AutomaticConclusions = automaticConclusions(report)
	report.ManualConfirmations = manualConfirmations(report)
	report.FailureActions = failureActions(report)
	report.OverallStatus = overallStatus(report)
	return report, nil
}

func overallStatus(report Report) string {
	if !report.Evidence.EvidenceChainValid || !report.Fuzz.Available ||
		report.Fuzz.Status != "passed" || len(report.Fuzz.CrashArtifacts) > 0 {
		return "FAIL"
	}
	for _, message := range report.Evidence.Integrity {
		if message != "ok" {
			return "FAIL"
		}
	}
	for _, check := range report.Checks {
		if !check.Passed {
			return "FAIL"
		}
	}
	for _, replay := range report.Replays {
		if !replay.Passed {
			return "FAIL"
		}
	}
	return "PASS"
}

func automaticConclusions(report Report) []Conclusion {
	check := func(runID, name string) (CheckSummary, bool) {
		for _, candidate := range report.Checks {
			if candidate.RunID == runID && candidate.Name == name {
				return candidate, true
			}
		}
		return CheckSummary{}, false
	}
	statusOf := func(runID, name string) string {
		if value, ok := check(runID, name); ok && value.Passed {
			return "confirmed"
		}
		return "failed"
	}
	primaryConflict := statusOf("primary_cancel", "conflict_steps_match")
	primaryCancel := statusOf("primary_cancel", "final_resolution")
	control := statusOf("global", "control_has_no_conflict")
	order := statusOf("global", "order_resolution_matches_primary")
	duplicate := statusOf("global", "duplicate_steps_state_unchanged")
	replay := statusOf("global", "replay_matches_source")
	evidence := "failed"
	if report.Evidence.EvidenceChainValid && len(report.Evidence.Integrity) == 1 &&
		report.Evidence.Integrity[0] == "ok" {
		evidence = "confirmed"
	}
	fuzzStatus := "failed"
	if report.Fuzz.Available && report.Fuzz.Status == "passed" && len(report.Fuzz.CrashArtifacts) == 0 {
		fuzzStatus = "confirmed"
	}
	return []Conclusion{
		{ID: "AUTO-01", Status: primaryConflict,
			Statement: "主实验在第 2 步观察到路径别名冲突：不同原始路径规范化到同一别名，却指向不同目标。",
			Evidence:  "primary_cancel/conflict_steps_match, steps 1-2"},
		{ID: "AUTO-02", Status: primaryCancel,
			Statement: "第 3 步按操作 ID 中途取消后，保留的候选成为唯一有效目标，最终无活动冲突。",
			Evidence:  "primary_cancel/final_resolution, primary_cancel/final_conflict_free"},
		{ID: "AUTO-03", Status: control,
			Statement: "对照组在同一序号执行中途取消，但两个别名不重叠，因此未产生冲突。",
			Evidence:  "control_cancel trace, global/control_has_no_conflict"},
		{ID: "AUTO-04", Status: order,
			Statement: "交换冲突提交顺序后，按操作 ID 取消同一候选，最终解析摘要与主实验一致。",
			Evidence:  "order_swap resolution vs primary_cancel"},
		{ID: "AUTO-05", Status: duplicate,
			Statement: "冲突中、取消后和重复取消时的精确重复提交均不改变状态，也不复活已取消候选。",
			Evidence:  "duplicate_probe steps 3,5,6; global/duplicate_steps_state_unchanged"},
		{ID: "AUTO-06", Status: replay,
			Statement: "主实验从 SQLite 内保存的场景 JSON 回放，每一步输入、结果和前后状态逐字节一致。",
			Evidence:  "primary_cancel-replay; global/replay_matches_source"},
		{ID: "AUTO-07", Status: evidence,
			Statement: "所有步骤的 SHA-256 证据链连续，SQLite integrity_check 返回 ok。",
			Evidence:  "runs.event_sha256, steps.evidence_sha256, PRAGMA integrity_check"},
		{ID: "AUTO-08", Status: fuzzStatus,
			Statement: "libFuzzer 冒烟运行完成且未产生 crash/timeout/OOM 工件；详细执行数见证据。",
			Evidence:  report.Fuzz.LogPath},
	}
}

func manualConfirmations(report Report) []ManualConfirmation {
	return []ManualConfirmation{
		{ID: "MAN-01", Decision: "pending",
			Question: "`/deploy//api/` 与 `/deploy/api` 被视为同一别名是否符合产品/路由规范？",
			Why:      "自动检查只验证当前实现的规范化规则，不能替代规范所有者确认。",
			Evidence: "primary_cancel step 2; internal/model/path.go"},
		{ID: "MAN-02", Decision: "pending",
			Question: "多个目标竞争同一别名时，应保持“冲突阻塞”还是采用确定性优先级？",
			Why:      "当前实现故意阻塞冲突；这是产品语义选择，不是可由回放单独证明的正确性。",
			Evidence: "primary_cancel step 2 state_after"},
		{ID: "MAN-03", Decision: "pending",
			Question: "取消应以提交操作 ID 为键，还是允许仅凭别名取消全部候选？",
			Why:      "两种策略都可通过测试，但对并发和重试语义影响不同。",
			Evidence: "primary_cancel step 3; scenarios.json"},
		{ID: "MAN-04", Decision: "pending",
			Question: "已取消操作的精确重复提交应保持 no-op，且不得复活候选，是否符合重试契约？",
			Why:      "自动检查证明了幂等行为，但重试窗口和保留期需要人工确认。",
			Evidence: "duplicate_probe steps 3,5,6"},
		{ID: "MAN-05", Decision: "pending",
			Question: "路径是否应保持大小写敏感，以及证据/数据库保留期限是否满足审计要求？",
			Why:      "涉及部署平台约定与合规策略，无法从本地实验推导。",
			Evidence: "path normalization policy; artifacts/evidence/manifest.json"},
	}
}

func failureActions(report Report) []Action {
	actions := []Action{
		{Condition: "任一自动检查失败", Command: "make experiment", Purpose: "清空并重建实验数据库，复现失败"},
		{Condition: "任一自动检查失败", Command: "make verify", Purpose: "定位失败检查、哈希链或 SQLite 完整性问题"},
		{Condition: "需要查看单次运行", Command: "make show RUN=primary_cancel", Purpose: "输出该运行每一步的输入、状态和结果"},
		{Condition: "libFuzzer 失败或未运行", Command: "make fuzz FUZZ_SECONDS=30", Purpose: "重建并运行 libFuzzer 冒烟测试，保留日志和 corpus"},
		{Condition: "报告需重建", Command: "make report", Purpose: "从 SQLite 重新导出报告和证据清单"},
	}
	if len(report.Fuzz.CrashArtifacts) > 0 {
		actions = append(actions, Action{
			Condition: "存在 libFuzzer crash 工件",
			Command:   "artifacts/fuzz/pathalias_fuzzer " + report.Fuzz.CrashArtifacts[0],
			Purpose:   "用原始工件独立复现崩溃",
		})
	}
	return actions
}
