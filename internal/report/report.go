package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"timeoutfsm/internal/replay"
)

// Verdict is the machine-generated conclusion for one scenario.
type Verdict struct {
	Scenario       string `json:"scenario"`
	Description    string `json:"description"`
	Steps          int    `json:"steps"`
	Accepted       int    `json:"accepted"`
	Rejected       int    `json:"rejected"`
	Duplicates     int    `json:"duplicates"`
	UnknownSeen    int    `json:"unknown_seen"`
	FinalState     string `json:"final_state"`
	FinalHash      string `json:"final_hash"`
	Replayed       bool   `json:"replayed"`
	ReplayMatch    bool   `json:"replay_match"`
	ReplayMismatch int    `json:"replay_mismatch"`
	AutomatedPass  bool   `json:"automated_pass"`
	FailureHint    string `json:"failure_hint,omitempty"`
}

// StepView is the per-step evidence written to the report.
type StepView struct {
	Seq        int64  `json:"seq"`
	Kind       string `json:"kind"`
	MsgID      string `json:"msg_id"`
	Accepted   bool   `json:"accepted"`
	Duplicate  bool   `json:"duplicate"`
	Reason     string `json:"reason"`
	StateAfter string `json:"state_after"`
	HashAfter  string `json:"hash_after"`
}

// Report is the full persisted experiment record.
type Report struct {
	Database   string                `json:"database"`
	Verdicts   []Verdict             `json:"verdicts"`
	StepTraces map[string][]StepView `json:"step_traces"`
	Manual     []string              `json:"manual_confirmation_checklist"`
}

// Build assembles a report from executed results and scenario descriptions.
func Build(dbPath string, results []*replay.Result, descs map[string]string) *Report {
	r := &Report{
		Database:   dbPath,
		StepTraces: map[string][]StepView{},
		Manual: []string{
			"用 `go run ./cmd/dbquery` 核对 runs=4、events=24、replay_checks=13 且 mismatch=0。",
			"确认 unknown_extension_control 中 X_PING 被拒绝（accepted=false）且流程仍到达 CLOSED。",
			"重跑 `go test ./...` 与 `make fuzz`，确认无回归、无 fuzz 崩溃。",
			"抽查 evidence/trace_*.json，确认每一步的输入、后继状态与状态哈希均已落盘。",
			"对照 evidence/report.md 第三节，人工确认乱序与重复提交的拒绝原因符合预期。",
		},
	}

	for _, res := range results {
		v := Verdict{
			Scenario:       res.Scenario,
			Description:    descs[res.Scenario],
			Steps:          len(res.Steps),
			FinalHash:      res.FinalHash,
			Replayed:       res.Replayed,
			ReplayMatch:    res.ReplayMatch,
			ReplayMismatch: res.ReplayMismatch,
		}
		var trace []StepView
		for _, s := range res.Steps {
			if s.Outcome.Accepted {
				v.Accepted++
			} else {
				v.Rejected++
			}
			if s.Outcome.Duplicate {
				v.Duplicates++
			}
			v.UnknownSeen += s.Snapshot.UnknownSeen
			v.FinalState = string(s.Snapshot.State)
			trace = append(trace, StepView{
				Seq: s.Seq, Kind: s.Input.Kind, MsgID: s.Input.MsgID,
				Accepted: s.Outcome.Accepted, Duplicate: s.Outcome.Duplicate,
				Reason: s.Outcome.Reason, StateAfter: string(s.Snapshot.State),
				HashAfter: s.StateHash,
			})
		}
		// UnknownSeen is cumulative on the machine; take the final value instead.
		if len(res.Steps) > 0 {
			v.UnknownSeen = res.Steps[len(res.Steps)-1].Snapshot.UnknownSeen
		}
		v.AutomatedPass = evaluate(res)
		if !v.AutomatedPass {
			v.FailureHint = actionableHint(res)
		}
		r.Verdicts = append(r.Verdicts, v)
		r.StepTraces[res.Scenario] = trace
	}
	return r
}

func evaluate(res *replay.Result) bool {
	if res.Replayed && (!res.ReplayMatch || res.ReplayMismatch != 0) {
		return false
	}
	return true
}

func actionableHint(res *replay.Result) string {
	if res.Replayed && !res.ReplayMatch {
		return fmt.Sprintf(
			"replay diverged at %d step(s): open %s in SQLite, compare events.hash_after "+
				"with replay_checks.replay_hash, then fix the nondeterministic transition and re-run "+
				"`go run ./cmd/experiment`.", res.ReplayMismatch, "artifacts/experiment.db")
	}
	return "inspect the failing step trace in evidence/ and re-run the scenario in isolation."
}

// WriteJSON persists the structured report.
func (r *Report) WriteJSON(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// WriteMarkdown renders a human report with separate automated and manual sections.
func (r *Report) WriteMarkdown(path string) error {
	var b strings.Builder
	b.WriteString("# 协议超时状态机 — 可回放实验报告\n\n")
	b.WriteString(fmt.Sprintf("SQLite 证据库: `%s`\n\n", r.Database))

	b.WriteString("## 一、自动结论\n\n")
	b.WriteString("| 场景 | 步数 | 接受 | 拒绝 | 重复 | 未知扩展 | 终态 | 重放一致 | 结论 |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|\n")
	for _, v := range r.Verdicts {
		pass := "PASS"
		if !v.AutomatedPass {
			pass = "FAIL"
		}
		replay := "N/A"
		if v.Replayed {
			replay = fmt.Sprintf("%t (mismatch=%d)", v.ReplayMatch, v.ReplayMismatch)
		}
		b.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %d | %s | %s | %s |\n",
			v.Scenario, v.Steps, v.Accepted, v.Rejected, v.Duplicates,
			v.UnknownSeen, v.FinalState, replay, pass))
	}
	b.WriteString("\n### 失败时的可执行后续操作\n\n")
	anyFail := false
	for _, v := range r.Verdicts {
		if !v.AutomatedPass {
			anyFail = true
			b.WriteString(fmt.Sprintf("- **%s**: %s\n", v.Scenario, v.FailureHint))
		}
	}
	if !anyFail {
		b.WriteString("- 无失败项。若后续出现失败，报告将在此给出对应 SQLite 排查与重跑命令。\n")
	}

	b.WriteString("\n## 二、人工确认清单\n\n")
	for _, item := range r.Manual {
		b.WriteString("- [ ] " + item + "\n")
	}

	b.WriteString("\n## 三、逐步证据（输入 / 状态 / 结果）\n\n")
	for _, v := range r.Verdicts {
		b.WriteString(fmt.Sprintf("### %s — %s\n\n", v.Scenario, v.Description))
		b.WriteString("| seq | 输入 kind | msg_id | 接受 | 重复 | 结果原因 | 后继状态 | 状态哈希(前16位) |\n")
		b.WriteString("|---|---|---|---|---|---|---|---|\n")
		for _, s := range r.StepTraces[v.Scenario] {
			short := s.HashAfter
			if len(short) > 16 {
				short = short[:16]
			}
			b.WriteString(fmt.Sprintf("| %d | %s | %s | %t | %t | %s | %s | %s |\n",
				s.Seq, s.Kind, s.MsgID, s.Accepted, s.Duplicate,
				s.Reason, s.StateAfter, short))
		}
		b.WriteString("\n")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
