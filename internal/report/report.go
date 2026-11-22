package report

import (
	"context"
	"strings"
	"time"

	"seedreview/internal/evidence"
	"seedreview/internal/model"
	"seedreview/internal/store"
)

type Report struct {
	SchemaVersion int              `json:"schema_version"`
	GeneratedAt   string           `json:"generated_at"`
	Run           RunSummary       `json:"run"`
	Automatic     AutomaticSection `json:"automatic"`
	Manual        ManualSection    `json:"manual_confirmation"`
	Compatibility Compatibility    `json:"compatibility"`
	AuditTrail    []map[string]any `json:"audit_trail"`
}

type RunSummary struct {
	ID            int64  `json:"id"`
	RecoveryID    string `json:"recovery_id"`
	SourceFormat  string `json:"source_format"`
	CapturedAt    string `json:"captured_at"`
	AppVersion    string `json:"app_version"`
	RNGAlgorithm  string `json:"rng_algorithm"`
	Seed          string `json:"seed"`
	RecoveredSeed string `json:"recovered_seed"`
	EffectiveSeed string `json:"effective_seed"`
	StateSHA256   string `json:"state_sha256"`
	StartedAt     string `json:"started_at"`
	CompletedAt   string `json:"completed_at"`
	Status        string `json:"status"`
}

type AutomaticSection struct {
	Conclusion        string            `json:"conclusion"`
	ConclusionText    string            `json:"conclusion_text"`
	ReplaySucceeded   bool              `json:"replay_succeeded"`
	Mapping           Mapping           `json:"mapping"`
	Findings          []model.Finding   `json:"findings"`
	Failure           FailureSection    `json:"failure"`
	EvidenceIntegrity EvidenceIntegrity `json:"evidence_integrity"`
}

type Mapping struct {
	AttackInput      ArtifactRef     `json:"attack_input"`
	UnknownExtension *ExtensionView  `json:"unknown_extension,omitempty"`
	Trigger          *TriggerView    `json:"trigger,omitempty"`
	Permission       *PermissionView `json:"permission,omitempty"`
	Logs             []LogView       `json:"log_evidence"`
}

type ArtifactRef struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
	EvidenceSHA256 string `json:"evidence_sha256"`
	TargetPath     string `json:"target_path"`
	TargetSHA256   string `json:"target_sha256"`
}

type ExtensionView struct {
	Name  string `json:"name"`
	Known bool   `json:"known"`
}

type TriggerView struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Function string `json:"function"`
	Kind     string `json:"kind"`
}

type PermissionView struct {
	Principal string `json:"principal"`
	Action    string `json:"action"`
	Expected  string `json:"expected"`
	Actual    string `json:"actual"`
	Policy    string `json:"policy"`
	Reason    string `json:"reason"`
}

type LogView struct {
	Sequence   int    `json:"sequence"`
	Level      string `json:"level"`
	Message    string `json:"message"`
	LineSHA256 string `json:"line_sha256"`
	Evidence   string `json:"evidence_sha256"`
}

type FailureSection struct {
	Code        string             `json:"code,omitempty"`
	Message     string             `json:"message,omitempty"`
	NextActions []model.NextAction `json:"next_actions"`
}

type EvidenceIntegrity struct {
	OK    bool             `json:"ok"`
	Items []EvidenceStatus `json:"items"`
}

type EvidenceStatus struct {
	SHA256       string `json:"sha256"`
	Kind         string `json:"kind"`
	RelativePath string `json:"relative_path"`
	Size         int64  `json:"size"`
	Present      bool   `json:"present"`
	HashOK       bool   `json:"hash_ok"`
	Error        string `json:"error,omitempty"`
}

type ManualSection struct {
	Status  string              `json:"status"`
	Pending int                 `json:"pending"`
	Checks  []model.ManualCheck `json:"checks"`
}

type Compatibility struct {
	InputFormat  string `json:"input_format"`
	OutputFormat string `json:"output_format"`
}

func Build(
	ctx context.Context,
	database *store.Store,
	evidenceStore *evidence.Store,
	runID int64,
) (Report, error) {
	view, err := database.GetRun(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	integrity := verifyEvidence(evidenceStore, view.Evidence)
	unknown, trigger, permission := mapCore(view.Extensions)
	report := Report{
		SchemaVersion: model.ReportSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Run: RunSummary{
			ID: view.ID, RecoveryID: view.RecoveryID,
			SourceFormat: view.SourceFormat, CapturedAt: view.CapturedAt,
			AppVersion: view.AppVersion, StartedAt: view.StartedAt,
			CompletedAt: view.CompletedAt, Status: view.Status,
			RNGAlgorithm: view.RNGAlgorithm, Seed: view.Seed,
			RecoveredSeed: view.RecoveredSeed,
			EffectiveSeed: view.EffectiveSeed,
			StateSHA256:   view.StateSHA256,
		},
		Automatic: AutomaticSection{
			Conclusion:      view.AutoConclusion,
			ConclusionText:  conclusionText(view.AutoConclusion),
			ReplaySucceeded: view.Status == "ok",
			Mapping: Mapping{
				AttackInput: ArtifactRef{
					Path: view.ArtifactPath, SHA256: view.InputSHA256,
					Size: view.InputSize, EvidenceSHA256: view.InputEvidence,
					TargetPath:   view.Target,
					TargetSHA256: view.TargetSHA256,
				},
				UnknownExtension: unknown, Trigger: trigger,
				Permission: permission,
				Logs:       mapLogs(view.Logs, 8),
			},
			Findings: view.Findings,
			Failure: FailureSection{
				Code: view.FailureCode, Message: view.FailureMessage,
				NextActions: view.NextActions,
			},
			EvidenceIntegrity: integrity,
		},
		Compatibility: Compatibility{
			InputFormat: view.SourceFormat, OutputFormat: "canonical-v2",
		},
	}
	report.Manual = manualSection(view.ManualChecks)
	report.AuditTrail, err = database.AuditEvents(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	return report, nil
}

func verifyEvidence(store *evidence.Store, records []model.Evidence) EvidenceIntegrity {
	result := EvidenceIntegrity{OK: true}
	for _, record := range records {
		status := EvidenceStatus{
			SHA256: record.SHA256, Kind: record.Kind,
			RelativePath: record.RelativePath, Size: record.Size,
		}
		if err := store.Verify(record); err != nil {
			status.Error = err.Error()
			result.OK = false
		} else {
			status.Present = true
			status.HashOK = true
		}
		result.Items = append(result.Items, status)
	}
	return result
}

func mapCore(extensions []model.ExtensionRecord) (*ExtensionView, *TriggerView, *PermissionView) {
	var unknown *ExtensionView
	var trigger *TriggerView
	var permission *PermissionView
	for _, extension := range extensions {
		if !extension.Known && unknown == nil {
			unknown = &ExtensionView{Name: extension.Name, Known: extension.Known}
		}
		if extension.Trigger != nil && trigger == nil {
			trigger = &TriggerView{
				File: extension.Trigger.File, Line: extension.Trigger.Line,
				Function: extension.Trigger.Function, Kind: extension.Trigger.Kind,
			}
		}
		if extension.Permission != nil && permission == nil {
			permission = &PermissionView{
				Principal: extension.Permission.Principal,
				Action:    extension.Permission.Action,
				Expected:  extension.Permission.Expected,
				Actual:    extension.Permission.Actual,
				Policy:    extension.Permission.Policy,
				Reason:    extension.Permission.Reason,
			}
		}
	}
	return unknown, trigger, permission
}

func mapLogs(logs []model.LogEvidence, limit int) []LogView {
	var result []LogView
	for _, line := range logs {
		if len(result) >= limit {
			break
		}
		result = append(result, LogView{
			Sequence: line.Sequence, Level: line.Level, Message: line.Message,
			LineSHA256: line.LineSHA256, Evidence: line.EvidenceSHA256,
		})
	}
	return result
}

func manualSection(checks []model.ManualCheck) ManualSection {
	section := ManualSection{Status: "complete", Checks: checks}
	rejected := false
	for _, check := range checks {
		if check.Status == "pending" {
			section.Pending++
			section.Status = "pending"
		}
		if check.Status == "rejected" {
			rejected = true
		}
	}
	if rejected {
		section.Status = "rejected"
	}
	return section
}

func conclusionText(conclusion string) string {
	switch conclusion {
	case "unknown_extension_denied":
		return "恢复后重放记录到未知扩展，权限门按策略拒绝；仍需人工确认策略、来源和日志留存。"
	case "permission_bypass_suspected":
		return "权限实际结果与预期不一致，存在疑似绕过，必须立即人工复核。"
	case "no_unknown_extension":
		return "本次重放未记录未知扩展；该结果不替代人工确认。"
	case "replay_failed":
		return "恢复后重放失败，当前不能形成通过结论；请按后续操作补齐证据。"
	case "trace_incomplete":
		return "结构化 trace 不完整，无法完成输入到权限证据的自动映射。"
	default:
		return "自动分析无法形成确定结论，需要人工复核原始证据。"
	}
}

func markdownEscape(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "`", "'")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	if len(value) > 1000 {
		return value[:1000] + "..."
	}
	return value
}
