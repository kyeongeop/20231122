package bundle

import (
	"fmt"
	"strconv"
)

const Schema = "apiskew.bundle/v1"

var RecordFields = []string{
	"ordinal",
	"sample_id",
	"source",
	"sample_sha256",
	"scenario_sha256",
	"object_key",
	"object_canonical_id",
	"input_hex",
	"input_bytes",
	"actor_role",
	"action",
	"tenant_match",
	"request_device",
	"device_a_skew_ms",
	"device_b_skew_ms",
	"v1_allow",
	"v1_reason",
	"v1_selected_replica",
	"v2_allow",
	"v2_reason",
	"v2_selected_replica",
	"permission_difference",
	"different_fields",
	"root_cause",
	"fix_rule_id",
	"fix_summary",
	"fix_verified",
	"attempts",
	"latest_attempt",
	"evidence_path",
	"evidence_sha256",
	"replay_command",
}

var AttemptFields = []string{
	"sample_id",
	"attempt",
	"engine",
	"status",
	"comparable",
	"v1_allow",
	"v2_allow",
	"permission_difference",
	"evidence_path",
	"evidence_sha256",
	"started_at",
	"completed_at",
}

type Record struct {
	Ordinal              int    `json:"ordinal"`
	SampleID             string `json:"sample_id"`
	Source               string `json:"source"`
	SampleSHA256         string `json:"sample_sha256"`
	ScenarioSHA256       string `json:"scenario_sha256"`
	ObjectKey            string `json:"object_key"`
	ObjectCanonicalID    string `json:"object_canonical_id"`
	InputHex             string `json:"input_hex"`
	InputBytes           int    `json:"input_bytes"`
	ActorRole            string `json:"actor_role"`
	Action               string `json:"action"`
	TenantMatch          bool   `json:"tenant_match"`
	RequestDevice        string `json:"request_device"`
	DeviceASkewMS        int32  `json:"device_a_skew_ms"`
	DeviceBSkewMS        int32  `json:"device_b_skew_ms"`
	V1Allow              bool   `json:"v1_allow"`
	V1Reason             string `json:"v1_reason"`
	V1SelectedReplica    string `json:"v1_selected_replica"`
	V2Allow              bool   `json:"v2_allow"`
	V2Reason             string `json:"v2_reason"`
	V2SelectedReplica    string `json:"v2_selected_replica"`
	PermissionDifference bool   `json:"permission_difference"`
	DifferentFields      string `json:"different_fields"`
	RootCause            string `json:"root_cause"`
	FixRuleID            string `json:"fix_rule_id"`
	FixSummary           string `json:"fix_summary"`
	FixVerified          bool   `json:"fix_verified"`
	Attempts             int    `json:"attempts"`
	LatestAttempt        int    `json:"latest_attempt"`
	EvidencePath         string `json:"evidence_path"`
	EvidenceSHA256       string `json:"evidence_sha256"`
	ReplayCommand        string `json:"replay_command"`
}

type AttemptRecord struct {
	SampleID             string `json:"sample_id"`
	Attempt              int    `json:"attempt"`
	Engine               string `json:"engine"`
	Status               string `json:"status"`
	Comparable           bool   `json:"comparable"`
	V1Allow              bool   `json:"v1_allow"`
	V2Allow              bool   `json:"v2_allow"`
	PermissionDifference bool   `json:"permission_difference"`
	EvidencePath         string `json:"evidence_path"`
	EvidenceSHA256       string `json:"evidence_sha256"`
	StartedAt            string `json:"started_at"`
	CompletedAt          string `json:"completed_at"`
}

func (r Record) row() []string {
	return []string{
		strconv.Itoa(r.Ordinal),
		r.SampleID,
		r.Source,
		r.SampleSHA256,
		r.ScenarioSHA256,
		r.ObjectKey,
		r.ObjectCanonicalID,
		r.InputHex,
		strconv.Itoa(r.InputBytes),
		r.ActorRole,
		r.Action,
		strconv.FormatBool(r.TenantMatch),
		r.RequestDevice,
		strconv.FormatInt(int64(r.DeviceASkewMS), 10),
		strconv.FormatInt(int64(r.DeviceBSkewMS), 10),
		strconv.FormatBool(r.V1Allow),
		r.V1Reason,
		r.V1SelectedReplica,
		strconv.FormatBool(r.V2Allow),
		r.V2Reason,
		r.V2SelectedReplica,
		strconv.FormatBool(r.PermissionDifference),
		r.DifferentFields,
		r.RootCause,
		r.FixRuleID,
		r.FixSummary,
		strconv.FormatBool(r.FixVerified),
		strconv.Itoa(r.Attempts),
		strconv.Itoa(r.LatestAttempt),
		r.EvidencePath,
		r.EvidenceSHA256,
		r.ReplayCommand,
	}
}

func (a AttemptRecord) row() []string {
	return []string{
		a.SampleID,
		strconv.Itoa(a.Attempt),
		a.Engine,
		a.Status,
		strconv.FormatBool(a.Comparable),
		strconv.FormatBool(a.V1Allow),
		strconv.FormatBool(a.V2Allow),
		strconv.FormatBool(a.PermissionDifference),
		a.EvidencePath,
		a.EvidenceSHA256,
		a.StartedAt,
		a.CompletedAt,
	}
}

func evidenceName(sampleID string, attempt int) string {
	return fmt.Sprintf("evidence/%s-a%04d.json", sampleID, attempt)
}
