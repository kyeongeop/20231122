package domain

import (
	"encoding/json"
	"fmt"
	"strings"
)

const EvidenceSchemaVersion = 1

type Decision struct {
	Version             string `json:"version"`
	Allow               bool   `json:"allow"`
	Reason              string `json:"reason"`
	SelectedReplica     string `json:"selected_replica"`
	SelectedDevice      string `json:"selected_device"`
	SelectedRevision    uint32 `json:"selected_revision"`
	SelectedUpdatedAtMS int64  `json:"selected_updated_at_ms"`
	SelectedLocalTimeMS int64  `json:"selected_local_time_ms"`
	EffectiveACL        byte   `json:"effective_acl"`
	Deleted             bool   `json:"deleted"`
}

type Comparison struct {
	PermissionDifference bool     `json:"permission_difference"`
	DifferentFields      []string `json:"different_fields"`
	RootCause            string   `json:"root_cause"`
	Summary              string   `json:"summary"`
}

type DeviceObservation struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	SkewMS         int32  `json:"skew_ms"`
	RequestClockMS int64  `json:"request_clock_ms"`
}

type Evidence struct {
	SchemaVersion   int                  `json:"schema_version"`
	SampleSHA256    string               `json:"sample_sha256"`
	ScenarioSHA256  string               `json:"scenario_sha256"`
	InputHex        string               `json:"input_hex"`
	InputBytes      int                  `json:"input_bytes"`
	Engine          string               `json:"engine"`
	DetectionSource string               `json:"detection_source"`
	FuzzerSHA256    string               `json:"fuzzer_sha256,omitempty"`
	FuzzerCommand   []string             `json:"fuzzer_command,omitempty"`
	Scenario        Scenario             `json:"scenario"`
	Attack          Attack               `json:"attack"`
	Devices         [2]DeviceObservation `json:"devices"`
	V1              Decision             `json:"v1"`
	V2              Decision             `json:"v2"`
	Comparison      Comparison           `json:"comparison"`
}

type FixPlan struct {
	RootCause     string   `json:"root_cause"`
	RuleID        string   `json:"rule_id"`
	Scope         string   `json:"scope"`
	Summary       string   `json:"summary"`
	BeforeV1Allow bool     `json:"before_v1_allow"`
	AfterV1Allow  bool     `json:"after_v1_allow"`
	V2Allow       bool     `json:"v2_allow"`
	Verified      bool     `json:"verified"`
	Verification  []string `json:"verification"`
}

type Evaluation struct {
	Evidence   Evidence   `json:"evidence"`
	Comparison Comparison `json:"comparison"`
	FixPlan    FixPlan    `json:"fix_plan"`
}

type ResolvePolicy string

const (
	ResolveByDeviceClock       ResolvePolicy = "device_clock"
	ResolveByCanonicalRevision ResolvePolicy = "canonical_revision"
)

var FingerprintFieldOrder = []string{
	"v1.allow",
	"v2.allow",
	"v1.selected_replica",
	"v2.selected_replica",
	"v1.reason",
	"v2.reason",
}

func Evaluate(scenario Scenario, input []byte, engine string) (Evaluation, error) {
	attack, err := DecodeAttack(input)
	if err != nil {
		return Evaluation{}, err
	}
	v1 := decide(scenario, attack, ResolveByDeviceClock, "v1")
	v2 := decide(scenario, attack, ResolveByCanonicalRevision, "v2")
	comparison := compareDecisions(v1, v2)
	scenarioHash, err := scenario.Hash()
	if err != nil {
		return Evaluation{}, err
	}
	sampleHash := SHA256Hex(input)
	devices := [2]DeviceObservation{
		{
			ID:             scenario.Devices[0].ID,
			Name:           scenario.Devices[0].Name,
			SkewMS:         attack.SkewAMS,
			RequestClockMS: requestClock(scenario, attack, scenario.Devices[0].ID),
		},
		{
			ID:             scenario.Devices[1].ID,
			Name:           scenario.Devices[1].Name,
			SkewMS:         attack.SkewBMS,
			RequestClockMS: requestClock(scenario, attack, scenario.Devices[1].ID),
		},
	}
	evidence := Evidence{
		SchemaVersion:   EvidenceSchemaVersion,
		SampleSHA256:    sampleHash,
		ScenarioSHA256:  scenarioHash,
		InputHex:        Hex(input),
		InputBytes:      len(input),
		Engine:          engine,
		DetectionSource: engine,
		Scenario:        scenario,
		Attack:          attack,
		Devices:         devices,
		V1:              v1,
		V2:              v2,
		Comparison:      comparison,
	}
	fixPlan := buildFixPlan(scenario, attack, v1, v2, comparison)
	return Evaluation{Evidence: evidence, Comparison: comparison, FixPlan: fixPlan}, nil
}

func decide(scenario Scenario, attack Attack, policy ResolvePolicy, version string) Decision {
	replica := resolveReplica(scenario, attack, policy)
	effectiveACL := effectiveACL(attack.ActorRole, replica.ACL)
	decision := Decision{
		Version:             version,
		Reason:              "allow",
		SelectedReplica:     replica.Name,
		SelectedDevice:      replica.DeviceID,
		SelectedRevision:    replica.Revision,
		SelectedUpdatedAtMS: replica.UpdatedAtMS,
		SelectedLocalTimeMS: replica.UpdatedAtMS + int64(skewForDevice(scenario, attack, replica.DeviceID)),
		EffectiveACL:        effectiveACL,
		Deleted:             replica.Deleted,
	}
	switch {
	case !attack.TenantMatch:
		decision.Reason = "tenant_mismatch"
	case attack.ActorRole == RoleOutsider:
		decision.Reason = "role_denied"
	case replica.Deleted:
		decision.Reason = "selected_replica_deleted"
	case effectiveACL&attack.Action.Permission() == 0:
		decision.Reason = "acl_denied"
	default:
		decision.Allow = true
	}
	return decision
}

func resolveReplica(scenario Scenario, attack Attack, policy ResolvePolicy) Replica {
	a, b := scenario.Object.Replicas[0], scenario.Object.Replicas[1]
	switch policy {
	case ResolveByCanonicalRevision:
		if b.Revision > a.Revision {
			return b
		}
		if b.Revision == a.Revision && b.UpdatedAtMS > a.UpdatedAtMS {
			return b
		}
		return a
	default:
		aLocal := a.UpdatedAtMS + int64(skewForDevice(scenario, attack, a.DeviceID))
		bLocal := b.UpdatedAtMS + int64(skewForDevice(scenario, attack, b.DeviceID))
		if bLocal > aLocal {
			return b
		}
		return a
	}
}

func skewForDevice(scenario Scenario, attack Attack, deviceID string) int32 {
	if deviceID == scenario.Devices[1].ID {
		return attack.SkewBMS
	}
	return attack.SkewAMS
}

func requestClock(scenario Scenario, attack Attack, deviceID string) int64 {
	latest := scenario.Object.Replicas[0].UpdatedAtMS
	if scenario.Object.Replicas[1].UpdatedAtMS > latest {
		latest = scenario.Object.Replicas[1].UpdatedAtMS
	}
	return latest + int64(skewForDevice(scenario, attack, deviceID))
}

func effectiveACL(role ActorRole, acl byte) byte {
	switch role {
	case RoleOwner:
		return PermRead | PermUpdate | PermDelete
	case RoleEditor:
		return acl
	case RoleViewer:
		return acl & PermRead
	default:
		return 0
	}
}

func compareDecisions(v1, v2 Decision) Comparison {
	fields := make([]string, 0, 3)
	if v1.Allow != v2.Allow {
		fields = append(fields, "allow")
	}
	if v1.SelectedReplica != v2.SelectedReplica {
		fields = append(fields, "selected_replica")
	}
	if v1.Reason != v2.Reason {
		fields = append(fields, "reason")
	}
	different := v1.Allow != v2.Allow
	rootCause := ""
	summary := "v1 and v2 permission decisions agree"
	if different {
		if v1.SelectedReplica != v2.SelectedReplica {
			rootCause = "duplicate_resolution_clock_skew"
		} else {
			rootCause = "permission_evaluation_divergence"
		}
		summary = fmt.Sprintf(
			"v1=%s (%s on %s), v2=%s (%s on %s)",
			allowWord(v1.Allow), v1.Reason, v1.SelectedReplica,
			allowWord(v2.Allow), v2.Reason, v2.SelectedReplica,
		)
	}
	return Comparison{
		PermissionDifference: different,
		DifferentFields:      fields,
		RootCause:            rootCause,
		Summary:              summary,
	}
}

func allowWord(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

func buildFixPlan(scenario Scenario, attack Attack, v1, v2 Decision, comparison Comparison) FixPlan {
	fixedV1 := decide(scenario, attack, ResolveByCanonicalRevision, "v1-fixed")
	plan := FixPlan{
		RootCause:     comparison.RootCause,
		RuleID:        "v1.canonical-duplicate-resolver",
		Scope:         "v1 duplicate resolver only",
		BeforeV1Allow: v1.Allow,
		AfterV1Allow:  fixedV1.Allow,
		V2Allow:       v2.Allow,
		Verified:      fixedV1.Allow == v2.Allow,
		Verification: []string{
			"replay the same sample bytes with v1 resolver set to canonical_revision",
			"expect v1 allow/deny to match v2 for this sample",
			"rerun the sample three times and compare the decision fingerprint",
			"verify every evidence file against SHA256SUMS before review",
		},
	}
	if comparison.PermissionDifference {
		plan.Summary = "Normalize device-clock timestamps before duplicate resolution, then select by canonical revision with a stable replica-id tie-breaker. Apply this only to the v1 duplicate resolver and keep both API versions on one shared resolver."
	} else {
		plan.Summary = "No local correction is required for this sample; v1 and v2 agree."
	}
	return plan
}

func (e Evaluation) EvidenceJSON() ([]byte, error) {
	return json.MarshalIndent(e.Evidence, "", "  ")
}

func CompareFingerprints(left, right Evidence) []string {
	changed := make(map[string]bool, len(FingerprintFieldOrder))
	if left.V1.Allow != right.V1.Allow {
		changed["v1.allow"] = true
	}
	if left.V2.Allow != right.V2.Allow {
		changed["v2.allow"] = true
	}
	if left.V1.SelectedReplica != right.V1.SelectedReplica {
		changed["v1.selected_replica"] = true
	}
	if left.V2.SelectedReplica != right.V2.SelectedReplica {
		changed["v2.selected_replica"] = true
	}
	if left.V1.Reason != right.V1.Reason {
		changed["v1.reason"] = true
	}
	if left.V2.Reason != right.V2.Reason {
		changed["v2.reason"] = true
	}
	return OrderedFingerprintFields(changed)
}

func OrderedFingerprintFields(changed map[string]bool) []string {
	fields := make([]string, 0, len(changed))
	for _, field := range FingerprintFieldOrder {
		if changed[field] {
			fields = append(fields, field)
		}
	}
	return fields
}

func JoinFields(fields []string) string {
	return strings.Join(fields, ",")
}
