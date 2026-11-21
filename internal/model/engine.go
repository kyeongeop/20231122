package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type OpKind string

const (
	OpSubmit OpKind = "submit"
	OpCancel OpKind = "cancel"
)

type Op struct {
	ID       string `json:"id"`
	Kind     OpKind `json:"kind"`
	Alias    string `json:"alias,omitempty"`
	Target   string `json:"target,omitempty"`
	CancelID string `json:"cancel_id,omitempty"`
}

type Result struct {
	OpID         string   `json:"op_id"`
	Kind         OpKind   `json:"kind"`
	Outcome      string   `json:"outcome"`
	Accepted     bool     `json:"accepted"`
	Detail       string   `json:"detail,omitempty"`
	Alias        string   `json:"alias,omitempty"`
	Target       string   `json:"target,omitempty"`
	ConflictWith []string `json:"conflict_with,omitempty"`
}

type SubmissionView struct {
	OpID            string `json:"op_id"`
	Alias           string `json:"alias"`
	CanonicalAlias  string `json:"canonical_alias"`
	Target          string `json:"target"`
	CanonicalTarget string `json:"canonical_target"`
	Status          string `json:"status"`
}

type AliasView struct {
	Alias        string   `json:"alias"`
	Status       string   `json:"status"`
	Targets      []string `json:"targets"`
	CandidateIDs []string `json:"candidate_ids"`
}

type Mapping struct {
	Alias  string `json:"alias"`
	Target string `json:"target"`
}

type State struct {
	Submissions    []SubmissionView `json:"submissions"`
	Aliases        []AliasView      `json:"aliases"`
	ActiveMappings []Mapping        `json:"active_mappings"`
}

type submission struct {
	Op              Op
	CanonicalAlias  string
	CanonicalTarget string
	Canceled        bool
}

type Engine struct {
	submissions map[string]*submission
	aliasIDs    map[string][]string
	seen        map[string]string
	order       []string
}

func NewEngine() *Engine {
	return &Engine{
		submissions: make(map[string]*submission),
		aliasIDs:    make(map[string][]string),
		seen:        make(map[string]string),
	}
}

func (e *Engine) Apply(op Op) Result {
	fingerprint, _ := json.Marshal(op)
	fp := digest(fingerprint)
	if prior, ok := e.seen[op.ID]; ok {
		if prior == fp {
			return Result{
				OpID: op.ID, Kind: op.Kind, Outcome: "duplicate_noop",
				Detail: "exact operation replay ignored",
			}
		}
		return Result{
			OpID: op.ID, Kind: op.Kind, Outcome: "id_collision",
			Detail: "operation id already used with different input",
		}
	}
	if strings.TrimSpace(op.ID) == "" {
		return Result{OpID: op.ID, Kind: op.Kind, Outcome: "invalid", Detail: "operation id is empty"}
	}

	switch op.Kind {
	case OpSubmit:
		return e.applySubmit(op, fp)
	case OpCancel:
		return e.applyCancel(op, fp)
	default:
		return Result{OpID: op.ID, Kind: op.Kind, Outcome: "invalid", Detail: "unknown operation kind"}
	}
}

func (e *Engine) applySubmit(op Op, fingerprint string) Result {
	alias, err := CanonicalPath(op.Alias)
	if err != nil {
		return invalid(op, "alias: "+err.Error())
	}
	target, err := CanonicalPath(op.Target)
	if err != nil {
		return invalid(op, "target: "+err.Error())
	}

	conflicts := make([]string, 0)
	for _, id := range e.aliasIDs[alias] {
		candidate := e.submissions[id]
		if candidate.Canceled || candidate.CanonicalTarget == target {
			continue
		}
		conflicts = append(conflicts, id)
	}
	sort.Strings(conflicts)

	e.submissions[op.ID] = &submission{
		Op: op, CanonicalAlias: alias, CanonicalTarget: target,
	}
	e.aliasIDs[alias] = append(e.aliasIDs[alias], op.ID)
	e.seen[op.ID] = fingerprint
	e.order = append(e.order, op.ID)

	result := Result{
		OpID: op.ID, Kind: op.Kind, Accepted: true,
		Alias: alias, Target: target, ConflictWith: conflicts,
	}
	if len(conflicts) > 0 {
		result.Outcome = "conflict"
		result.Detail = "alias now has multiple targets; activation blocked"
		return result
	}
	result.Outcome = "activated"
	return result
}

func (e *Engine) applyCancel(op Op, fingerprint string) Result {
	if strings.TrimSpace(op.CancelID) == "" {
		return invalid(op, "cancel_id is empty")
	}
	target, ok := e.submissions[op.CancelID]
	if !ok {
		return invalid(op, "cancel target is not a submitted operation")
	}
	if target.Canceled {
		e.seen[op.ID] = fingerprint
		e.order = append(e.order, op.ID)
		return Result{
			OpID: op.ID, Kind: op.Kind, Outcome: "cancel_noop",
			Detail: "target was already canceled", Accepted: false,
			Alias: target.CanonicalAlias, Target: target.CanonicalTarget,
		}
	}

	target.Canceled = true
	e.seen[op.ID] = fingerprint
	e.order = append(e.order, op.ID)

	result := Result{
		OpID: op.ID, Kind: op.Kind, Outcome: "canceled", Accepted: true,
		Alias: target.CanonicalAlias, Target: target.CanonicalTarget,
	}
	view := e.aliasView(target.CanonicalAlias)
	switch view.Status {
	case "active":
		result.Detail = "cancellation resolved alias to remaining target"
	case "conflicted":
		result.Detail = "cancellation removed one candidate; conflict remains"
	default:
		result.Detail = "cancellation left alias empty"
	}
	return result
}

func invalid(op Op, detail string) Result {
	return Result{OpID: op.ID, Kind: op.Kind, Outcome: "invalid", Detail: detail}
}

func (e *Engine) aliasView(alias string) AliasView {
	view := AliasView{Alias: alias, Targets: []string{}, CandidateIDs: []string{}}
	targetSet := make(map[string]struct{})
	for _, id := range e.aliasIDs[alias] {
		candidate := e.submissions[id]
		if candidate.Canceled {
			continue
		}
		view.CandidateIDs = append(view.CandidateIDs, id)
		targetSet[candidate.CanonicalTarget] = struct{}{}
	}
	sort.Strings(view.CandidateIDs)
	for target := range targetSet {
		view.Targets = append(view.Targets, target)
	}
	sort.Strings(view.Targets)
	switch {
	case len(view.Targets) == 0:
		view.Status = "empty"
	case len(view.Targets) == 1:
		view.Status = "active"
	default:
		view.Status = "conflicted"
	}
	return view
}

func (e *Engine) Snapshot() State {
	state := State{
		Submissions:    make([]SubmissionView, 0, len(e.submissions)),
		Aliases:        make([]AliasView, 0, len(e.aliasIDs)),
		ActiveMappings: make([]Mapping, 0),
	}

	aliases := make([]string, 0, len(e.aliasIDs))
	for alias := range e.aliasIDs {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		view := e.aliasView(alias)
		state.Aliases = append(state.Aliases, view)
		if view.Status == "active" {
			state.ActiveMappings = append(state.ActiveMappings, Mapping{
				Alias: alias, Target: view.Targets[0],
			})
		}
	}

	ids := make([]string, 0, len(e.submissions))
	for id := range e.submissions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		submission := e.submissions[id]
		alias := e.aliasView(submission.CanonicalAlias)
		status := "active"
		switch {
		case submission.Canceled:
			status = "canceled"
		case alias.Status == "conflicted":
			status = "conflicted"
		}
		state.Submissions = append(state.Submissions, SubmissionView{
			OpID:            submission.Op.ID,
			Alias:           submission.Op.Alias,
			CanonicalAlias:  submission.CanonicalAlias,
			Target:          submission.Op.Target,
			CanonicalTarget: submission.CanonicalTarget,
			Status:          status,
		})
	}
	return state
}

func (e *Engine) StateJSON() []byte {
	data, _ := json.Marshal(e.Snapshot())
	return data
}

func (e *Engine) StateDigest() string {
	return digest(e.StateJSON())
}

func (e *Engine) ResolutionDigest() string {
	state := e.Snapshot()
	data, _ := json.Marshal(state.ActiveMappings)
	return digest(data)
}

func (e *Engine) Validate() []string {
	state := e.Snapshot()
	problems := make([]string, 0)
	for _, alias := range state.Aliases {
		if alias.Status == "active" && len(alias.Targets) != 1 {
			problems = append(problems, fmt.Sprintf("%s active with %d targets", alias.Alias, len(alias.Targets)))
		}
		if alias.Status == "conflicted" && len(alias.Targets) < 2 {
			problems = append(problems, fmt.Sprintf("%s conflicted with %d targets", alias.Alias, len(alias.Targets)))
		}
	}
	for _, submission := range state.Submissions {
		if submission.Status == "canceled" && submission.CanonicalAlias == "" {
			problems = append(problems, submission.OpID+" canceled without alias")
		}
	}
	return problems
}

func Digest(data []byte) string {
	return digest(data)
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
