package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"example.com/migration-review/internal/model"
	"example.com/migration-review/internal/sqlscan"
)

type Actor struct {
	Capabilities []string `json:"capabilities"`
	Description  string   `json:"description,omitempty"`
}

type Config struct {
	Version int              `json:"version"`
	Actors  map[string]Actor `json:"actors"`
}

type Options struct {
	AllowDestructive bool
	AllowAttach      bool
	AllowAdmin       bool
	ApprovalID       string
}

type Engine struct {
	config    Config
	canonical []byte
	hash      string
}

func Load(data []byte) (*Engine, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("policy is empty")
	}
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	if cfg.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version %d", cfg.Version)
	}
	if len(cfg.Actors) == 0 {
		return nil, fmt.Errorf("policy must define at least one actor")
	}
	known := capabilitySet(model.AllCapabilities())
	for name, actor := range cfg.Actors {
		if strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("actor name cannot be empty")
		}
		for _, cap := range actor.Capabilities {
			if _, ok := known[model.Capability(cap)]; !ok {
				return nil, fmt.Errorf("actor %q has unknown capability %q", name, cap)
			}
		}
		sort.Strings(cfg.Actors[name].Capabilities)
	}
	canonical, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("canonicalize policy: %w", err)
	}
	return &Engine{config: cfg, canonical: canonical, hash: model.SHA256Hex(canonical)}, nil
}

func (e *Engine) Hash() string {
	return e.hash
}

func (e *Engine) Canonical() []byte {
	return append([]byte(nil), e.canonical...)
}

func (e *Engine) Authorize(manifest *model.Manifest, opts Options) model.PermissionDecision {
	decision := model.PermissionDecision{
		Actor:        manifest.Actor,
		Format:       manifest.Format,
		PolicySHA256: e.hash,
		EvaluatedAt:  time.Now().UTC(),
	}
	granted, actorExists := e.granted(manifest.Actor)
	var denials []string
	for _, stmt := range manifest.Statements {
		sd := model.StatementDecision{
			Index:     stmt.Index,
			Actor:     manifest.Actor,
			Granted:   granted,
			Statement: stmt.SQL,
			Target:    stmt.Target,
		}
		capability, keyword, token, classReason := classify(stmt.SQL)
		sd.Keyword = keyword
		sd.Capability = capability
		localLine, localCol := sqlscan.LineColumn(stmt.SQL, token.Start)
		line := stmt.BaseLine + localLine - 1
		col := localCol
		if localLine == 1 {
			col = stmt.BaseColumn + localCol - 1
		}
		sd.Trigger = model.Trigger{
			File:   stmt.Source,
			Line:   line,
			Column: col,
			Offset: token.Start,
			Token:  token.Text,
		}
		if sd.Trigger.Token == "" {
			sd.Trigger.Token = keyword
		}
		if !actorExists {
			sd.Allowed = false
			sd.Reason = fmt.Sprintf("actor %q is not present in the policy", manifest.Actor)
		} else if !contains(granted, string(capability)) {
			sd.Allowed = false
			sd.Reason = fmt.Sprintf("%s requires %q; actor %q has [%s]", classReason, capability, manifest.Actor, strings.Join(granted, ", "))
		} else {
			sd.Allowed, sd.OperatorOpt, sd.Reason = operatorGate(capability, opts)
		}
		if !sd.Allowed {
			denials = append(denials, fmt.Sprintf("statement %d at %s: %s", stmt.Index+1, sd.Trigger.String(), sd.Reason))
		}
		decision.Statements = append(decision.Statements, sd)
	}
	decision.Allowed = len(denials) == 0 && len(decision.Statements) > 0
	if len(denials) > 0 {
		decision.DenyReason = strings.Join(denials, "; ")
	}
	if len(decision.Statements) == 0 {
		decision.DenyReason = "manifest has no executable statements"
	}
	return decision
}

func (e *Engine) granted(actorName string) ([]string, bool) {
	actor, ok := e.config.Actors[actorName]
	if !ok {
		return nil, false
	}
	out := append([]string(nil), actor.Capabilities...)
	sort.Strings(out)
	return out, true
}

func classReason(cap model.Capability) string {
	switch cap {
	case model.CapDestructive:
		return "destructive SQL token"
	case model.CapAttach:
		return "database attach/detach"
	case model.CapAdmin:
		return "privileged or unrecognized SQL"
	case model.CapSchema:
		return "schema-changing SQL"
	case model.CapWrite:
		return "data-changing SQL"
	default:
		return "read-only SQL"
	}
}

func operatorGate(cap model.Capability, opts Options) (bool, string, string) {
	switch cap {
	case model.CapDestructive:
		if !opts.AllowDestructive {
			return false, "--allow-destructive", "destructive capability requires independent operator flag --allow-destructive"
		}
		if strings.TrimSpace(opts.ApprovalID) == "" {
			return false, "--approval-id", "destructive capability requires externally supplied --approval-id"
		}
		return true, "--allow-destructive", "destructive capability allowed by operator and approval id"
	case model.CapAttach:
		if !opts.AllowAttach {
			return false, "--allow-attach", "attach capability requires independent operator flag --allow-attach"
		}
		return true, "--allow-attach", "attach capability allowed by operator"
	case model.CapAdmin:
		if !opts.AllowAdmin {
			return false, "--allow-admin", "admin capability requires independent operator flag --allow-admin"
		}
		return true, "--allow-admin", "admin capability allowed by operator"
	default:
		return true, "", string(cap) + " capability granted by policy"
	}
}

func classify(sqlText string) (model.Capability, string, sqlscan.Token, string) {
	tokens := sqlscan.Tokens(sqlText, 0)
	if len(tokens) == 0 {
		return model.CapAdmin, "", sqlscan.Token{Start: 0}, "empty or comment-only statement"
	}
	first := tokens[0]
	best := model.CapRead
	bestToken := first
	for i, token := range tokens {
		cap := tokenCapability(token.Upper)
		if cap == "" {
			continue
		}
		if token.Upper == "PRAGMA" && i == 0 {
			if strings.Contains(sqlText[token.End:], "=") {
				cap = model.CapAdmin
			}
		}
		if priority(cap) > priority(best) {
			best = cap
			bestToken = token
		}
	}
	if tokenCapability(first.Upper) == "" {
		return model.CapAdmin, first.Upper, first, classReason(model.CapAdmin)
	}
	if priority(best) == priority(model.CapRead) {
		firstCap := tokenCapability(first.Upper)
		if priority(firstCap) == priority(model.CapRead) {
			return model.CapRead, first.Upper, first, classReason(model.CapRead)
		}
	}
	return best, bestToken.Upper, bestToken, classReason(best)
}

func tokenCapability(upper string) model.Capability {
	switch upper {
	case "SELECT", "EXPLAIN", "VALUES", "WITH":
		return model.CapRead
	case "INSERT", "UPDATE", "DELETE", "REPLACE", "UPSERT":
		return model.CapWrite
	case "CREATE", "ALTER", "RENAME", "REINDEX", "ANALYZE":
		return model.CapSchema
	case "DROP", "TRUNCATE":
		return model.CapDestructive
	case "ATTACH", "DETACH":
		return model.CapAttach
	case "PRAGMA", "VACUUM":
		return model.CapAdmin
	case "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE":
		return model.CapAdmin
	default:
		return ""
	}
}

func priority(cap model.Capability) int {
	switch cap {
	case model.CapAdmin:
		return 6
	case model.CapDestructive:
		return 5
	case model.CapAttach:
		return 4
	case model.CapSchema:
		return 3
	case model.CapWrite:
		return 2
	default:
		return 1
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func capabilitySet(caps []model.Capability) map[model.Capability]struct{} {
	out := make(map[model.Capability]struct{}, len(caps))
	for _, cap := range caps {
		out[cap] = struct{}{}
	}
	return out
}
