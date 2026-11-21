package parse

import (
	"bytes"
	"encoding/json"

	"lfireview/internal/model"
)

// v1Object is the legacy flat snapshot record.
type v1Object struct {
	CorrelationID string `json:"correlation_id"`
	Payload       string `json:"payload"`
	TriggerFile   string `json:"trigger_file"`
	TriggerLine   int    `json:"trigger_line"`
	TriggerSymbol string `json:"trigger_symbol"`
	AccessVerdict string `json:"access_verdict"`
	AccessRule    string `json:"access_rule"`
	LogFile       string `json:"log_file"`
	LogLine       int    `json:"log_line"`
	LogEvidence   string `json:"log_evidence"`
}

// v2Envelope is the current versioned, nested snapshot record.
type v2Envelope struct {
	Schema   string `json:"schema"`
	Incident struct {
		CorrelationID string `json:"correlation_id"`
		Attack        struct {
			Input    string `json:"input"`
			Encoding string `json:"encoding"`
		} `json:"attack"`
		Trigger struct {
			File   string `json:"file"`
			Line   int    `json:"line"`
			Symbol string `json:"symbol"`
		} `json:"trigger"`
		Permission struct {
			Decision string `json:"decision"`
			Rule     string `json:"rule"`
		} `json:"permission"`
		Log struct {
			Path    string `json:"path"`
			Line    int    `json:"line"`
			Snippet string `json:"snippet"`
		} `json:"log"`
	} `json:"incident"`
}

func mergeV1(rec model.EvidenceRecord, v v1Object) model.EvidenceRecord {
	rec.CorrelationID = v.CorrelationID
	rec.AttackInput = v.Payload
	rec.TriggerFile = v.TriggerFile
	rec.TriggerLine = v.TriggerLine
	rec.TriggerSymbol = v.TriggerSymbol
	rec.PermissionDecision = normalizeVerdict(v.AccessVerdict)
	rec.PermissionRule = v.AccessRule
	rec.LogPath = v.LogFile
	rec.LogLine = v.LogLine
	rec.LogSnippet = v.LogEvidence
	return rec
}

func mergeV2(rec model.EvidenceRecord, v v2Envelope) model.EvidenceRecord {
	rec.CorrelationID = v.Incident.CorrelationID
	rec.AttackInput = v.Incident.Attack.Input
	rec.TriggerFile = v.Incident.Trigger.File
	rec.TriggerLine = v.Incident.Trigger.Line
	rec.TriggerSymbol = v.Incident.Trigger.Symbol
	rec.PermissionDecision = normalizeVerdict(v.Incident.Permission.Decision)
	rec.PermissionRule = v.Incident.Permission.Rule
	rec.LogPath = v.Incident.Log.Path
	rec.LogLine = v.Incident.Log.Line
	rec.LogSnippet = v.Incident.Log.Snippet
	return rec
}

func normalizeVerdict(raw string) model.PermissionDecision {
	switch string(bytes.ToLower(bytes.TrimSpace([]byte(raw)))) {
	case "permit", "allow", "allowed":
		return model.PermitAll
	case "deny", "denied", "blocked":
		return model.DenyAll
	default:
		return model.PermUnknown
	}
}

// tolerantV1 recovers a legacy record from its valid key/value prefix.
func tolerantV1(data []byte) (v1Object, bool) {
	kv, ok := tolerantExtract(data)
	if !ok {
		return v1Object{}, false
	}
	var out v1Object
	got := false
	if s, ok := kv["correlation_id"].(string); ok {
		out.CorrelationID, got = s, true
	}
	if s, ok := kv["payload"].(string); ok {
		out.Payload, got = s, true
	}
	if s, ok := kv["trigger_file"].(string); ok {
		out.TriggerFile, got = s, true
	}
	if n, ok := kv["trigger_line"].(json.Number); ok {
		out.TriggerLine = atoiSafe(n)
		got = true
	}
	if s, ok := kv["trigger_symbol"].(string); ok {
		out.TriggerSymbol, got = s, true
	}
	if s, ok := kv["access_verdict"].(string); ok {
		out.AccessVerdict, got = s, true
	}
	if s, ok := kv["access_rule"].(string); ok {
		out.AccessRule, got = s, true
	}
	if s, ok := kv["log_file"].(string); ok {
		out.LogFile, got = s, true
	}
	if n, ok := kv["log_line"].(json.Number); ok {
		out.LogLine = atoiSafe(n)
		got = true
	}
	if s, ok := kv["log_evidence"].(string); ok {
		out.LogEvidence, got = s, true
	}
	return out, got
}

// tolerantV2 recovers a current-format record from its valid prefix.
func tolerantV2(data []byte) (v2Envelope, bool) {
	kv, ok := tolerantExtract(data)
	if !ok {
		return v2Envelope{}, false
	}
	var out v2Envelope
	got := false
	put := func(path string, fn func(any)) {
		if v, present := kv[path]; present {
			fn(v)
			got = true
		}
	}
	put("incident.correlation_id", func(v any) {
		out.Incident.CorrelationID, _ = v.(string)
	})
	put("incident.attack.input", func(v any) {
		out.Incident.Attack.Input, _ = v.(string)
	})
	put("incident.attack.encoding", func(v any) {
		out.Incident.Attack.Encoding, _ = v.(string)
	})
	put("incident.trigger.file", func(v any) {
		out.Incident.Trigger.File, _ = v.(string)
	})
	put("incident.trigger.line", func(v any) {
		if n, ok := v.(json.Number); ok {
			out.Incident.Trigger.Line = atoiSafe(n)
		}
	})
	put("incident.trigger.symbol", func(v any) {
		out.Incident.Trigger.Symbol, _ = v.(string)
	})
	put("incident.permission.decision", func(v any) {
		out.Incident.Permission.Decision, _ = v.(string)
	})
	put("incident.permission.rule", func(v any) {
		out.Incident.Permission.Rule, _ = v.(string)
	})
	put("incident.log.path", func(v any) {
		out.Incident.Log.Path, _ = v.(string)
	})
	put("incident.log.line", func(v any) {
		if n, ok := v.(json.Number); ok {
			out.Incident.Log.Line = atoiSafe(n)
		}
	})
	put("incident.log.snippet", func(v any) {
		out.Incident.Log.Snippet, _ = v.(string)
	})
	return out, got
}

// tolerantExtract walks JSON tokens until the stream ends (including an
// unexpected EOF) and returns every leaf value keyed by its dotted path.
// The second result is false when no object could be entered at all.
func tolerantExtract(data []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	kv := map[string]any{}
	path := make([]string, 0, 8)
	pendingKey := ""
	enteredObject := false

	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				enteredObject = true
				path = append(path, pendingKey)
				pendingKey = ""
			case '}':
				if len(path) > 0 {
					path = path[:len(path)-1]
				}
			case '[':
				path = append(path, pendingKey)
				pendingKey = ""
			case ']':
				if len(path) > 0 {
					path = path[:len(path)-1]
				}
			}
		case string:
			if pendingKey == "" && dec.More() {
				pendingKey = t
			} else {
				storeLeaf(kv, path, pendingKey, t)
				pendingKey = ""
			}
		case json.Number, bool, nil:
			storeLeaf(kv, path, pendingKey, t)
			pendingKey = ""
		}
	}
	return kv, enteredObject
}

func storeLeaf(kv map[string]any, path []string, key string, value any) {
	if key == "" {
		return
	}
	parts := make([]string, 0, len(path)+1)
	for _, p := range path {
		if p != "" {
			parts = append(parts, p)
		}
	}
	parts = append(parts, key)
	joined := ""
	for i, p := range parts {
		if i > 0 {
			joined += "."
		}
		joined += p
	}
	kv[joined] = value
}

func atoiSafe(n json.Number) int {
	v, err := n.Int64()
	if err != nil {
		return 0
	}
	return int(v)
}
