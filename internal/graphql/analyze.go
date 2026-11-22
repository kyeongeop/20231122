package graphql

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const DefaultLimit = 4

type Step struct {
	Seq         int             `json:"seq"`
	Stage       string          `json:"stage"`
	Input       json.RawMessage `json:"input"`
	StateBefore json.RawMessage `json:"state_before"`
	StateAfter  json.RawMessage `json:"state_after"`
	Result      json.RawMessage `json:"result"`
	Status      string          `json:"status"`
	ErrorCode   string          `json:"error_code,omitempty"`
	ErrorDetail string          `json:"error_detail,omitempty"`
}

type Failure struct {
	Seq    int    `json:"seq"`
	Stage  string `json:"stage"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type Trace struct {
	Query      string          `json:"query"`
	Limit      int             `json:"limit"`
	Steps      []Step          `json:"steps"`
	FirstError *Failure        `json:"first_error,omitempty"`
	FinalState json.RawMessage `json:"final_state"`
}

type state struct {
	Bytes         int    `json:"bytes"`
	InputSHA256   string `json:"input_sha256"`
	Tokens        int    `json:"tokens"`
	OpenBraces    int    `json:"open_braces"`
	SyntaxOK      bool   `json:"syntax_ok"`
	SyntaxError   string `json:"syntax_error,omitempty"`
	MaxDepth      int    `json:"max_depth"`
	DepthComplete bool   `json:"depth_complete"`
	Limit         int    `json:"limit"`
	Decision      string `json:"decision"`
}

type token struct {
	Kind   string `json:"kind"`
	Text   string `json:"text,omitempty"`
	Offset int    `json:"offset"`
}

type lexicalResult struct {
	Tokens []token `json:"tokens"`
	Err    string  `json:"error,omitempty"`
	Offset int     `json:"error_offset,omitempty"`
}

type syntaxResult struct {
	OK         bool   `json:"ok"`
	OpenBraces int    `json:"open_braces"`
	Code       string `json:"code,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type depthResult struct {
	MaxDepth int    `json:"max_depth"`
	Complete bool   `json:"complete"`
	Code     string `json:"code,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type policyResult struct {
	Decision string `json:"decision"`
	Limit    int    `json:"limit"`
	MaxDepth int    `json:"max_depth"`
	Code     string `json:"code,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

func Analyze(query string, limit int) Trace {
	if limit <= 0 {
		limit = DefaultLimit
	}

	sum := sha256.Sum256([]byte(query))
	current := state{
		Bytes:       len(query),
		InputSHA256: hex.EncodeToString(sum[:]),
		Limit:       limit,
	}
	trace := Trace{Query: query, Limit: limit}

	step, next := ingestStep(current, query)
	trace.Steps = append(trace.Steps, step)
	current = next

	lex := tokenize(query)
	step, next = tokenizeStep(current, query, lex, limit)
	trace.Steps = append(trace.Steps, step)
	current = next

	syntax := checkSyntax(lex)
	step, next = syntaxStep(current, query, lex, syntax, limit)
	trace.Steps = append(trace.Steps, step)
	current = next

	depth := measureDepth(lex, syntax)
	step, next = depthStep(current, query, depth, limit)
	trace.Steps = append(trace.Steps, step)
	current = next

	policy := decidePolicy(depth, limit)
	step, next = policyStep(current, query, policy, limit)
	trace.Steps = append(trace.Steps, step)
	current = next

	trace.FinalState = toJSON(current)
	for i := range trace.Steps {
		if trace.Steps[i].Status == "error" {
			trace.FirstError = &Failure{
				Seq:    trace.Steps[i].Seq,
				Stage:  trace.Steps[i].Stage,
				Code:   trace.Steps[i].ErrorCode,
				Detail: trace.Steps[i].ErrorDetail,
			}
			break
		}
	}
	return trace
}

func ingestStep(before state, query string) (Step, state) {
	after := before
	after.Bytes = len(query)
	after.InputSHA256 = hashString(query)
	input := toJSON(map[string]any{"query": query})
	result := toJSON(map[string]any{
		"accepted": true,
		"bytes":    len(query),
		"sha256":   after.InputSHA256,
	})
	return makeStep(1, "ingest", input, before, after, result, "", ""), after
}

func tokenizeStep(before state, query string, lex lexicalResult, limit int) (Step, state) {
	after := before
	after.Tokens = len(lex.Tokens)
	after.Limit = limit
	input := toJSON(map[string]any{"query": query})
	result := toJSON(map[string]any{
		"token_count":  len(lex.Tokens),
		"tokens":       lex.Tokens,
		"error":        lex.Err,
		"error_offset": lex.Offset,
	})
	if lex.Err != "" {
		return makeStep(2, "tokenize", input, before, after, result, "LEXICAL_ERROR", lex.Err), after
	}
	return makeStep(2, "tokenize", input, before, after, result, "", ""), after
}

func syntaxStep(before state, query string, lex lexicalResult, syntax syntaxResult, limit int) (Step, state) {
	after := before
	after.OpenBraces = syntax.OpenBraces
	after.SyntaxOK = syntax.OK
	after.Limit = limit
	input := toJSON(map[string]any{"query": query})
	result := toJSON(syntax)
	if lex.Err != "" {
		after.SyntaxError = "PRECONDITION_FAILED"
		return makeStep(3, "syntax", input, before, after, result, "PRECONDITION_FAILED",
			"syntax check cannot complete after lexical error"), after
	}
	if !syntax.OK {
		after.SyntaxError = syntax.Code
		return makeStep(3, "syntax", input, before, after, result, syntax.Code, syntax.Detail), after
	}
	return makeStep(3, "syntax", input, before, after, result, "", ""), after
}

func depthStep(before state, query string, depth depthResult, limit int) (Step, state) {
	after := before
	after.MaxDepth = depth.MaxDepth
	after.DepthComplete = depth.Complete
	after.Limit = limit
	if !depth.Complete {
		after.MaxDepth = 0
	}
	input := toJSON(map[string]any{"query": query})
	result := toJSON(depth)
	if !depth.Complete {
		return makeStep(4, "depth", input, before, after, result, "PRECONDITION_FAILED",
			depth.Detail), after
	}
	return makeStep(4, "depth", input, before, after, result, "", ""), after
}

func policyStep(before state, query string, policy policyResult, limit int) (Step, state) {
	after := before
	after.Decision = policy.Decision
	after.Limit = limit
	input := toJSON(map[string]any{"query": query, "limit": limit})
	result := toJSON(policy)
	if policy.Code != "" {
		return makeStep(5, "policy", input, before, after, result, policy.Code, policy.Detail), after
	}
	return makeStep(5, "policy", input, before, after, result, "", ""), after
}

func makeStep(seq int, stage string, input json.RawMessage, before, after state, result json.RawMessage, code, detail string) Step {
	status := "ok"
	if code != "" {
		status = "error"
	}
	return Step{
		Seq:         seq,
		Stage:       stage,
		Input:       input,
		StateBefore: toJSON(before),
		StateAfter:  toJSON(after),
		Result:      result,
		Status:      status,
		ErrorCode:   code,
		ErrorDetail: detail,
	}
}

func tokenize(query string) lexicalResult {
	var out lexicalResult
	for i := 0; i < len(query); {
		c := query[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',':
			i++
		case c == '#':
			for i < len(query) && query[i] != '\n' {
				i++
			}
		case c == '"':
			start := i
			i++
			closed := false
			for i < len(query) {
				if query[i] == '\\' {
					i += 2
					continue
				}
				if query[i] == '"' {
					i++
					closed = true
					break
				}
				if query[i] == '\n' || query[i] == '\r' {
					out.Err = fmt.Sprintf("newline in string at byte %d", i)
					out.Offset = i
					return out
				}
				i++
			}
			if !closed {
				out.Err = fmt.Sprintf("unterminated string at byte %d", start)
				out.Offset = start
				return out
			}
			out.Tokens = append(out.Tokens, token{Kind: "String", Text: query[start:i], Offset: start})
		case isNameStart(c):
			start := i
			i++
			for i < len(query) && isNameContinue(query[i]) {
				i++
			}
			out.Tokens = append(out.Tokens, token{Kind: "Name", Text: query[start:i], Offset: start})
		case strings.ContainsRune("{}()[]:!$=@|&", rune(c)):
			out.Tokens = append(out.Tokens, token{Kind: string(c), Text: string(c), Offset: i})
			i++
		case c == '-' || (c >= '0' && c <= '9'):
			start := i
			i++
			for i < len(query) && ((query[i] >= '0' && query[i] <= '9') || query[i] == '.' || query[i] == 'e' || query[i] == 'E' || query[i] == '+' || query[i] == '-') {
				i++
			}
			out.Tokens = append(out.Tokens, token{Kind: "Number", Text: query[start:i], Offset: start})
		default:
			out.Err = fmt.Sprintf("unexpected character %q at byte %d", c, i)
			out.Offset = i
			return out
		}
	}
	return out
}

func checkSyntax(lex lexicalResult) syntaxResult {
	if lex.Err != "" {
		return syntaxResult{OK: false, Code: "PRECONDITION_FAILED", Detail: "lexical error: " + lex.Err}
	}
	if len(lex.Tokens) == 0 {
		return syntaxResult{OK: false, Code: "EMPTY_DOCUMENT", Detail: "document contains no tokens"}
	}
	type open struct {
		kind string
		pos  int
	}
	var stack []open
	openBraces := 0
	pairs := map[string]string{")": "(", "]": "[", "}": "{"}
	for _, tok := range lex.Tokens {
		switch tok.Kind {
		case "{", "(", "[":
			stack = append(stack, open{kind: tok.Kind, pos: tok.Offset})
			if tok.Kind == "{" {
				openBraces++
			}
		case "}", ")", "]":
			if len(stack) == 0 {
				return syntaxResult{OK: false, Code: "MISMATCHED_DELIMITER",
					Detail: fmt.Sprintf("unexpected %q at byte %d", tok.Kind, tok.Offset)}
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if top.kind != pairs[tok.Kind] {
				return syntaxResult{OK: false, Code: "MISMATCHED_DELIMITER",
					Detail: fmt.Sprintf("expected close for %q at byte %d, got %q at byte %d", top.kind, top.pos, tok.Kind, tok.Offset)}
			}
			if tok.Kind == "}" {
				openBraces--
			}
		}
	}
	if len(stack) > 0 {
		top := stack[len(stack)-1]
		return syntaxResult{OK: false, OpenBraces: openBraces, Code: "UNCLOSED_DELIMITER",
			Detail: fmt.Sprintf("unclosed %q opened at byte %d", top.kind, top.pos)}
	}
	return syntaxResult{OK: true, OpenBraces: 0}
}

func measureDepth(lex lexicalResult, syntax syntaxResult) depthResult {
	if !syntax.OK {
		return depthResult{Complete: false, Code: "PRECONDITION_FAILED",
			Detail: "depth cannot be trusted before syntax passes"}
	}
	braces := 0
	parens := 0
	brackets := 0
	maxDepth := 0
	for _, tok := range lex.Tokens {
		switch tok.Kind {
		case "{":
			braces++
		case "}":
			braces--
		case "(":
			parens++
		case ")":
			parens--
		case "[":
			brackets++
		case "]":
			brackets--
		case "Name":
			if parens == 0 && brackets == 0 && braces > 0 {
				if braces > maxDepth {
					maxDepth = braces
				}
			}
		}
	}
	return depthResult{MaxDepth: maxDepth, Complete: true}
}

func decidePolicy(depth depthResult, limit int) policyResult {
	if !depth.Complete {
		return policyResult{Decision: "blocked", Limit: limit, Code: "PRECONDITION_FAILED",
			Detail: "policy requires a complete depth measurement"}
	}
	if depth.MaxDepth > limit {
		return policyResult{Decision: "blocked", Limit: limit, MaxDepth: depth.MaxDepth,
			Code:   "DEPTH_LIMIT_EXCEEDED",
			Detail: fmt.Sprintf("max depth %d exceeds limit %d", depth.MaxDepth, limit)}
	}
	return policyResult{Decision: "allow", Limit: limit, MaxDepth: depth.MaxDepth}
}

func toJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isNameContinue(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9')
}
