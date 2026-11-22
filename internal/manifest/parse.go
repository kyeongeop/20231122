package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"example.com/migration-review/internal/model"
	"example.com/migration-review/internal/sqlscan"
)

const maxInputBytes = 4 << 20

type rawStatement struct {
	SQL    string `json:"sql"`
	Target string `json:"target,omitempty"`
}

type v2Envelope struct {
	FormatVersion json.RawMessage `json:"format_version"`
	Version       json.RawMessage `json:"version"`
	Migration     struct {
		ID          string          `json:"id"`
		Actor       string          `json:"actor"`
		RequestedBy string          `json:"requested_by"`
		ApprovalID  string          `json:"approval_id"`
		Statements  json.RawMessage `json:"statements"`
	} `json:"migration"`
}

type v1Envelope struct {
	ID          string          `json:"id"`
	Actor       string          `json:"actor"`
	RequestedBy string          `json:"requested_by"`
	ApprovalID  string          `json:"approval_id"`
	SQL         string          `json:"sql"`
	Statements  json.RawMessage `json:"statements"`
}

func Parse(data []byte, sourceName string) (*model.Manifest, error) {
	if len(data) == 0 {
		return nil, errors.New("manifest is empty")
	}
	if len(data) > maxInputBytes {
		return nil, fmt.Errorf("manifest exceeds %d bytes", maxInputBytes)
	}
	clean := bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	trimmed := bytes.TrimSpace(clean)
	if len(trimmed) == 0 {
		return nil, errors.New("manifest is whitespace only")
	}

	m := &model.Manifest{
		SourceName:   sourceName,
		SourceSHA256: model.SHA256Hex(data),
		Raw:          append([]byte(nil), data...),
	}
	if trimmed[0] != '{' && trimmed[0] != '[' {
		if err := parseLegacySQL(m, trimmed); err != nil {
			return nil, err
		}
		return m, finish(m)
	}

	var probe map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return nil, fmt.Errorf("invalid JSON manifest: %w", err)
	}
	if looksCurrent(probe) {
		if err := parseCurrent(m, trimmed); err != nil {
			return nil, err
		}
	} else {
		if err := parseLegacyJSON(m, trimmed); err != nil {
			return nil, err
		}
	}
	return m, finish(m)
}

func looksCurrent(probe map[string]json.RawMessage) bool {
	for _, key := range []string{"format_version", "version"} {
		raw, ok := probe[key]
		if !ok {
			continue
		}
		var n int
		if json.Unmarshal(raw, &n) == nil && n >= 2 {
			return true
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			if n, err := strconv.Atoi(strings.TrimPrefix(s, "v")); err == nil && n >= 2 {
				return true
			}
		}
	}
	_, hasMigration := probe["migration"]
	return hasMigration
}

func parseCurrent(m *model.Manifest, data []byte) error {
	var env v2Envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&env); err != nil {
		return fmt.Errorf("invalid v2 envelope: %w", err)
	}
	if env.Migration.ID == "" {
		return errors.New("v2 migration.id is required")
	}
	m.Format = model.FormatCurrent
	m.ID = env.Migration.ID
	m.Actor = strings.TrimSpace(env.Migration.Actor)
	m.RequestedBy = strings.TrimSpace(env.Migration.RequestedBy)
	m.ApprovalID = strings.TrimSpace(env.Migration.ApprovalID)
	statements, err := decodeStatements(env.Migration.Statements)
	if err != nil {
		return fmt.Errorf("v2 migration.statements: %w", err)
	}
	if len(statements) == 0 {
		return errors.New("v2 migration.statements must contain at least one statement")
	}
	for i, raw := range statements {
		prefix := fmt.Sprintf("%s#/migration/statements/%d", m.SourceName, i)
		appendSQL(m, raw.SQL, raw.Target, prefix)
	}
	if m.Actor == "" {
		m.ParseWarnings = append(m.ParseWarnings, "v2 actor is empty; all statements will be denied")
	}
	return nil
}

func parseLegacyJSON(m *model.Manifest, data []byte) error {
	var env v1Envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&env); err != nil {
		return fmt.Errorf("invalid legacy JSON manifest: %w", err)
	}
	m.Format = model.FormatLegacyJSON
	m.ID = strings.TrimSpace(env.ID)
	m.Actor = strings.TrimSpace(env.Actor)
	m.RequestedBy = strings.TrimSpace(env.RequestedBy)
	m.ApprovalID = strings.TrimSpace(env.ApprovalID)
	if m.ID == "" {
		m.ID = sourceStem(m.SourceName)
		m.ParseWarnings = append(m.ParseWarnings, "legacy manifest has no id; using source filename")
	}
	statements, err := decodeStatements(env.Statements)
	if err != nil {
		return fmt.Errorf("legacy statements: %w", err)
	}
	if env.SQL != "" {
		appendSQL(m, env.SQL, "", m.SourceName+"#sql")
	}
	for i, raw := range statements {
		prefix := fmt.Sprintf("%s#/statements/%d", m.SourceName, i)
		appendSQL(m, raw.SQL, raw.Target, prefix)
	}
	if len(m.Statements) == 0 {
		return errors.New("legacy manifest has no sql or statements")
	}
	m.ParseWarnings = append(m.ParseWarnings, "legacy-v1 accepted through compatibility path")
	return nil
}

func parseLegacySQL(m *model.Manifest, data []byte) error {
	m.Format = model.FormatLegacySQL
	m.ID = sourceStem(m.SourceName)
	appendSQL(m, string(data), "", m.SourceName)
	if len(m.Statements) == 0 {
		return errors.New("legacy SQL file has no statements")
	}
	m.ParseWarnings = append(m.ParseWarnings, "raw SQL has no signed actor; --actor is required at execution time")
	return nil
}

func appendSQL(m *model.Manifest, sqlText, target, source string) {
	for _, span := range sqlscan.SplitStatements(sqlText) {
		if _, ok := sqlscan.FirstToken(span.Text); !ok {
			continue
		}
		line, column := sqlscan.LineColumn(sqlText, span.Start)
		idx := len(m.Statements)
		m.Statements = append(m.Statements, model.Statement{
			Index:      idx,
			SQL:        span.Text,
			Target:     target,
			Source:     source,
			BaseLine:   line,
			BaseColumn: column,
		})
	}
}

func decodeStatements(raw json.RawMessage) ([]rawStatement, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("must be an array: %w", err)
	}
	out := make([]rawStatement, 0, len(items))
	for i, item := range items {
		var text string
		if json.Unmarshal(item, &text) == nil {
			if strings.TrimSpace(text) == "" {
				return nil, fmt.Errorf("statement %d is empty", i)
			}
			out = append(out, rawStatement{SQL: text})
			continue
		}
		var obj rawStatement
		if err := json.Unmarshal(item, &obj); err != nil {
			return nil, fmt.Errorf("statement %d must be a string or object: %w", i, err)
		}
		if strings.TrimSpace(obj.SQL) == "" {
			return nil, fmt.Errorf("statement %d has empty sql", i)
		}
		out = append(out, obj)
	}
	return out, nil
}

func finish(m *model.Manifest) error {
	for i := range m.Statements {
		m.Statements[i].Index = i
	}
	normalized, err := canonical(m)
	if err != nil {
		return fmt.Errorf("normalize manifest: %w", err)
	}
	m.Normalized = normalized
	return nil
}

func canonical(m *model.Manifest) ([]byte, error) {
	type statement struct {
		SQL    string `json:"sql"`
		Target string `json:"target,omitempty"`
		Source string `json:"source"`
	}
	type migration struct {
		ID            string      `json:"id"`
		Actor         string      `json:"actor"`
		RequestedBy   string      `json:"requested_by,omitempty"`
		ApprovalID    string      `json:"approval_id,omitempty"`
		Statements    []statement `json:"statements"`
		SourceFormat  string      `json:"source_format"`
		ParseWarnings []string    `json:"parse_warnings,omitempty"`
	}
	payload := struct {
		FormatVersion int       `json:"format_version"`
		Migration     migration `json:"migration"`
	}{FormatVersion: 2}
	payload.Migration = migration{
		ID:            m.ID,
		Actor:         m.Actor,
		RequestedBy:   m.RequestedBy,
		ApprovalID:    m.ApprovalID,
		SourceFormat:  string(m.Format),
		ParseWarnings: m.ParseWarnings,
	}
	for _, stmt := range m.Statements {
		payload.Migration.Statements = append(payload.Migration.Statements, statement{SQL: stmt.SQL, Target: stmt.Target, Source: stmt.Source})
	}
	return json.MarshalIndent(payload, "", "  ")
}

func sourceStem(name string) string {
	base := filepath.Base(name)
	ext := filepath.Ext(base)
	return strings.TrimSuffix(base, ext)
}
