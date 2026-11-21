package evidence

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Insert appends a record; RecordID is filled from the content digest when
// empty so identical evidence always yields identical identifiers.
func (s *Store) Insert(r *Record) error {
	if r.RecordID == "" {
		r.RecordID = r.Digest()[:32]
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO evidence
		(record_id, ts, scenario, input_sha256, input_len, attack_vector,
		 trigger_func, trigger_file, trigger_line,
		 perm_subject, perm_action, perm_decision, perm_reason,
		 expanded_bytes, expansion_count,
		 quota_max_output_bytes, quota_max_expansion_ratio,
		 log_file, log_digest, notes)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.RecordID, r.TS, r.Scenario, r.InputSHA256, r.InputLen, r.AttackVector,
		r.TriggerFunc, r.TriggerFile, r.TriggerLine,
		r.PermSubject, r.PermAction, r.PermDecision, r.PermReason,
		r.ExpandedBytes, r.ExpansionCount,
		r.QuotaMaxOutputBytes, r.QuotaMaxExpansionRatio,
		r.LogFile, r.LogDigest, r.Notes)
	return err
}

// List returns every record in insertion order.
func (s *Store) List() ([]Record, error) {
	rows, err := s.db.Query(`SELECT record_id, ts, scenario, input_sha256, input_len,
		attack_vector, trigger_func, trigger_file, trigger_line,
		perm_subject, perm_action, perm_decision, perm_reason,
		expanded_bytes, expansion_count,
		quota_max_output_bytes, quota_max_expansion_ratio,
		log_file, log_digest, notes FROM evidence ORDER BY rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.RecordID, &r.TS, &r.Scenario, &r.InputSHA256, &r.InputLen,
			&r.AttackVector, &r.TriggerFunc, &r.TriggerFile, &r.TriggerLine,
			&r.PermSubject, &r.PermAction, &r.PermDecision, &r.PermReason,
			&r.ExpandedBytes, &r.ExpansionCount,
			&r.QuotaMaxOutputBytes, &r.QuotaMaxExpansionRatio,
			&r.LogFile, &r.LogDigest, &r.Notes); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ExportJSONL writes every record as one JSON object per line. Keys appear
// in FieldOrder on every line.
func (s *Store) ExportJSONL(w io.Writer) (int, error) {
	recs, err := s.List()
	if err != nil {
		return 0, err
	}
	bw := bufio.NewWriter(w)
	for _, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			return 0, err
		}
		if _, err := bw.Write(append(b, '\n')); err != nil {
			return 0, err
		}
	}
	return len(recs), bw.Flush()
}

// ImportJSONL reads JSONL produced by ExportJSONL into the store. Each line
// is validated against FieldOrder before decoding so a reordered or
// incomplete artifact is rejected instead of silently reloaded.
func (s *Store) ImportJSONL(r io.Reader) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if err := checkKeyOrder(line); err != nil {
			return n, fmt.Errorf("line %d: %w", n+1, err)
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return n, fmt.Errorf("line %d: %w", n+1, err)
		}
		if err := s.Insert(&rec); err != nil {
			return n, err
		}
		n++
	}
	return n, sc.Err()
}

// checkKeyOrder decodes only the object keys and requires them to match
// FieldOrder exactly, in order.
func checkKeyOrder(line []byte) error {
	dec := json.NewDecoder(bytes.NewReader(line))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("expected JSON object")
	}
	i := 0
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return err
		}
		key := kt.(string)
		if i >= len(FieldOrder) {
			return fmt.Errorf("unexpected extra key %q", key)
		}
		if key != FieldOrder[i] {
			return fmt.Errorf("key %d is %q, want %q", i, key, FieldOrder[i])
		}
		i++
		var skip any
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	if i != len(FieldOrder) {
		return fmt.Errorf("got %d keys, want %d", i, len(FieldOrder))
	}
	return nil
}

// VerifyReload compares every record in other against this store, in order,
// and returns the number of matching records.
func (s *Store) VerifyReload(other *Store) (int, error) {
	a, err := s.List()
	if err != nil {
		return 0, err
	}
	b, err := other.List()
	if err != nil {
		return 0, err
	}
	if len(a) != len(b) {
		return 0, fmt.Errorf("record count differs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Digest() != b[i].Digest() {
			return i, fmt.Errorf("record %d (%s) digest mismatch", i, a[i].RecordID)
		}
	}
	return len(a), nil
}
