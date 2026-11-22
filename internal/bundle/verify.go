package bundle

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"apiskew.local/apiskew/internal/domain"
)

type VerifyOptions struct {
	Dir      string
	SampleID string
}

type VerifyResult struct {
	BundleSchema string `json:"bundle_schema"`
	SessionID    string `json:"session_id"`
	RecordCount  int    `json:"record_count"`
	CheckedCount int    `json:"checked_count"`
	AttemptCount int    `json:"attempt_count"`
	Status       string `json:"status"`
}

type loadedBundle struct {
	Manifest   Manifest
	Scenario   domain.Scenario
	Records    []Record
	Attempts   []AttemptRecord
	RecordRaw  [][]byte
	Checksums  map[string]string
	LatestByID map[string]Record
}

func Verify(options VerifyOptions) (VerifyResult, error) {
	if options.Dir == "" {
		return VerifyResult{}, errors.New("bundle directory is required")
	}
	dir, err := filepath.Abs(options.Dir)
	if err != nil {
		return VerifyResult{}, err
	}
	loaded, err := loadBundle(dir)
	if err != nil {
		return VerifyResult{}, err
	}
	checked := 0
	for index, record := range loaded.Records {
		if options.SampleID != "" && record.SampleID != options.SampleID {
			continue
		}
		if err := verifyRecord(dir, loaded, record, loaded.RecordRaw[index]); err != nil {
			return VerifyResult{}, fmt.Errorf("%s: %w", record.SampleID, err)
		}
		checked++
	}
	if options.SampleID != "" && checked == 0 {
		return VerifyResult{}, fmt.Errorf("sample %s not present in bundle", options.SampleID)
	}
	return VerifyResult{
		BundleSchema: loaded.Manifest.Schema,
		SessionID:    loaded.Manifest.Session.ID,
		RecordCount:  len(loaded.Records),
		CheckedCount: checked,
		AttemptCount: len(loaded.Attempts),
		Status:       "verified",
	}, nil
}

func loadBundle(dir string) (loadedBundle, error) {
	var loaded loadedBundle
	checksums, err := verifyChecksums(dir)
	if err != nil {
		return loaded, err
	}
	loaded.Checksums = checksums
	manifestRaw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return loaded, err
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestRaw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&loaded.Manifest); err != nil {
		return loaded, fmt.Errorf("manifest: %w", err)
	}
	if loaded.Manifest.Schema != Schema {
		return loaded, fmt.Errorf("manifest schema = %q, want %q", loaded.Manifest.Schema, Schema)
	}
	if !reflect.DeepEqual(loaded.Manifest.RecordFields, RecordFields) {
		return loaded, errors.New("manifest record field contract differs from this tool")
	}
	if !reflect.DeepEqual(loaded.Manifest.AttemptFields, AttemptFields) {
		return loaded, errors.New("manifest attempt field contract differs from this tool")
	}
	if err := verifyManifestFiles(dir, loaded.Manifest, checksums); err != nil {
		return loaded, err
	}
	scenarioRaw, err := os.ReadFile(filepath.Join(dir, "scenario.json"))
	if err != nil {
		return loaded, err
	}
	scenario, err := domain.DecodeScenarioJSON(scenarioRaw)
	if err != nil {
		return loaded, fmt.Errorf("scenario: %w", err)
	}
	scenarioSHA, err := scenario.Hash()
	if err != nil {
		return loaded, err
	}
	if scenarioSHA != loaded.Manifest.Session.ScenarioSHA256 {
		return loaded, errors.New("scenario hash does not match manifest")
	}
	loaded.Scenario = scenario
	loaded.Records, loaded.RecordRaw, err = readRecords(filepath.Join(dir, "records.jsonl"))
	if err != nil {
		return loaded, err
	}
	if len(loaded.Records) != loaded.Manifest.RecordCount {
		return loaded, fmt.Errorf("record count = %d, manifest says %d", len(loaded.Records), loaded.Manifest.RecordCount)
	}
	loaded.Attempts, err = readAttempts(filepath.Join(dir, "attempts.jsonl"))
	if err != nil {
		return loaded, err
	}
	loaded.LatestByID = make(map[string]Record, len(loaded.Records))
	for index, record := range loaded.Records {
		if index > 0 && record.Ordinal <= loaded.Records[index-1].Ordinal {
			return loaded, fmt.Errorf("record %d has non-increasing ordinal %d", index, record.Ordinal)
		}
		if _, exists := loaded.LatestByID[record.SampleID]; exists {
			return loaded, fmt.Errorf("duplicate sample id %s", record.SampleID)
		}
		loaded.LatestByID[record.SampleID] = record
	}
	if err := verifyCSV(filepath.Join(dir, "records.csv"), loaded.Records); err != nil {
		return loaded, err
	}
	if err := verifySQLite(filepath.Join(dir, "records.db"), scenario, loaded.Records, loaded.Attempts); err != nil {
		return loaded, err
	}
	return loaded, nil
}

func verifyChecksums(dir string) (map[string]string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return nil, err
	}
	checksums := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 {
			return nil, fmt.Errorf("malformed SHA256SUMS line %q", line)
		}
		relative := filepath.ToSlash(filepath.Clean(filepath.FromSlash(parts[1])))
		if relative == "." || strings.HasPrefix(relative, "../") || filepath.IsAbs(relative) {
			return nil, fmt.Errorf("unsafe checksum path %q", parts[1])
		}
		if _, exists := checksums[relative]; exists {
			return nil, fmt.Errorf("duplicate checksum for %s", relative)
		}
		checksums[relative] = parts[0]
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if _, ok := checksums["manifest.json"]; !ok {
		return nil, errors.New("SHA256SUMS does not cover manifest.json")
	}
	for relative, expected := range checksums {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(relative)))
		if err != nil {
			return nil, fmt.Errorf("checksum target %s: %w", relative, err)
		}
		if got := domain.SHA256Hex(data); got != expected {
			return nil, fmt.Errorf("checksum mismatch for %s", relative)
		}
	}
	return checksums, nil
}

func verifyManifestFiles(dir string, manifest Manifest, checksums map[string]string) error {
	seen := make(map[string]bool)
	for _, file := range manifest.Files {
		relative := filepath.ToSlash(filepath.Clean(filepath.FromSlash(file.Path)))
		if seen[relative] {
			return fmt.Errorf("duplicate manifest file %s", relative)
		}
		seen[relative] = true
		if expected, ok := checksums[relative]; !ok || expected != file.SHA256 {
			return fmt.Errorf("manifest file hash mismatch for %s", relative)
		}
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(relative)))
		if err != nil {
			return err
		}
		if int64(len(data)) != file.Bytes {
			return fmt.Errorf("manifest size mismatch for %s", relative)
		}
	}
	for relative := range checksums {
		if relative == "manifest.json" || relative == "SHA256SUMS" {
			continue
		}
		if !seen[relative] {
			return fmt.Errorf("file %s is not listed in manifest", relative)
		}
	}
	return nil
}

func readRecords(path string) ([]Record, [][]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	var records []Record
	var raws [][]byte
	for scanner.Scan() {
		line := append([]byte{}, scanner.Bytes()...)
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		keys, err := topLevelKeys(line)
		if err != nil {
			return nil, nil, fmt.Errorf("records.jsonl key order: %w", err)
		}
		if !reflect.DeepEqual(keys, RecordFields) {
			return nil, nil, fmt.Errorf("records.jsonl field order = %v", keys)
		}
		var record Record
		if err := json.Unmarshal(line, &record); err != nil {
			return nil, nil, err
		}
		records = append(records, record)
		raws = append(raws, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return records, raws, nil
}

func readAttempts(path string) ([]AttemptRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var attempts []AttemptRecord
	for scanner.Scan() {
		line := append([]byte{}, scanner.Bytes()...)
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		keys, err := topLevelKeys(line)
		if err != nil {
			return nil, fmt.Errorf("attempts.jsonl key order: %w", err)
		}
		if !reflect.DeepEqual(keys, AttemptFields) {
			return nil, fmt.Errorf("attempts.jsonl field order = %v", keys)
		}
		var attempt AttemptRecord
		if err := json.Unmarshal(line, &attempt); err != nil {
			return nil, err
		}
		attempts = append(attempts, attempt)
	}
	return attempts, scanner.Err()
}

func topLevelKeys(line []byte) ([]string, error) {
	decoder := json.NewDecoder(bytes.NewReader(line))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return nil, errors.New("record is not a JSON object")
	}
	var keys []string
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("object key is not a string")
		}
		keys = append(keys, key)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	return keys, nil
}

func verifyCSV(path string, records []Record) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	rows, err := reader.ReadAll()
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errors.New("records.csv is empty")
	}
	if !reflect.DeepEqual(rows[0], RecordFields) {
		return fmt.Errorf("records.csv header = %v", rows[0])
	}
	if len(rows)-1 != len(records) {
		return fmt.Errorf("records.csv row count = %d, want %d", len(rows)-1, len(records))
	}
	for index, record := range records {
		if got, want := rows[index+1], record.row(); !reflect.DeepEqual(got, want) {
			return fmt.Errorf("records.csv row %d differs", index+2)
		}
	}
	return nil
}

func verifySQLite(path string, scenario domain.Scenario, records []Record, attempts []AttemptRecord) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA query_only=ON"); err != nil {
		return err
	}
	columnRows, err := db.Query(`SELECT name FROM pragma_table_info('records') ORDER BY cid`)
	if err != nil {
		return err
	}
	var columns []string
	for columnRows.Next() {
		var name string
		if err := columnRows.Scan(&name); err != nil {
			columnRows.Close()
			return err
		}
		columns = append(columns, name)
	}
	columnRows.Close()
	expectedColumns := append(append([]string{}, RecordFields...), "record_json")
	if !reflect.DeepEqual(columns, expectedColumns) {
		return fmt.Errorf("records.db columns = %v", columns)
	}
	rows, err := db.Query(`SELECT ordinal,sample_id,record_json FROM records ORDER BY ordinal ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		var ordinal int
		var sampleID, raw string
		if err := rows.Scan(&ordinal, &sampleID, &raw); err != nil {
			return err
		}
		if index >= len(records) {
			return errors.New("records.db has extra rows")
		}
		var record Record
		if err := json.Unmarshal([]byte(raw), &record); err != nil {
			return err
		}
		if !reflect.DeepEqual(record, records[index]) || ordinal != records[index].Ordinal || sampleID != records[index].SampleID {
			return fmt.Errorf("records.db row %d differs from records.jsonl", index+1)
		}
		index++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if index != len(records) {
		return fmt.Errorf("records.db has %d rows, want %d", index, len(records))
	}
	var scenarioRaw string
	if err := db.QueryRow(`SELECT scenario_json FROM scenario LIMIT 1`).Scan(&scenarioRaw); err != nil {
		return err
	}
	expectedScenario, err := scenario.CanonicalJSON()
	if err != nil {
		return err
	}
	if scenarioRaw != string(expectedScenario) {
		return errors.New("records.db scenario differs from scenario.json")
	}
	attemptRows, err := db.Query(
		`SELECT sample_id,attempt,engine,status,comparable,v1_allow,v2_allow,permission_difference,
		        evidence_path,evidence_sha256,started_at,completed_at
		 FROM attempts ORDER BY sample_id ASC, attempt ASC`,
	)
	if err != nil {
		return err
	}
	defer attemptRows.Close()
	var dbAttempts []AttemptRecord
	for attemptRows.Next() {
		var attempt AttemptRecord
		var comparable, v1Allow, v2Allow, difference int
		if err := attemptRows.Scan(
			&attempt.SampleID, &attempt.Attempt, &attempt.Engine, &attempt.Status,
			&comparable, &v1Allow, &v2Allow, &difference, &attempt.EvidencePath,
			&attempt.EvidenceSHA256, &attempt.StartedAt, &attempt.CompletedAt,
		); err != nil {
			return err
		}
		attempt.Comparable = comparable != 0
		attempt.V1Allow = v1Allow != 0
		attempt.V2Allow = v2Allow != 0
		attempt.PermissionDifference = difference != 0
		dbAttempts = append(dbAttempts, attempt)
	}
	if err := attemptRows.Err(); err != nil {
		return err
	}
	sorted := append([]AttemptRecord{}, attempts...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].SampleID != sorted[j].SampleID {
			return sorted[i].SampleID < sorted[j].SampleID
		}
		return sorted[i].Attempt < sorted[j].Attempt
	})
	if !reflect.DeepEqual(dbAttempts, sorted) {
		return errors.New("records.db attempts differ from attempts.jsonl")
	}
	return nil
}

func verifyRecord(dir string, loaded loadedBundle, record Record, raw []byte) error {
	if record.SampleID == "" || record.Source == "" {
		return errors.New("sample id and source are required")
	}
	input, err := hex.DecodeString(record.InputHex)
	if err != nil {
		return fmt.Errorf("input_hex: %w", err)
	}
	if len(input) != record.InputBytes {
		return fmt.Errorf("input byte count = %d, record says %d", len(input), record.InputBytes)
	}
	if got := domain.SHA256Hex(input); got != record.SampleSHA256 {
		return fmt.Errorf("sample hash = %s, record says %s", got, record.SampleSHA256)
	}
	fresh, err := domain.Evaluate(loaded.Scenario, input, "verify-bundle")
	if err != nil {
		return err
	}
	if record.ScenarioSHA256 != loaded.Manifest.Session.ScenarioSHA256 ||
		fresh.Evidence.ScenarioSHA256 != record.ScenarioSHA256 {
		return errors.New("scenario hash mismatch")
	}
	if record.ObjectKey != loaded.Scenario.Object.Key ||
		record.ObjectCanonicalID != loaded.Scenario.Object.CanonicalID {
		return errors.New("object identity mismatch")
	}
	if record.ActorRole != fresh.Evidence.Attack.ActorRole.String() ||
		record.Action != fresh.Evidence.Attack.Action.String() ||
		record.TenantMatch != fresh.Evidence.Attack.TenantMatch ||
		record.RequestDevice != fresh.Evidence.Attack.RequestDevice ||
		record.DeviceASkewMS != fresh.Evidence.Attack.SkewAMS ||
		record.DeviceBSkewMS != fresh.Evidence.Attack.SkewBMS {
		return errors.New("attack fields do not match input")
	}
	if record.V1Allow != fresh.Evidence.V1.Allow ||
		record.V1Reason != fresh.Evidence.V1.Reason ||
		record.V1SelectedReplica != fresh.Evidence.V1.SelectedReplica ||
		record.V2Allow != fresh.Evidence.V2.Allow ||
		record.V2Reason != fresh.Evidence.V2.Reason ||
		record.V2SelectedReplica != fresh.Evidence.V2.SelectedReplica ||
		record.PermissionDifference != fresh.Comparison.PermissionDifference ||
		record.DifferentFields != domain.JoinFields(fresh.Comparison.DifferentFields) {
		return errors.New("decision fields do not match independent Go evaluation")
	}
	if record.RootCause != fresh.FixPlan.RootCause ||
		record.FixRuleID != fresh.FixPlan.RuleID ||
		record.FixSummary != fresh.FixPlan.Summary ||
		record.FixVerified != fresh.FixPlan.Verified {
		return errors.New("fix plan differs from independent Go evaluation")
	}
	if record.ReplayCommand != fmt.Sprintf("apiskew verify-bundle . --sample %s", record.SampleID) {
		return errors.New("replay command is not sample-specific")
	}
	attempts := make([]AttemptRecord, 0)
	for _, attempt := range loaded.Attempts {
		if attempt.SampleID == record.SampleID {
			attempts = append(attempts, attempt)
		}
	}
	if len(attempts) != record.Attempts || len(attempts) == 0 {
		return fmt.Errorf("attempt count = %d, record says %d", len(attempts), record.Attempts)
	}
	for index, attempt := range attempts {
		if attempt.Attempt != index+1 {
			return fmt.Errorf("attempt order has %d at position %d", attempt.Attempt, index+1)
		}
		evidence, err := verifyEvidenceFile(dir, loaded, record, attempt)
		if err != nil {
			return fmt.Errorf("attempt %d: %w", attempt.Attempt, err)
		}
		if attempt.V1Allow != evidence.V1.Allow ||
			attempt.V2Allow != evidence.V2.Allow ||
			attempt.PermissionDifference != evidence.Comparison.PermissionDifference {
			return fmt.Errorf("attempt %d summary differs from evidence", attempt.Attempt)
		}
	}
	latest := attempts[len(attempts)-1]
	if record.LatestAttempt != latest.Attempt ||
		record.EvidencePath != latest.EvidencePath ||
		record.EvidenceSHA256 != latest.EvidenceSHA256 {
		return errors.New("record does not point at the latest attempt")
	}
	evidence, err := verifyEvidenceFile(dir, loaded, record, latest)
	if err != nil {
		return fmt.Errorf("latest attempt: %w", err)
	}
	if drift := domain.CompareFingerprints(evidence, fresh.Evidence); len(drift) != 0 {
		return fmt.Errorf("stored evidence drifted from Go evaluation: %s", domain.JoinFields(drift))
	}
	if !reflect.DeepEqual(evidence.Comparison, fresh.Comparison) {
		return errors.New("stored comparison differs from Go evaluation")
	}
	if evidence.SampleSHA256 != record.SampleSHA256 ||
		evidence.InputHex != record.InputHex ||
		evidence.ScenarioSHA256 != record.ScenarioSHA256 {
		return errors.New("evidence hashes do not match record")
	}
	if !reflect.DeepEqual(evidence.Attack, fresh.Evidence.Attack) {
		return errors.New("evidence attack differs from record")
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return errors.New("empty JSONL record")
	}
	return nil
}

func verifyEvidenceFile(dir string, loaded loadedBundle, record Record, attempt AttemptRecord) (domain.Evidence, error) {
	relative := filepath.ToSlash(filepath.Clean(filepath.FromSlash(attempt.EvidencePath)))
	if relative != attempt.EvidencePath || strings.HasPrefix(relative, "../") || filepath.IsAbs(relative) {
		return domain.Evidence{}, fmt.Errorf("unsafe evidence path %q", attempt.EvidencePath)
	}
	if relative != evidenceName(record.SampleID, attempt.Attempt) {
		return domain.Evidence{}, fmt.Errorf("evidence path %q does not follow naming contract", relative)
	}
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(relative)))
	if err != nil {
		return domain.Evidence{}, err
	}
	if got := domain.SHA256Hex(data); got != attempt.EvidenceSHA256 {
		return domain.Evidence{}, fmt.Errorf("evidence hash = %s, attempt says %s", got, attempt.EvidenceSHA256)
	}
	if expected, ok := loaded.Checksums[relative]; !ok || expected != attempt.EvidenceSHA256 {
		return domain.Evidence{}, errors.New("evidence is not covered by SHA256SUMS")
	}
	var evidence domain.Evidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return domain.Evidence{}, err
	}
	if evidence.SampleSHA256 != record.SampleSHA256 {
		return domain.Evidence{}, errors.New("evidence sample hash mismatch")
	}
	if evidence.Engine == "" || evidence.DetectionSource == "" {
		return domain.Evidence{}, errors.New("evidence lacks engine provenance")
	}
	return evidence, nil
}
