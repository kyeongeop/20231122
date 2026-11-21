package bundle

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"auditfix/internal/audit"
	"auditfix/internal/model"
	"auditfix/internal/runner"
)

func loadArtifacts(root string, manifest Manifest) (loadedBundle, error) {
	loaded := loadedBundle{root: root}
	loaded.manifest = manifest
	if err := readCanonicalFile(filepath.Join(root, "case.json"), &loaded.caseRow); err != nil {
		return loaded, err
	}
	if err := readCanonicalFile(filepath.Join(root, "run.json"), &loaded.run); err != nil {
		return loaded, err
	}
	var err error
	loaded.events, err = readJSONL[model.Event](filepath.Join(root, "events.jsonl"),
		manifest.RowCounts.Events)
	if err != nil {
		return loaded, err
	}
	loaded.corrections, err = readJSONL[model.Correction](filepath.Join(root, "corrections.jsonl"),
		manifest.RowCounts.Corrections)
	if err != nil {
		return loaded, err
	}
	loaded.evidence, err = readJSONL[EvidenceRow](filepath.Join(root, "evidence.jsonl"),
		manifest.RowCounts.Evidence)
	if err != nil {
		return loaded, err
	}
	loaded.samples, err = readJSONL[SampleRow](filepath.Join(root, "samples.jsonl"),
		manifest.RowCounts.Samples)
	if err != nil {
		return loaded, err
	}
	loaded.attempts, err = readJSONL[AttemptRow](filepath.Join(root, "attempts.jsonl"),
		manifest.RowCounts.Attempts)
	if err != nil {
		return loaded, err
	}
	if err := checkFieldOrder(reflect.TypeOf(model.Case{}), manifest.FieldOrders.Case); err != nil {
		return loaded, err
	}
	if err := checkFieldOrder(reflect.TypeOf(model.Event{}), manifest.FieldOrders.Event); err != nil {
		return loaded, err
	}
	if err := checkFieldOrder(reflect.TypeOf(model.Correction{}), manifest.FieldOrders.Correction); err != nil {
		return loaded, err
	}
	if err := checkFieldOrder(reflect.TypeOf(EvidenceRow{}), manifest.FieldOrders.Evidence); err != nil {
		return loaded, err
	}
	if err := checkFieldOrder(reflect.TypeOf(SampleRow{}), manifest.FieldOrders.Sample); err != nil {
		return loaded, err
	}
	if err := checkFieldOrder(reflect.TypeOf(model.Run{}), manifest.FieldOrders.Run); err != nil {
		return loaded, err
	}
	if err := checkFieldOrder(reflect.TypeOf(AttemptRow{}), manifest.FieldOrders.Attempt); err != nil {
		return loaded, err
	}
	return loaded, verifyOrders(loaded)
}

func readCanonicalFile(path string, value any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, value); err != nil {
		return fmt.Errorf("decode %s: %w", filepath.Base(path), err)
	}
	canonical, err := canonicalJSON(value, true)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, canonical) {
		return fmt.Errorf("%s is not canonical JSON", filepath.Base(path))
	}
	return nil
}

func readJSONL[T any](path string, expected int) ([]T, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 32*1024*1024)
	var rows []T
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		if len(line) == 0 {
			return nil, fmt.Errorf("%s line %d is blank", filepath.Base(path), lineNo)
		}
		var row T
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", filepath.Base(path), lineNo, err)
		}
		canonical, err := canonicalJSON(row, false)
		if err != nil {
			return nil, err
		}
		canonical = bytes.TrimSuffix(canonical, []byte("\n"))
		if !bytes.Equal(line, canonical) {
			return nil, fmt.Errorf("%s line %d is not canonical or field order changed",
				filepath.Base(path), lineNo)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(rows) != expected {
		return nil, fmt.Errorf("%s row count is %d, manifest says %d",
			filepath.Base(path), len(rows), expected)
	}
	return rows, nil
}

func checkFieldOrder(t reflect.Type, expected []string) error {
	actual := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		actual = append(actual, name)
	}
	if !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("field order mismatch for %s: actual=%v expected=%v",
			t.Name(), actual, expected)
	}
	return nil
}

func verifyOrders(loaded loadedBundle) error {
	lastDevice := ""
	lastSeqByDevice := map[string]int64{}
	lastOrdinal := map[string]int{}
	for i, event := range loaded.events {
		if i == 0 && event.Device != "device-a" && event.Device != "device-b" {
			return fmt.Errorf("event %d has unsupported device %q", i, event.Device)
		}
		if lastDevice != "" && event.Device != lastDevice {
			if lastDevice == "device-b" || event.Device != "device-b" {
				return fmt.Errorf("events are not ordered device-a then device-b")
			}
			lastDevice = event.Device
		}
		if lastDevice == "" {
			lastDevice = event.Device
		}
		if event.Ordinal != lastOrdinal[event.Device]+1 {
			return fmt.Errorf("event ordinal is not contiguous for %s", event.Device)
		}
		if event.Seq <= lastSeqByDevice[event.Device] {
			return fmt.Errorf("event sequence is not increasing for %s", event.Device)
		}
		lastOrdinal[event.Device] = event.Ordinal
		lastSeqByDevice[event.Device] = event.Seq
	}
	lastCorrection := model.Correction{}
	for i, correction := range loaded.corrections {
		if i > 0 {
			if correction.Device < lastCorrection.Device ||
				(correction.Device == lastCorrection.Device &&
					correction.SeqFrom < lastCorrection.SeqFrom) {
				return errorsNew("corrections are not ordered by device and seq_from")
			}
		}
		lastCorrection = correction
	}
	for i, item := range loaded.evidence {
		if i > 0 && item.BlobID <= loaded.evidence[i-1].BlobID {
			return errorsNew("evidence is not ordered by blob_id")
		}
	}
	for i, sample := range loaded.samples {
		if sample.SampleIndex != i+1 {
			return errorsNew("samples are not ordered by contiguous sample_index")
		}
	}
	lastSample := 0
	lastAttempt := 0
	for _, attempt := range loaded.attempts {
		if attempt.SampleIndex < lastSample {
			return errorsNew("attempts are not ordered by sample_index")
		}
		if attempt.SampleIndex != lastSample {
			lastSample = attempt.SampleIndex
			lastAttempt = 0
		}
		if attempt.AttemptNo <= lastAttempt {
			return errorsNew("attempt_no is not increasing within a sample")
		}
		lastAttempt = attempt.AttemptNo
	}
	return nil
}

func errorsNew(message string) error {
	return fmt.Errorf("%s", message)
}

func verifyCrossReferences(loaded loadedBundle) ([]string, error) {
	var warnings []string
	manifest := loaded.manifest
	if loaded.caseRow.CaseID != manifest.CaseID {
		return warnings, errorsNew("case id mismatch")
	}
	if loaded.run.RunID != manifest.RunID || loaded.run.CaseID != manifest.CaseID {
		return warnings, errorsNew("run id or case id mismatch")
	}
	if loaded.run.HarnessSHA256 != manifest.HarnessSHA256 ||
		loaded.run.TimeoutMS != manifest.TimeoutMS ||
		loaded.run.FuzzArgs != manifest.FuzzArgs {
		return warnings, errorsNew("run harness evidence differs from manifest")
	}
	if err := verifyOriginalLogs(loaded); err != nil {
		return warnings, err
	}
	sampleByID := make(map[string]SampleRow)
	for _, sample := range loaded.samples {
		sampleByID[sample.SampleID] = sample
		sum, size, err := sha256File(filepath.Join(loaded.root, filepath.FromSlash(sample.BundlePath)))
		if err != nil || sum != sample.SHA256 || size != sample.Size {
			return warnings, fmt.Errorf("sample bytes mismatch: %s", sample.Name)
		}
	}
	for _, item := range loaded.evidence {
		sum, size, err := sha256File(filepath.Join(loaded.root, filepath.FromSlash(item.BundlePath)))
		if err != nil || sum != item.SHA256 || size != item.Size {
			return warnings, fmt.Errorf("evidence bytes mismatch: %s", item.SourceName)
		}
	}
	for _, attempt := range loaded.attempts {
		sample, ok := sampleByID[attempt.SampleID]
		if !ok || sample.Name != attempt.SampleName || sample.SampleIndex != attempt.SampleIndex {
			return warnings, fmt.Errorf("attempt references unknown sample %s", attempt.SampleID)
		}
		if attempt.ResultJSON == "" {
			if isTerminal(attempt.Status) {
				return warnings, fmt.Errorf("terminal attempt %s/%d has no evidence",
					attempt.SampleName, attempt.AttemptNo)
			}
			continue
		}
		if err := verifyAttemptEvidence(attempt, loaded.root, sample.SHA256,
			manifest.HarnessSHA256); err != nil {
			return warnings, fmt.Errorf("%s/%d: %w", attempt.SampleName, attempt.AttemptNo, err)
		}
	}
	if loaded.run.Status == "complete" {
		terminal := make(map[string]bool)
		for _, attempt := range loaded.attempts {
			if isTerminal(attempt.Status) {
				terminal[attempt.SampleID] = true
			}
		}
		for _, sample := range loaded.samples {
			if !terminal[sample.SampleID] {
				return warnings, fmt.Errorf("complete run lacks terminal attempt for %s", sample.Name)
			}
		}
	}
	return warnings, nil
}

func verifyOriginalLogs(loaded loadedBundle) error {
	logs := make(map[string][]byte)
	for _, item := range loaded.evidence {
		if item.Role != "device-a-log" && item.Role != "device-b-log" {
			continue
		}
		path := filepath.Join(loaded.root, filepath.FromSlash(item.BundlePath))
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		logs[item.Role] = data
	}
	if logs["device-a-log"] == nil || logs["device-b-log"] == nil {
		return errorsNew("bundle does not contain both original device logs")
	}
	aEvents, err := audit.ParseDeviceLog(bytes.NewReader(logs["device-a-log"]), "device-a")
	if err != nil {
		return fmt.Errorf("reparse device-a log: %w", err)
	}
	bEvents, err := audit.ParseDeviceLog(bytes.NewReader(logs["device-b-log"]), "device-b")
	if err != nil {
		return fmt.Errorf("reparse device-b log: %w", err)
	}
	analysis := audit.Analyze(aEvents, bEvents, loaded.caseRow.CaseID, loaded.caseRow.CreatedAt)
	if loaded.caseRow.ClockOffsetNS != analysis.ClockOffsetNS ||
		loaded.caseRow.AnchorPairCount != analysis.AnchorPairs ||
		loaded.caseRow.ChainStatus != analysis.ChainStatus ||
		loaded.caseRow.DeviceAEventRows != len(aEvents) ||
		loaded.caseRow.DeviceBEventRows != len(bEvents) ||
		loaded.caseRow.CorrectionCount != len(analysis.Corrections) {
		return errorsNew("case summary fields do not match recomputed analysis")
	}
	if !canonicalEqual(analysis.Events, loaded.events) {
		return errorsNew("exported events do not match original log evidence")
	}
	if !canonicalEqual(analysis.Corrections, loaded.corrections) {
		return errorsNew("exported corrections do not match recomputed analysis")
	}
	return nil
}

func canonicalEqual(left, right any) bool {
	a, errA := canonicalJSON(left, false)
	b, errB := canonicalJSON(right, false)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

func verifyAttemptEvidence(attempt AttemptRow, root, sampleSHA, harnessSHA string) error {
	var evidence runner.Evidence
	if err := json.Unmarshal([]byte(attempt.ResultJSON), &evidence); err != nil {
		return fmt.Errorf("decode result_json: %w", err)
	}
	canonical, err := canonicalJSON(evidence, false)
	if err != nil {
		return err
	}
	if string(bytes.TrimSuffix(canonical, []byte("\n"))) != attempt.ResultJSON {
		return errorsNew("result_json is not canonical")
	}
	digest := sha256Hex([]byte("auditfix.evidence.v1\n" + attempt.ResultJSON))
	if digest != attempt.EvidenceSHA256 {
		return errorsNew("attempt evidence digest mismatch")
	}
	if evidence.SampleSHA256 != sampleSHA || evidence.HarnessSHA256 != harnessSHA {
		return errorsNew("attempt evidence binds a different sample or harness")
	}
	if evidence.StdoutSHA256 != attempt.StdoutSHA256 ||
		evidence.StderrSHA256 != attempt.StderrSHA256 {
		return errorsNew("attempt output hashes differ from evidence")
	}
	if err := validateBundlePath(attempt.StdoutPath); err != nil {
		return err
	}
	if err := validateBundlePath(attempt.StderrPath); err != nil {
		return err
	}
	stdout, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(attempt.StdoutPath)))
	if err != nil {
		return fmt.Errorf("read captured stdout: %w", err)
	}
	stderr, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(attempt.StderrPath)))
	if err != nil {
		return fmt.Errorf("read captured stderr: %w", err)
	}
	if sha256Hex(stdout) != attempt.StdoutSHA256 ||
		sha256Hex(stderr) != attempt.StderrSHA256 {
		return errorsNew("captured output bytes do not match captured hashes")
	}
	if evidence.Classification == "" || attempt.Status == "" {
		return errorsNew("attempt evidence is incomplete")
	}
	switch attempt.Status {
	case "complete":
		if evidence.TimedOut || evidence.Signal != 0 || evidence.ExitCode != 0 {
			return errorsNew("complete attempt has non-zero process termination evidence")
		}
	case "timeout":
		if !evidence.TimedOut {
			return errorsNew("timeout attempt is not marked timed out")
		}
	case "crash":
		if evidence.TimedOut || (evidence.Signal == 0 && evidence.ExitCode == 0) {
			return errorsNew("crash attempt lacks crash termination evidence")
		}
	}
	return nil
}
