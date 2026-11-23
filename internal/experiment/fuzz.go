package experiment

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"example.com/deserialize-boundary/internal/ledger"
	"example.com/deserialize-boundary/internal/wire"
)

type CorpusSummary struct {
	RunID    string         `json:"run_id"`
	Files    int            `json:"files"`
	Valid    int            `json:"valid"`
	Invalid  int            `json:"invalid"`
	Panics   int            `json:"panics"`
	Outcomes map[string]int `json:"outcomes"`
	Digest   string         `json:"digest"`
}

type FuzzStats struct {
	LogPath       string `json:"log_path"`
	Runs          int64  `json:"runs"`
	Coverage      int64  `json:"coverage"`
	CorpusFiles   int64  `json:"corpus_files"`
	CorpusBytes   int64  `json:"corpus_bytes"`
	Findings      []string
	Completed     bool `json:"completed"`
	HarnessBanner bool `json:"harness_banner"`
}

func SeedCorpus(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	valid := frameHex(canonicalRecords())
	descRecords := canonicalRecords()
	for left, right := 0, len(descRecords)-1; left < right; left, right = left+1, right-1 {
		descRecords[left], descRecords[right] = descRecords[right], descRecords[left]
	}
	desc := frameHex(descRecords)

	seeds := map[string][]byte{
		"valid-asc":         valid,
		"valid-desc":        desc,
		"invalid-empty":     {},
		"invalid-magic":     mutate(valid, 0, 'X'),
		"invalid-version":   mutate(valid, 4, 2),
		"invalid-flags":     mutate(valid, 7, 1),
		"invalid-count-0":   mutate(valid, 5, 0),
		"invalid-count-17":  mutate(valid, 5, 17),
		"invalid-zero-id":   mutateCRC16(valid, 8, 0),
		"invalid-zero-len":  mutateCRC16(valid, 10, 0),
		"invalid-len-513":   mutateCRC16(valid, 10, 513),
		"invalid-crc":       mutate(valid, len(valid)-1, valid[len(valid)-1]^0xff),
		"invalid-truncated": valid[:len(valid)-6],
		"invalid-duplicate": duplicateIDFrame(),
		"invalid-too-large": make([]byte, wire.MaxInput+1),
	}
	seeds["invalid-trailing"] = insertBeforeCRC(valid, []byte{0x7f})
	seeds["invalid-nul"] = frameWithNUL()
	seeds["valid-unicode"] = mustFrame([]wire.Record{{ID: 9, Payload: "边界-测试-🚀"}})

	names := make([]string, 0, len(seeds))
	for name := range seeds {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), seeds[name], 0o644); err != nil {
			return err
		}
	}
	return nil
}

func mutate(data []byte, index int, value byte) []byte {
	out := append([]byte(nil), data...)
	if index < len(out) {
		out[index] = value
	}
	return out
}

func mutateCRC16(data []byte, index int, value uint16) []byte {
	out := append([]byte(nil), data...)
	if index+2 <= len(out) {
		binary.BigEndian.PutUint16(out[index:index+2], value)
	}
	return fixCRC(out)
}

func fixCRC(data []byte) []byte {
	out := append([]byte(nil), data...)
	if len(out) >= 4 {
		binary.BigEndian.PutUint32(out[len(out)-4:], crc32.Checksum(out[:len(out)-4], crc32.MakeTable(crc32.IEEE)))
	}
	return out
}

func insertBeforeCRC(data []byte, inserted []byte) []byte {
	out := make([]byte, 0, len(data)+len(inserted))
	out = append(out, data[:len(data)-4]...)
	out = append(out, inserted...)
	out = append(out, data[len(data)-4:]...)
	return fixCRC(out)
}

func mustFrame(records []wire.Record) []byte {
	data, err := wire.Encode(wire.Envelope{Records: records})
	if err != nil {
		panic(err)
	}
	return data
}

func frameWithNUL() []byte {
	payload := []byte{'a', 0, 'b'}
	data := make([]byte, wire.HeaderSize+wire.RecordHeaderSize+len(payload)+wire.TrailerSize)
	copy(data[:4], wire.Magic)
	data[4] = wire.Version
	data[5] = 1
	binary.BigEndian.PutUint16(data[8:10], 7)
	binary.BigEndian.PutUint16(data[10:12], uint16(len(payload)))
	copy(data[12:], payload)
	return fixCRC(data)
}

func (c *Checker) IngestCorpus(ctx context.Context, corpusDir, outDir string) (CorpusSummary, error) {
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		return CorpusSummary{}, err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		files = append(files, entry.Name())
	}
	sort.Strings(files)

	const runID = "fuzz-corpus"
	if err := c.Ledger.ResetRun(ctx, runID); err != nil {
		return CorpusSummary{}, err
	}
	if err := c.Ledger.StartRun(ctx, ledger.Run{
		ID:       runID,
		Scenario: "libfuzzer-corpus-replay",
		Role:     "fuzz",
		Mode:     "parse",
		Seed:     1,
		Expected: "no panic; every retained corpus file is classified",
		Status:   "running",
	}); err != nil {
		return CorpusSummary{}, err
	}

	state := State{Phase: "fuzz_replay"}
	recorder := &stepRecorder{ctx: ctx, ledger: c.Ledger, runID: runID}
	outcomes := make(map[string]int)
	digestParts := make([]string, 0, len(files))
	for index, name := range files {
		path := filepath.Join(corpusDir, name)
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return CorpusSummary{}, readErr
		}
		before := state.clone()
		recorder.started = time.Now()
		classification, result, panicText := safeClassify(data)
		switch {
		case panicText != "":
			state.Panics++
			state.LastOutcome = "fuzz_panic"
		case classification == "valid":
			state.ValidInputs++
			state.LastOutcome = "fuzz_valid"
		default:
			state.InvalidInputs++
			state.LastOutcome = "fuzz_boundary_error"
		}
		state.CorpusFiles++
		after := state.clone()
		result["file"] = name
		result["size"] = len(data)
		result["classification"] = classification
		if panicText != "" {
			result["panic"] = panicText
		}
		outcome := state.LastOutcome
		op := Op{Kind: OpParseRaw, Label: name, RawHex: hex.EncodeToString(data)}
		if err := recorder.record(before, after, "fuzz_input", outcome, eventInput{
			Scenario: runID,
			Index:    index,
			Op:       op,
			FrameHex: op.RawHex,
		}, result); err != nil {
			return CorpusSummary{}, err
		}
		outcomes[outcome]++
		digestParts = append(digestParts, name+"="+classification)
	}
	status := "complete"
	if state.Panics > 0 {
		status = "failed"
	}
	digest := sha256Hex([]byte(strings.Join(digestParts, "\n")))
	if err := c.Ledger.CompleteRun(ctx, runID, status, digest); err != nil {
		return CorpusSummary{}, err
	}
	trace, err := c.Ledger.ExportJSONL(ctx, runID)
	if err != nil {
		return CorpusSummary{}, err
	}
	if err := os.MkdirAll(filepath.Join(outDir, "traces"), 0o755); err != nil {
		return CorpusSummary{}, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "traces", runID+".jsonl"), trace, 0o644); err != nil {
		return CorpusSummary{}, err
	}

	summary := CorpusSummary{
		RunID:    runID,
		Files:    len(files),
		Valid:    state.ValidInputs,
		Invalid:  state.InvalidInputs,
		Panics:   state.Panics,
		Outcomes: outcomes,
		Digest:   digest,
	}
	checks := []ledger.Check{
		newCheck("fuzz_corpus_no_panics", "fuzzing", len(files) > 0 && state.Panics == 0,
			"all retained libFuzzer inputs replay without panic",
			fmt.Sprintf("files=%d invalid=%d panics=%d", len(files), state.InvalidInputs, state.Panics),
			"artifacts/evidence/traces/fuzz-corpus.jsonl",
			"Each corpus file is one recorded replay step."),
		newCheck("fuzz_corpus_boundary_rejections", "fuzzing", state.InvalidInputs > 0,
			"at least one malformed corpus input is rejected by a typed boundary error",
			fmt.Sprintf("invalid=%d", state.InvalidInputs),
			"artifacts/evidence/traces/fuzz-corpus.jsonl",
			"Shows the corpus exercised the negative boundary path."),
	}
	for _, check := range checks {
		if err := c.Ledger.PutCheck(ctx, check); err != nil {
			return summary, err
		}
	}
	return summary, nil
}

func safeClassify(data []byte) (classification string, result map[string]any, panicText string) {
	result = make(map[string]any)
	defer func() {
		if recovered := recover(); recovered != nil {
			panicText = fmt.Sprintf("%v\n%s", recovered, debug.Stack())
			classification = "panic"
		}
	}()
	envelope, err := wire.Parse(data)
	classification = wire.Classify(err)
	if err != nil {
		result["error"] = err.Error()
		return classification, result, ""
	}
	result["digest"] = wire.CanonicalDigest(envelope.Records)
	result["record_ids"] = recordIDs(envelope.Records)
	return classification, result, ""
}

func (c *Checker) IngestFuzzLog(ctx context.Context, logPath, artifactDir, corpusDir string) (FuzzStats, error) {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return FuzzStats{}, err
	}
	logText := string(data)
	stats := FuzzStats{
		LogPath: logPath,
		HarnessBanner: strings.Contains(logText, "INFO: Seed:") ||
			strings.Contains(logText, "Running with entropic power schedule"),
		Completed: strings.Contains(logText, "Done ") && strings.Contains(logText, "runs"),
	}
	stats.Runs = lastInt(regexp.MustCompile(`Done (\d+) runs`), logText)
	if stats.Runs == 0 {
		stats.Runs = lastInt(regexp.MustCompile(`#(\d+)\s+DONE`), logText)
	}
	stats.Coverage = lastInt(regexp.MustCompile(`cov:\s*(\d+)`), logText)
	stats.CorpusFiles = lastInt(regexp.MustCompile(`corp:\s*(\d+)/`), logText)
	stats.CorpusBytes = lastInt(regexp.MustCompile(`corp:\s*\d+/(\d+)b`), logText)
	entries, err := os.ReadDir(artifactDir)
	if err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasPrefix(name, "crash-") || strings.HasPrefix(name, "timeout-") ||
				strings.HasPrefix(name, "oom-") || strings.HasPrefix(name, "leak-") {
				stats.Findings = append(stats.Findings, filepath.Join(artifactDir, name))
			}
		}
	}
	sort.Strings(stats.Findings)
	corpusFiles := countFiles(corpusDir)

	checks := []ledger.Check{
		newCheck("libfuzzer_harness_executed", "fuzzing",
			stats.HarnessBanner && stats.Completed && stats.Runs > 0,
			"libFuzzer banner is present and at least one run completed",
			fmt.Sprintf("banner=%t completed=%t runs=%d", stats.HarnessBanner, stats.Completed, stats.Runs),
			"artifacts/evidence/fuzz/fuzzer.log",
			"Proves the target was driven by libFuzzer, not a Go-only loop."),
		newCheck("libfuzzer_no_findings", "fuzzing", len(stats.Findings) == 0,
			"no crash, timeout, OOM, or leak artifact",
			fmt.Sprintf("findings=%d", len(stats.Findings)),
			"artifacts/evidence/fuzz/",
			strings.Join(stats.Findings, ", ")),
		newCheck("libfuzzer_corpus_retained", "fuzzing", corpusFiles > 0,
			"the fuzzer retained a replayable corpus",
			fmt.Sprintf("corpus_files=%d", corpusFiles),
			"artifacts/evidence/fuzz/corpus/",
			"Retained files are replayed into SQLite by ingest-fuzz."),
	}
	for _, check := range checks {
		if err := c.Ledger.PutCheck(ctx, check); err != nil {
			return stats, err
		}
	}
	return stats, nil
}

func lastInt(re *regexp.Regexp, text string) int64 {
	matches := re.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return 0
	}
	value, _ := strconv.ParseInt(matches[len(matches)-1][1], 10, 64)
	return value
}

func countFiles(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			count++
		}
	}
	return count
}
