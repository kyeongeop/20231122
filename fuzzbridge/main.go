package main

/*
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"pathaliaslab/internal/ledger"
	"pathaliaslab/internal/model"
)

var (
	aliases = []string{
		"/deploy/api", "/deploy//api/", "/deploy/./api", "/deploy/api/../api",
		"/deploy/web", "/deploy//web/", "/deploy/api/../web",
	}
	targets = []string{
		"/srv/blue", "/srv//blue/", "/srv/green", "/srv/./green/",
		"/srv/red", "/srv//red/",
	}
	fuzzDBPath   = envOr("PATHALIAS_FUZZ_DB", filepath.Join(os.TempDir(), "pathalias-fuzzer.db"))
	artifactDir  = envOr("PATHALIAS_FUZZ_ARTIFACTS", filepath.Join("artifacts", "fuzz"))
	openOnce     sync.Once
	store        *ledger.Ledger
	openErr      error
	currentInput []byte
	currentOps   []model.Op
	currentError string
)

func main() {}

//export PathAliasFuzzOneInput
func PathAliasFuzzOneInput(data *C.uint8_t, size C.size_t) (code C.int) {
	currentInput = C.GoBytes(unsafe.Pointer(data), C.int(size))
	currentOps = nil
	currentError = ""
	defer func() {
		if recovered := recover(); recovered != nil {
			currentError = fmt.Sprintf("panic: %v", recovered)
			writeFailure()
			code = 1
		}
	}()
	if err := runOne(currentInput); err != nil {
		currentError = err.Error()
		writeFailure()
		return 1
	}
	return 0
}

func runOne(input []byte) error {
	if len(input) == 0 {
		return nil
	}
	ops := decodeOps(input)
	currentOps = ops
	if len(ops) == 0 {
		return nil
	}
	if err := ensureStore(); err != nil {
		return err
	}
	if err := store.ResetRun("libfuzzer"); err != nil {
		return err
	}
	scenarioJSON, _ := json.MarshalIndent(struct {
		Name string     `json:"name"`
		Ops  []model.Op `json:"ops"`
	}{Name: "libfuzzer", Ops: ops}, "", "  ")
	if err := store.BeginRun("libfuzzer", "libfuzzer", "fuzz", scenarioJSON); err != nil {
		return err
	}

	engine := model.NewEngine()
	eventHash := ""
	for index, op := range ops {
		before := engine.StateJSON()
		result := engine.Apply(op)
		after := engine.StateJSON()
		if problems := engine.Validate(); len(problems) > 0 {
			return fmt.Errorf("step %d invariant failure: %s", index+1, strings.Join(problems, "; "))
		}
		inputJSON, _ := json.Marshal(op)
		resultJSON, _ := json.Marshal(result)
		var err error
		eventHash, err = store.AddStep("libfuzzer", index+1, inputJSON, before, resultJSON, after)
		if err != nil {
			return err
		}
		if op.ID == "" {
			return fmt.Errorf("step %d produced empty operation id", index+1)
		}
	}
	finalState := engine.StateJSON()
	if err := store.FinishRun("libfuzzer", "passed", finalState, engine.ResolutionDigest(), eventHash, len(ops)); err != nil {
		return err
	}
	if err := store.VerifyEvidenceChain("libfuzzer"); err != nil {
		return err
	}
	steps, err := store.Steps("libfuzzer")
	if err != nil {
		return err
	}
	if len(steps) != len(ops) {
		return fmt.Errorf("sqlite step count %d != input operations %d", len(steps), len(ops))
	}
	if err := verifyReplay(ops, engine.StateDigest()); err != nil {
		return err
	}
	return verifyRepeatIsStable(engine, ops)
}

func decodeOps(data []byte) []model.Op {
	count := 1 + int(data[0]%12)
	ops := make([]model.Op, 0, count)
	submitted := make([]string, 0, count)
	position := 1
	for index := 0; index < count && position+2 < len(data); index++ {
		mode := data[position] % 6
		alias := aliases[int(data[position+1])%len(aliases)]
		target := targets[int(data[position+2])%len(targets)]
		selector := int(data[position+2])
		position += 3
		opID := fmt.Sprintf("f-%02d", index)
		switch mode {
		case 2:
			if len(submitted) == 0 {
				op := model.Op{ID: opID, Kind: model.OpSubmit, Alias: alias, Target: target}
				ops = append(ops, op)
				submitted = append(submitted, op.ID)
				continue
			}
			cancelID := submitted[selector%len(submitted)]
			ops = append(ops, model.Op{ID: opID, Kind: model.OpCancel, CancelID: cancelID})
		case 3:
			if len(ops) == 0 {
				op := model.Op{ID: opID, Kind: model.OpSubmit, Alias: alias, Target: target}
				ops = append(ops, op)
				submitted = append(submitted, op.ID)
				continue
			}
			ops = append(ops, ops[len(ops)-1])
		case 4:
			if len(submitted) == 0 {
				op := model.Op{ID: opID, Kind: model.OpSubmit, Alias: alias, Target: target}
				ops = append(ops, op)
				submitted = append(submitted, op.ID)
				continue
			}
			reused := submitted[selector%len(submitted)]
			ops = append(ops, model.Op{ID: reused, Kind: model.OpSubmit, Alias: alias, Target: target})
		default:
			op := model.Op{ID: opID, Kind: model.OpSubmit, Alias: alias, Target: target}
			ops = append(ops, op)
			submitted = append(submitted, op.ID)
		}
	}
	return ops
}

func verifyReplay(ops []model.Op, expectedDigest string) error {
	replay := model.NewEngine()
	for index, op := range ops {
		replay.Apply(op)
		if problems := replay.Validate(); len(problems) > 0 {
			return fmt.Errorf("replay step %d invariant failure: %s", index+1, strings.Join(problems, "; "))
		}
	}
	if replay.StateDigest() != expectedDigest {
		return fmt.Errorf("replay state digest differs: got %s want %s", replay.StateDigest(), expectedDigest)
	}
	return nil
}

func verifyRepeatIsStable(engine *model.Engine, ops []model.Op) error {
	before := engine.StateDigest()
	for index, op := range ops {
		result := engine.Apply(op)
		if result.Outcome != "duplicate_noop" && result.Outcome != "id_collision" {
			return fmt.Errorf("repeat step %d unexpectedly returned %s", index+1, result.Outcome)
		}
		if engine.StateDigest() != before {
			return fmt.Errorf("repeat step %d mutated state", index+1)
		}
	}
	return nil
}

func ensureStore() error {
	openOnce.Do(func() {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			_ = os.Remove(fuzzDBPath + suffix)
		}
		if err := os.MkdirAll(filepath.Dir(fuzzDBPath), 0o755); err != nil {
			openErr = err
			return
		}
		store, openErr = ledger.Open(fuzzDBPath)
	})
	return openErr
}

func writeFailure() {
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "libFuzzer failure evidence:", err)
		return
	}
	inputPath := filepath.Join(artifactDir, "failure-input.bin")
	_ = os.WriteFile(inputPath, currentInput, 0o644)
	steps := []ledger.StepRecord{}
	if store != nil {
		_ = store.BackupTo(filepath.Join(artifactDir, "failure.db"))
		steps, _ = store.Steps("libfuzzer")
	}
	payload := struct {
		Runtime     string              `json:"runtime"`
		Error       string              `json:"error"`
		InputBytes  int                 `json:"input_bytes"`
		InputSHA256 string              `json:"input_sha256"`
		Operations  []model.Op          `json:"operations"`
		Steps       []ledger.StepRecord `json:"steps"`
		AtUTC       string              `json:"at_utc"`
	}{
		Runtime: runtime.Version(), Error: currentError,
		InputBytes: len(currentInput), InputSHA256: ledger.SHA256(currentInput),
		Operations: currentOps, Steps: steps,
		AtUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, _ := json.MarshalIndent(payload, "", "  ")
	_ = os.WriteFile(filepath.Join(artifactDir, "failure.json"), append(data, '\n'), 0o644)
	fmt.Fprintf(os.Stderr, "libFuzzer invariant failure: %s\n", currentError)
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
