// Fuzz bridge (package main): the Go side of the libFuzzer bridge. It is compiled with
// `go build -buildmode=c-archive` and linked into a C harness that provides
// LLVMFuzzerTestOneInput (see fuzz/harness/fuzz_harness.c).
//
// The bridge feeds arbitrary attacker-controlled bytes through the SAME code
// path the CLI uses (ingest -> SQLite -> state machine), so a fuzz-discovery
// exercises real parsing, checksum and authorization logic rather than a
// parallel test harness.
package main

import "C"

import (
	"os"
	"path/filepath"

	"riskflow/internal/engine"
	"riskflow/internal/ingest"
	"riskflow/internal/model"
	"riskflow/internal/replay"
	"riskflow/internal/store"
)

// crash is invoked only when a security invariant is violated. It deliberately
// aborts so libFuzzer records a crash artifact with the offending input.
func crash(why string) {
	panic("riskflow invariant violated: " + why)
}

//export RiskflowFuzz
func RiskflowFuzz(data *C.char, n C.int) C.int {
	if n <= 0 {
		return 0
	}
	raw := C.GoBytes(unsafePointer(data), n)

	// Test-only poison switch: a well-known magic input forces an invariant
	// crash so the crash/evidence pipeline can be demonstrated deterministically.
	// It is a fixed sentinel, not something random mutation would rely on.
	if string(raw) == "POISON_RISKFLOW_INVARIANT" {
		crash("demonstrated via POISON_RISKFLOW_INVARIANT sentinel")
	}

	// Each fuzz iteration gets an isolated on-disk SQLite file so WAL recovery
	// and evidence persistence are exercised for real.
	dir := cTempDir()
	defer os.RemoveAll(dir)
	dbPath := filepath.Join(dir, "fuzz.db")
	st, err := store.Open(dbPath)
	if err != nil {
		// Failing to open our own database is an environment bug, not a target
		// finding; signal "skip" rather than a crash.
		return -1
	}
	defer st.Close()

	p := replay.New(st)
	out, perr := ingest.Parse("FUZZ-BATCH", raw)
	_ = st.UpsertBatch("FUZZ-BATCH", out.Schema, "libfuzzer", "", int64(len(raw)), out.Truncated)

	// Truncation must always be reported, never silently swallowed.
	if perr == ingest.ErrTruncated && !out.Truncated {
		crash("ErrTruncated returned without Truncated flag")
	}
	if perr != nil && perr != ingest.ErrTruncated {
		// Hard parse error: valid rejection path, nothing to run.
		return 0
	}

	for _, rec := range out.Records {
		// Persist through the real pipeline so SQLite WAL/evidence tables are
		// exercised with attacker-controlled content too.
		if err := st.InsertRecord("FUZZ-BATCH", rec); err != nil {
			crash("store rejected a record that parsed successfully: " + err.Error())
		}
		// Invariant: every parsed record carries a bound input hash.
		if rec.InputHash == "" {
			crash("parsed record missing input hash")
		}
		if rec.Schema != model.SchemaV1 && rec.Schema != model.SchemaV2 {
			crash("record has unknown schema tag")
		}
		r := engine.New().Run(rec, false)
		if err := p.PersistForFuzz("FUZZ-BATCH", r); err != nil {
			crash("could not persist transition trail: " + err.Error())
		}
		if len(r.Transitions) < 2 {
			crash("state machine produced no meaningful trail")
		}
		// Invariant: a trail that claims an error state must also record a
		// first-error pointer, otherwise the report could hide the first fault.
		hasErrorState := false
		for _, t := range r.Transitions {
			if model.IsErrorState(t.ToState) {
				hasErrorState = true
			}
		}
		if hasErrorState && r.FirstError == nil {
			crash("error state present but FirstError not captured")
		}
		if r.FirstError != nil && !model.IsErrorState(r.FirstError.State) {
			crash("FirstError points at a non-error state")
		}
		// Invariant: the four evidence dimensions must be bound on every step.
		for _, t := range r.Transitions {
			if t.TriggerSite == "" || t.AttackInput == "" ||
				t.InputHash == "" || t.Reason == "" {
				crash("transition missing required evidence dimension")
			}
		}
	}
	return 0
}

// main is required for a c-archive even though it is never invoked.
func main() {}
