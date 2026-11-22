# 20231122

## Filename Unicode Bypass — Pausable Processing Pipeline

Go + libFuzzer + SQLite implementation of a pausable pipeline that hunts
Unicode-based filename filter bypasses around a set of "missing fragment"
templates.

### Layout

- `internal/filter/filter.go` — naive validator under test, canonicalization
  oracle (fullwidth folding, confusable mapping, Cf/Cc stripping, bidi
  detection, Windows trailing-dot/space trim), hardened validator, and the
  cheap degraded path.
- `internal/filter/fuzz_test.go` — `FuzzFilenameUnicodeBypass` (finds
  bypasses; crashers are preserved as evidence) and
  `FuzzHardenedNoBypass` (invariant of the hardened filter, stays green).
- `cmd/fuzzbypass/main.go` — libFuzzer shim exporting
  `LLVMFuzzerTestOneInput`. Build with
  `go build -tags "fuzzshim libfuzzer" -buildmode=c-shared` and link with
  `clang -fsanitize=fuzzer`. (The `libfuzzer` tag is Go's official
  coverage-instrumentation switch; linking requires clang's sanitizer-cov
  runtime.)
- `internal/pipeline/` — deterministic extreme-parameter corpus generator
  (`corpus.go`), pausable checkpointed processor (`pipeline.go`), evidence
  report renderer (`report.go`).
- `internal/store/store.go` — minimal cgo binding to the system
  `libsqlite3` (prototypes declared locally; no dev headers needed).
- `cmd/ubpipe/main.go` — CLI driver.

### Corpus: extreme parameters around a missing fragment

8 missing-fragment templates (missing stem `report..exe`, missing path
segment `dir//payload.exe`, missing ASCII dot `photo\u2024exe`, missing
UTF-8 continuation byte, missing visual order via U+202E RLO, fullwidth
delimiters, trailing dot, `tar..gz`) x 4 Unicode tricks (ZWSP injection,
Cyrillic homoglyph ext, trailing space, none) x pad-to-length
{254, 255, 256, 257, 4095, 4096} x pad position {prefix, middle, suffix}
= 608 deterministic items with stable IDs.

### Pausable flow

```sh
go run ./cmd/ubpipe run    --db artifacts/evidence.db --pause-after 60
go run ./cmd/ubpipe resume --db artifacts/evidence.db
go run ./cmd/ubpipe report --db artifacts/evidence.db --out artifacts/evidence_report.md
```

- Every batch commits a checkpoint transaction (offset, cumulative
  SHA-256 digest, last-item verdict hash) into SQLite; a pause loses at
  most nothing and a crash loses at most one batch.
- On resume the pipeline recomputes the verdict hash of the last
  pre-pause item and compares it with the checkpoint (integrity proof),
  then continues; pre-pause vs post-resume results are compared in the
  report (segment stats + cumulative digests).
- Resource pressure: names >= `--degrade-len` bytes take the cheap
  ASCII-only degraded path per item; an expired deadline degrades the
  rest of the session (sticky, persisted in the checkpoint). Every
  degradation is recorded with its reason.
- Boundary sampling: each segment records exactly one sample on each
  side of the length boundary (`--boundary`, default 255), so the report
  shows the before/after change across the boundary and across pause/resume.

### Fuzzing

```sh
go test -fuzz=FuzzFilenameUnicodeBypass -fuzztime=30s ./internal/filter/
go test -fuzz=FuzzHardenedNoBypass   -fuzztime=30s ./internal/filter/
```

Crashers land in `internal/filter/testdata/fuzz/...`; preserved copies
live in `artifacts/evidence/fuzz_corpus/`.

### Evidence

- `artifacts/evidence.db` — SQLite evidence (runs, checkpoints, findings,
  degradations, boundary_samples).
- `artifacts/evidence_report.md` — rendered report.
- `artifacts/evidence/fuzz_corpus/` — fuzzer-discovered bypass inputs.
