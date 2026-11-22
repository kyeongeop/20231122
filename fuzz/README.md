# libFuzzer target

`cache_key_fuzzer.cpp` mirrors the Go cache key experiment. It stores the second
snapshot under the same `METHOD + path` key, then asserts that the second fetch
is served from the selected snapshot. A version-blind key trips
`CACHELEAK_ASSERT` and `__builtin_trap()`, producing a permanent crash artifact.

```bash
./build.sh
./run.sh
```

The Go runner invokes the same target with `-fsanitize=fuzzer,address`, captures
the complete log, and seals both the log and the crash artifact in the evidence
directory. An artifact is expected; the experiment checks the sealed SHA-256
rather than treating the non-zero libFuzzer exit as a runner failure.
