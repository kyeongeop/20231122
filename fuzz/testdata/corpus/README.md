# Fuzz seed corpus

Regenerate with:

```bash
go run ./cmd/truncstream corpus fuzz/testdata/corpus
```

The same seeds are copied into `fuzz/corpus_libfuzzer/` for the clang
libFuzzer harness. Each seed exercises one documented parser path:

| seed | expected class |
| --- | --- |
| `valid_compressed`, `uncompressed`, `no_eof` | success / truncation at EOF |
| `bad_magic` | `BAD_MAGIC` |
| `truncated_header` | `TRUNCATED_HEADER` |
| `truncated_payload` | `TRUNCATED_PAYLOAD` |
| `corrupt_payload` | `CHECKSUM_MISMATCH` / `DECOMPRESS_FAILED` |
| `tiny`, `empty` | `TRUNCATED_HEADER` |

The regression input that previously crashed the parser (varint length
overflow) is tracked under
`internal/stream/testdata/fuzz/FuzzParse/1270d30f2697e90e` and is replayed
by every `go test ./internal/stream/` run.
