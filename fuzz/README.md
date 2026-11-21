# libFuzzer integration

`harness.cc` is a real libFuzzer entry point. It calls `CorpusProbe`, exported
from the Go package in `bridge/`, through a c-archive. The probe is the same
deterministic reducer used when corpus objects are processed before and after a
pause, so fuzz findings exercise production input handling.

```sh
./fuzz/build.sh
./fuzz/run.sh                    # SECONDS_TO_RUN=60 ./fuzz/run.sh
```

Requires clang with the fuzzer sanitizer runtime. If clang is unavailable, the
equivalent Go-native libFuzzer workflow still runs:

```sh
go test ./internal/probe -run '^$' -fuzz FuzzAnalyze -fuzztime 30s
```
