# libFuzzer replay

The C harness accepts the same `RZ31` container bytes stored in SQLite. It
checks the magic, declared size, record count and extension length before
following the unregistered `0x7e` path.

Build and replay the preserved sample:

```bash
cd fuzz
CC=clang ./build.sh
./kz3_replay corpus/seed.kz3
```

The standalone binary is built with ASan and UBSan. A non-zero exit status and
an `AddressSanitizer: heap-buffer-overflow` report are the expected result.
`./run.sh` performs the same check and stores stderr in `../tmp/replay.stderr`.

Run the actual libFuzzer target with the saved corpus:

```bash
./kz3_fuzz -runs=200000 corpus/
```

The crash is not allowed to mutate the evidence database. Replays are copied
into SQLite only by the Go service, with the input SHA-256 and command recorded.
