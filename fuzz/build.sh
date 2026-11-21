#!/usr/bin/env bash
# Builds both the hardened and vulnerable libFuzzer targets.
# Requires clang with compiler-rt (libFuzzer) and sanitizer runtimes.
set -euo pipefail

CLANG="${CLANG:-clang}"
cd "$(dirname "$0")"

"$CLANG" -g -O1 -fsanitize=fuzzer,address,undefined \
	parser_fuzz.c -o parser_fuzz_hardened

# The vulnerable target additionally enables the non-default unsigned-wrap
# check so the historical uint32 overflows are reported as audit findings.
"$CLANG" -g -O1 -fsanitize=fuzzer,address,undefined -DVULNERABLE \
	-fsanitize=unsigned-integer-overflow \
	parser_fuzz.c -o parser_fuzz_vulnerable

echo "built: parser_fuzz_hardened parser_fuzz_vulnerable"
