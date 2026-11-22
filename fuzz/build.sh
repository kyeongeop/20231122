#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${ROOT}/build/fuzz"
USER_HOME="$(getent passwd "$(id -u)" | cut -d: -f6)"
mkdir -p "${BUILD}"

GO_BIN="${GO:-$(command -v go || true)}"
if [[ -z "${GO_BIN}" && -x "${USER_HOME}/.local/go/bin/go" ]]; then
  GO_BIN="${USER_HOME}/.local/go/bin/go"
fi
CC_BIN="${CC:-$(command -v clang || true)}"
if [[ -z "${CC_BIN}" && -x "${USER_HOME}/.local/llvm/usr/bin/clang-21" ]]; then
  CC_BIN="${USER_HOME}/.local/llvm/usr/bin/clang-21"
fi
CXX_BIN="${CXX:-$(command -v clang++ || true)}"
if [[ -z "${CXX_BIN}" && -x "${USER_HOME}/.local/llvm/usr/bin/clang++-21" ]]; then
  CXX_BIN="${USER_HOME}/.local/llvm/usr/bin/clang++-21"
fi
if [[ -z "${CC_BIN}" && -x "${USER_HOME}/.local/llvm/usr/bin/clang" ]]; then
  CC_BIN="${USER_HOME}/.local/llvm/usr/bin/clang"
fi
if [[ -z "${CXX_BIN}" && -x "${USER_HOME}/.local/llvm/usr/bin/clang++" ]]; then
  CXX_BIN="${USER_HOME}/.local/llvm/usr/bin/clang++"
fi
if [[ -z "${GO_BIN}" ]]; then
  echo "go not found; set GO=/path/to/go" >&2
  exit 1
fi
if [[ -z "${CC_BIN}" || -z "${CXX_BIN}" ]]; then
  echo "clang/clang++ not found; set CC and CXX" >&2
  exit 1
fi

ARCHIVE="${BUILD}/libtaintlab_fuzz.a"
BIN="${BUILD}/taintlab_fuzz"
export CGO_ENABLED=1
export CC="${CC_BIN}"
export CXX="${CXX_BIN}"
export CGO_CFLAGS="-fsanitize=fuzzer"
export CGO_LDFLAGS="-fsanitize=fuzzer"
export GOTOOLCHAIN=local

"${GO_BIN}" build \
  -tags=libfuzzer \
  -gcflags=all=-d=libfuzzer \
  -buildmode=c-archive \
  -o "${ARCHIVE}" \
  "${ROOT}/fuzz"

"${CXX_BIN}" -O1 -g -fsanitize=fuzzer \
  -o "${BIN}" "${ARCHIVE}" -lpthread -ldl -lm

echo "built ${BIN}"

