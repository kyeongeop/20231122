#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USER_HOME="$(getent passwd "$(id -u)" | cut -d: -f6)"
if [[ -z "$USER_HOME" ]]; then
	USER_HOME="$HOME"
fi

find_go() {
	if command -v go >/dev/null 2>&1; then
		command -v go
		return
	fi
	local candidate
	for candidate in \
		"$USER_HOME/.local/toolchains/go/bin/go" \
		"$USER_HOME/.local/toolchain/go/bin/go" \
		"$USER_HOME/.local/go/bin/go" \
		"$HOME/.local/toolchains/go/bin/go" \
		"$HOME/.local/toolchain/go/bin/go" \
		"$HOME/.local/go/bin/go" \
		"/usr/local/go/bin/go"; do
		if [[ -x "$candidate" ]]; then
			printf '%s\n' "$candidate"
			return
		fi
	done
	return 1
}

find_clang() {
	if command -v clang >/dev/null 2>&1; then
		command -v clang
		return
	fi
	local candidate
	for candidate in \
		"$USER_HOME/.local/toolchains/clang-21/usr/lib/llvm-21/bin/clang" \
		"$USER_HOME/.local/llvm/usr/lib/llvm-21/bin/clang" \
		"$USER_HOME/.local/llvm18/usr/lib/llvm-18/bin/clang" \
		"$HOME/.local/toolchains/clang-21/usr/lib/llvm-21/bin/clang" \
		"$HOME/.local/llvm/usr/lib/llvm-21/bin/clang" \
		"$HOME/.local/llvm18/usr/lib/llvm-18/bin/clang" \
		"/usr/bin/clang"; do
		if [[ -x "$candidate" ]]; then
			printf '%s\n' "$candidate"
			return
		fi
	done
	return 1
}

GO="$(find_go)" || {
	echo "Go toolchain not found; set GO or add go to PATH" >&2
	exit 1
}
CLANG="$(find_clang)" || {
	echo "Clang with libFuzzer not found; set CLANG or add clang to PATH" >&2
	exit 1
}

export GO
export CLANG
export ROOT
export CGO_ENABLED=1
export CC="$CLANG"
export TMPDIR="$ROOT/.tmp"
mkdir -p "$TMPDIR"
