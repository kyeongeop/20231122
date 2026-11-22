# Source this file to activate the rootless toolchain:
#   source scripts/env.sh
#
# Provides Go 1.24 and clang-18 (with libFuzzer + sanitizer runtimes)
# installed under ~/.local/toolchain without requiring root.

CK_TOOLCHAIN_ROOT="${CK_TOOLCHAIN_ROOT:-$HOME/.local/toolchain}"

export GOROOT="$CK_TOOLCHAIN_ROOT/go"
export LLVM_HOME="$CK_TOOLCHAIN_ROOT/llvm18/usr/lib/llvm-18"

export PATH="$LLVM_HOME/bin:$GOROOT/bin:$PATH"
export LD_LIBRARY_PATH="$LLVM_HOME/lib:$CK_TOOLCHAIN_ROOT/llvm18/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"

# ckaudit defaults; override when invoking the CLI.
export CK_CLANG="$LLVM_HOME/bin/clang-18"
export CK_CC="${CK_CC:-cc}"

# System ships libsqlite3.so.0 without the development symlink; provide one.
mkdir -p "$CK_TOOLCHAIN_ROOT/lib"
ln -sf /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 "$CK_TOOLCHAIN_ROOT/lib/libsqlite3.so" 2>/dev/null || true
export CGO_ENABLED=1
export CGO_LDFLAGS="-L$CK_TOOLCHAIN_ROOT/lib -lsqlite3"
export CGO_CFLAGS="-g -O1"

echo "env: $(go version 2>/dev/null) | $(clang-18 --version 2>/dev/null | head -1)"
