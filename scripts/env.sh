# Source this file to put the locally available toolchain on PATH.
# Go 1.23.4 ships in ~/go; clang-18 + libFuzzer were extracted from Ubuntu
# .deb packages into /tmp/llvm-debs (no root required). Override the roots
# with GO_ROOT / LLVM_ROOT if your layout differs.

GO_ROOT=${GO_ROOT:-/home/hj/go}
LLVM_ROOT=${LLVM_ROOT:-/tmp/llvm-debs/usr/lib/llvm-18}
LLVM_LIBDIR=${LLVM_LIBDIR:-/tmp/llvm-debs/usr/lib/x86_64-linux-gnu}

export PATH="$GO_ROOT/bin:$LLVM_ROOT/bin:$PATH"
export LD_LIBRARY_PATH="$LLVM_ROOT/lib:$LLVM_LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# The module proxy is reachable directly but not through the (currently down)
# local proxy; checksum verification is disabled for the offline mirror.
export GOSUMDB=off
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true
