# Source this file to expose the user-local Go 1.24 + clang-18/libFuzzer toolchain.
# Usage: source ./env.sh
export GOROOT="$HOME/.local/go"
export LLVM_HOME="$HOME/.local/llvm18/usr/lib/llvm-18"
export PATH="$GOROOT/bin:$LLVM_HOME/bin:$PATH"
export LD_LIBRARY_PATH="$LLVM_HOME/lib:$HOME/.local/llvm18/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
export GOTOOLCHAIN=local
export GOSUMDB=off
export GOFLAGS=-mod=mod
# The ambient proxy on this host is dead; talk to the network directly.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
