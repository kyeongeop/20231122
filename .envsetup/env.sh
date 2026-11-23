# Source this file to activate the local toolchain: source .envsetup/env.sh
export PATH="/home/hj/.local/toolchains/go1.27.4/bin:/home/hj/.local/toolchains/clang-21/usr/bin:$PATH"
export LD_LIBRARY_PATH="/home/hj/.local/compat-libs:${LD_LIBRARY_PATH:-}"
export GOMODCACHE="/home/hj/.codex-relay-home-zsby_ujn/go/pkg/mod"
export GOFLAGS="-mod=mod"
export GOPROXY="off"
export CC=clang-21
export CXX=clang++-21
