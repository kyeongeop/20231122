# Source this file to pick up the offline toolchains used in this environment:
#   source scripts/env.sh
export PATH="/tmp/go/bin:/tmp/clangroot/usr/bin:$PATH"
export GOPATH="${GOPATH:-/home/hj/.gopath}"
export GOPROXY=off
export GOSUMDB=off
export GOFLAGS=-mod=mod
export CGO_ENABLED=1
