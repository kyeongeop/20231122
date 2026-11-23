#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN="$ROOT/.toolchain"
ROOTFS="$TOOLCHAIN/root"

if [[ -x "$ROOTFS/usr/local/go/bin/go" && -x "$ROOTFS/usr/lib/llvm-20/bin/clang" ]]; then
	echo "toolchain already present: $ROOTFS"
	exit 0
fi

mkdir -p "$TOOLCHAIN/debs" "$TOOLCHAIN/root" "$TOOLCHAIN/downloads"
(
	cd "$TOOLCHAIN/debs"
	apt-get -o Acquire::http::Proxy=false -o Acquire::https::Proxy=false download \
		clang-20 libclang-cpp20 libllvm20 libclang-common-20-dev \
		llvm-20-linker-tools libclang1-20 libclang-rt-20-dev libsqlite3-dev
)
for deb in "$TOOLCHAIN"/debs/*.deb; do
	dpkg-deb -x "$deb" "$ROOTFS"
done
if [[ ! -x "$ROOTFS/usr/local/go/bin/go" ]]; then
	curl -fL --retry 3 -o "$TOOLCHAIN/downloads/go.tar.gz" \
		https://go.dev/dl/go1.24.6.linux-amd64.tar.gz
	mkdir -p "$ROOTFS/usr/local"
	tar -C "$ROOTFS/usr/local" -xzf "$TOOLCHAIN/downloads/go.tar.gz"
fi

echo "toolchain ready: $ROOTFS"

