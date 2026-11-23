ROOT := $(CURDIR)
TOOLCHAIN := $(ROOT)/.toolchain/root

export PATH := $(TOOLCHAIN)/usr/local/go/bin:$(TOOLCHAIN)/usr/lib/llvm-20/bin:$(PATH)
export LD_LIBRARY_PATH := $(TOOLCHAIN)/usr/lib/x86_64-linux-gnu:$(TOOLCHAIN)/usr/lib/llvm-20/lib:$(LD_LIBRARY_PATH)
export GOPATH := $(ROOT)/.toolchain/gopath
export GOMODCACHE := $(GOPATH)/pkg/mod
export GOCACHE := $(ROOT)/.toolchain/gocache
export CGO_ENABLED := 1
export CGO_CFLAGS := -I$(TOOLCHAIN)/usr/include
export CGO_LDFLAGS := -L$(TOOLCHAIN)/usr/lib/x86_64-linux-gnu -Wl,-rpath,$(TOOLCHAIN)/usr/lib/x86_64-linux-gnu
