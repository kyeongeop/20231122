package main

/*
#include <stdint.h>
*/
import "C"

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"proto-fuzz-exp/proto"
)

const maxSavedArtifacts = 32

var (
	seenMu   sync.Mutex
	seenSigs = map[string]bool{}
	savedN   int
)

func artifactDir() string {
	if d := os.Getenv("FUZZ_ARTIFACT_DIR"); d != "" {
		return d
	}
	return "."
}

//export FuzzOne
func FuzzOne(data *C.uint8_t, n C.int) C.int {
	b := C.GoBytes(unsafe.Pointer(data), n)
	rec := proto.Decode(b)
	sig1 := proto.Signature(proto.Execute(1, rec))
	sig2 := proto.Signature(proto.Execute(2, rec))
	if sig1 != sig2 {
		// Deduplicate by divergence signature and cap the artifact count:
		// one representative input per distinct divergence is enough.
		pair := sig1 + "||" + sig2
		seenMu.Lock()
		if seenSigs[pair] || savedN >= maxSavedArtifacts {
			seenMu.Unlock()
			return 0
		}
		seenSigs[pair] = true
		savedN++
		seenMu.Unlock()
		sum := sha1.Sum(b)
		path := filepath.Join(artifactDir(), "crash-"+hex.EncodeToString(sum[:]))
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if werr := os.WriteFile(path, b, 0o644); werr == nil {
				fmt.Printf("DIVERGENCE v1=%q v2=%q saved=%s\n", sig1, sig2, path)
			}
		}
	}
	return 0
}

func main() {}
