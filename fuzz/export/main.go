package main

/*
#include <stddef.h>
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"sync"
	"unsafe"

	"example.com/migration-review/internal/fuzzcheck"
	"example.com/migration-review/internal/model"
	"example.com/migration-review/internal/policy"
)

var (
	engineMu sync.RWMutex
	engine   *policy.Engine
)

//export MFLoadPolicy
func MFLoadPolicy(data *C.uchar, size C.size_t) C.int {
	if size == 0 || size > 1<<20 {
		return -1
	}
	bytes := C.GoBytes(unsafe.Pointer(data), C.int(size))
	loaded, err := policy.Load(bytes)
	if err != nil {
		return -2
	}
	engineMu.Lock()
	engine = loaded
	engineMu.Unlock()
	return 0
}

//export MFEvaluate
func MFEvaluate(data *C.uchar, size C.size_t) (result C.int) {
	defer func() {
		if recover() != nil {
			result = -1
		}
	}()
	if size > 4<<20 {
		return -2
	}
	bytes := C.GoBytes(unsafe.Pointer(data), C.int(size))
	engineMu.RLock()
	current := engine
	engineMu.RUnlock()
	if current == nil {
		return -3
	}
	manifest, decision, err := fuzzcheck.Evaluate(bytes, current)
	if err != nil {
		return 0
	}
	normalized := manifest.Normalized
	if len(normalized) == 0 {
		return -4
	}
	var roundTrip map[string]any
	if err := json.Unmarshal(normalized, &roundTrip); err != nil {
		return -5
	}
	if decision.Allowed {
		for _, statement := range decision.Statements {
			if !statement.Allowed {
				return -6
			}
		}
	}
	return C.int(semanticFeatures(bytes, manifest, decision))
}

func semanticFeatures(raw []byte, manifest *model.Manifest, decision model.PermissionDecision) uint32 {
	features := uint32(1)
	switch manifest.Format {
	case model.FormatLegacyJSON:
		features |= 1 << 1
	case model.FormatLegacySQL:
		features |= 1 << 2
	case model.FormatCurrent:
		features |= 1 << 3
	}
	if len(manifest.Statements) > 1 {
		features |= 1 << 4
	}
	if len(manifest.Statements) > 3 {
		features |= 1 << 5
	}
	if len(manifest.ParseWarnings) > 0 {
		features |= 1 << 6
	}
	if decision.Allowed {
		features |= 1 << 7
	} else {
		features |= 1 << 8
	}
	for _, statement := range decision.Statements {
		switch statement.Capability {
		case model.CapRead:
			features |= 1 << 9
		case model.CapWrite:
			features |= 1 << 10
		case model.CapSchema:
			features |= 1 << 11
		case model.CapDestructive:
			features |= 1 << 12
		case model.CapAttach:
			features |= 1 << 13
		case model.CapAdmin:
			features |= 1 << 14
		}
		if !statement.Allowed {
			features |= 1 << 15
		}
		if statement.OperatorOpt != "" && !statement.Allowed {
			features |= 1 << 16
		}
	}
	if manifest.Actor == "" {
		features |= 1 << 17
	}
	if manifest.ApprovalID != "" {
		features |= 1 << 18
	}
	if bytes.Contains(raw, []byte(";")) {
		features |= 1 << 19
	}
	if bytes.Contains(raw, []byte("--")) || bytes.Contains(raw, []byte("/*")) {
		features |= 1 << 20
	}
	if bytes.ContainsAny(raw, "'\"`[") {
		features |= 1 << 21
	}
	if bytes.IndexByte(raw, 0) >= 0 {
		features |= 1 << 22
	}
	for _, b := range raw {
		if b >= 0x80 {
			features |= 1 << 23
			break
		}
	}
	return features & 0x7fffffff
}

func main() {}
