package main

/*
#include <stdint.h>
*/
import "C"

import (
	"unsafe"

	"crossdomain-audit/internal/audit"
)

const maxFuzzInput = 1 << 20

//export CrossDomainAuditFuzz
func CrossDomainAuditFuzz(data *C.uchar, size C.size_t) C.int {
	if data == nil || size == 0 || size > maxFuzzInput {
		return 0
	}
	raw := C.GoBytes(unsafe.Pointer(data), C.int(size))
	mode := raw[0] % 4
	payload := raw[1:]
	opt := audit.Options{}
	switch mode {
	case 1:
		opt.ExpectedBytes = len(payload) + 1 + int(raw[0]%97)
	case 2:
		opt.ExpectedBytes = len(payload)
		opt.ReplayOf = "fuzz-replay"
		opt.RecoveredFrom = len(payload) / 2
	case 3:
		opt.ExpectedBytes = len(payload) + 1
	}
	result := audit.Analyze(payload, opt)
	validateResult(payload, result)
	return C.int(stateSignal(result))
}

func stateSignal(result audit.Result) int {
	code := len(result.Steps) & 0x0f
	code |= (result.Counts.Pass & 0x03) << 4
	if result.Counts.Fail > 0 {
		code |= 1 << 6
	}
	if result.Counts.Undecided > 0 {
		code |= 1 << 7
	}
	if result.Counts.Blocked > 0 {
		code |= 1 << 8
	}
	if result.Counts.Truncated > 0 {
		code |= 1 << 9
	}
	if result.FirstError != nil {
		code |= 1 << 10
		code |= (result.FirstError.Ordinal & 0x07) << 11
	}
	if result.Boundary != nil {
		code |= 1 << 14
		code |= (result.Boundary.Ordinal & 0x07) << 15
	}
	if result.ReplayOK {
		code |= 1 << 18
	}
	return code
}

func validateResult(raw []byte, result audit.Result) {
	for _, step := range result.Steps {
		if step.Status == audit.StatusFail || step.Status == audit.StatusTruncated {
			if result.FirstError == nil {
				panic("first error invariant violated")
			}
		}
		if step.Status == audit.StatusUndecided && result.Boundary == nil {
			panic("undecided boundary invariant violated")
		}
		if step.Evidence == nil {
			continue
		}
		if step.Evidence.Start < 0 || step.Evidence.End < step.Evidence.Start || step.Evidence.End > len(raw) {
			panic("evidence range escaped input")
		}
	}
}

func main() {}
