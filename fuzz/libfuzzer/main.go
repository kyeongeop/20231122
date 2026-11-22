package main

/*
#include <stdlib.h>

static void depthlab_abort(void) {
	abort();
}
*/
import "C"

import (
	"encoding/json"
	"unsafe"

	"depthlab/internal/graphql"
)

//export LLVMFuzzerTestOneInput
func LLVMFuzzerTestOneInput(data unsafe.Pointer, size C.int) C.int {
	query := C.GoBytes(data, size)
	if fuzzQuery(query) {
		C.depthlab_abort()
	}
	return 0
}

func fuzzQuery(query []byte) bool {
	trace := graphql.Analyze(string(query), graphql.DefaultLimit)
	var depth struct {
		MaxDepth int  `json:"max_depth"`
		Complete bool `json:"complete"`
	}
	if err := json.Unmarshal(trace.Steps[3].Result, &depth); err != nil {
		return false
	}
	return depth.Complete && depth.MaxDepth > graphql.DefaultLimit
}

func main() {}
