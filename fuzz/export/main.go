package main

/*
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"bytes"
	"unsafe"

	"webhookprovenance/internal/inspect"
)

//export GoVerifyWebhook
func GoVerifyWebhook(data *C.uint8_t, size C.size_t) C.int {
	if data == nil || size == 0 || size > 64*1024 {
		return 0
	}
	input := C.GoBytes(unsafe.Pointer(data), C.int(size))
	signature, body, found := bytes.Cut(input, []byte("\n"))
	if !found {
		signature, body = nil, input
	}
	outcome := inspect.VerifyWebhook(inspect.VerifyInput{
		ObjectID:      "libfuzzer",
		Body:          body,
		Signature:     string(signature),
		SignatureAlg:  "HMAC-SHA256",
		Canonicalizer: "stripe-v1",
		Headers: map[string]string{
			"content-type": "application/octet-stream",
		},
		Secret: []byte("whsec_fuzz_fixture"),
	})
	if outcome.Err != nil {
		if outcome.Failure != nil && outcome.Failure.Code == "SIG_ENVELOPE_INVALID" {
			return 2
		}
		return 3
	}
	switch outcome.Result.Verdict {
	case inspect.VerdictVerified:
		return 1
	case inspect.VerdictIndeterminate:
		return 4
	default:
		return 5
	}
}

func main() {}
