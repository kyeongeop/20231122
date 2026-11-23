package main

/*
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"encoding/json"
	"unsafe"

	"oauthreview/internal/callback"
	"oauthreview/internal/runner"
)

var validator = callback.NewValidator(runner.NewPolicy())

// Fuzz 是 libFuzzer 入口（经 fuzzentry.c 桥接）。
// 不变量：任意输入都不得触发 panic；所有可识别输入必须产生确定性结论。
//
//export Fuzz
func Fuzz(data *C.char, size C.int) C.int {
	raw := C.GoBytes(unsafe.Pointer(data), size)

	// 语料封装形态：完整 Envelope JSON，覆盖两种 Content-Type 路径。
	var env runner.Envelope
	if json.Unmarshal(raw, &env) == nil && env.Body != "" {
		exercise(env.ContentType, []byte(env.Body))
		return 0
	}
	// 裸输入形态：分别按两种格式尝试，解析器必须优雅拒绝。
	exercise("application/x-www-form-urlencoded", raw)
	exercise("application/json", raw)
	return 0
}

func exercise(contentType string, body []byte) {
	cb, err := callback.Parse(contentType, body)
	if err != nil {
		return
	}
	out := validator.Validate("fuzz", cb)
	if out == nil || out.Decision.Verdict == "" {
		panic("validator returned empty verdict")
	}
}

func main() {}
