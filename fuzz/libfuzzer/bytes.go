//go:build cgofuzz

package main

/*
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import "unsafe"

// cBytes 把 libFuzzer 提供的 C 缓冲区拷贝为 Go 字符串，
// 不保留对 C 内存的引用，避免越界访问。
func cBytes(data *C.uint8_t, size C.size_t) []byte {
	if size == 0 || data == nil {
		return nil
	}
	n := int(size)
	slice := unsafe.Slice((*byte)(unsafe.Pointer(data)), n)
	cp := make([]byte, n)
	copy(cp, slice)
	return cp
}
