// Package parser 实现 WebSocket 帧(RFC 6455)长度解析,
// 包含三个长度检查锚点:
//
//	A1-header   基础头长度检查(原始偏移 0..1)
//	A2-extlen   扩展长度字段检查(原始偏移 2..9)
//	A3-payload  负载边界检查(原始偏移 >= 2)
//
// ParseVulnerable 保留未修复的原始行为(越界读/溢出),
// ParseFixed 为局部修正版本,逐锚点校验并记录证据事件。
package parser

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	AnchorHeader  = "A1-header"
	AnchorExtLen  = "A2-extlen"
	AnchorPayload = "A3-payload"
)

// MaxPayload 是修复版允许的最大负载长度(16 MiB)。
const MaxPayload = 16 << 20

// AnchorEvent 记录一次锚点命中的关键证据。
type AnchorEvent struct {
	Anchor      string `json:"anchor"`
	RawOffset   int    `json:"raw_offset"`   // 触发检查的原始字节偏移
	DeclaredLen uint64 `json:"declared_len"` // 帧内声明的长度
	AvailLen    int    `json:"avail_len"`    // 缓冲区实际剩余
	Detail      string `json:"detail"`
}

// Frame 是解析成功的帧。
type Frame struct {
	Fin        bool
	Opcode     byte
	Masked     bool
	PayloadLen uint64
	HeaderLen  int
	Payload    []byte
}

// Result 是一次解析的完整结果,含证据事件与(被恢复的)panic。
type Result struct {
	Frame  *Frame
	Events []AnchorEvent
	Err    error
	Panic  any
}

// Parse 按 mode 解析:"fixed" 走修复版,其他走原始版。panic 被恢复并记录。
func Parse(data []byte, mode string) (res Result) {
	defer func() {
		if r := recover(); r != nil {
			res.Panic = r
		}
	}()
	if mode == "fixed" {
		res.Frame, res.Err = parseFixed(data, &res.Events)
	} else {
		res.Frame, res.Err = parseVulnerable(data)
	}
	return res
}

// parseVulnerable 是未修改的原始解析逻辑:三个锚点均不做长度检查。
func parseVulnerable(data []byte) (*Frame, error) {
	// A1: 直接索引,短输入即越界。
	b0, b1 := data[0], data[1]
	f := &Frame{Fin: b0&0x80 != 0, Opcode: b0 & 0x0f, Masked: b1&0x80 != 0}
	n := uint64(b1 & 0x7f)
	off := 2
	// A2: 不确认扩展长度字段是否在位,也不检查 64 位长度最高位。
	switch n {
	case 126:
		n = uint64(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
	case 127:
		n = binary.BigEndian.Uint64(data[off : off+8])
		off += 8
	}
	if f.Masked {
		off += 4 // 掩码键,同样不检查是否在位
	}
	// A3: 直接按声明长度切片,声明大于实际即越界;int 溢出也不检查。
	f.Payload = data[off : off+int(n)]
	f.PayloadLen = n
	f.HeaderLen = off
	return f, nil
}

// parseFixed 是局部修正版:仅在三个锚点处插入长度检查,其余逻辑不变。
func parseFixed(data []byte, events *[]AnchorEvent) (*Frame, error) {
	// A1-header: 基础头至少 2 字节。
	if len(data) < 2 {
		*events = append(*events, AnchorEvent{
			Anchor: AnchorHeader, RawOffset: 0,
			DeclaredLen: 2, AvailLen: len(data),
			Detail: "base header truncated",
		})
		return nil, errors.New("wsframe: base header truncated")
	}
	b0, b1 := data[0], data[1]
	f := &Frame{Fin: b0&0x80 != 0, Opcode: b0 & 0x0f, Masked: b1&0x80 != 0}
	n := uint64(b1 & 0x7f)
	off := 2

	// A2-extlen: 扩展长度字段必须完整,且 64 位长度最高位必须为 0。
	switch n {
	case 126:
		if len(data) < off+2 {
			*events = append(*events, AnchorEvent{
				Anchor: AnchorExtLen, RawOffset: off,
				DeclaredLen: 2, AvailLen: len(data) - off,
				Detail: "16-bit extended length truncated",
			})
			return nil, errors.New("wsframe: 16-bit extended length truncated")
		}
		n = uint64(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
	case 127:
		if len(data) < off+8 {
			*events = append(*events, AnchorEvent{
				Anchor: AnchorExtLen, RawOffset: off,
				DeclaredLen: 8, AvailLen: len(data) - off,
				Detail: "64-bit extended length truncated",
			})
			return nil, errors.New("wsframe: 64-bit extended length truncated")
		}
		n = binary.BigEndian.Uint64(data[off : off+8])
		off += 8
		if n&(1<<63) != 0 {
			*events = append(*events, AnchorEvent{
				Anchor: AnchorExtLen, RawOffset: off - 8,
				DeclaredLen: n, AvailLen: len(data) - off,
				Detail: "64-bit length MSB set",
			})
			return nil, errors.New("wsframe: 64-bit length MSB set")
		}
	}
	if f.Masked {
		if len(data) < off+4 {
			*events = append(*events, AnchorEvent{
				Anchor: AnchorExtLen, RawOffset: off,
				DeclaredLen: 4, AvailLen: len(data) - off,
				Detail: "masking key truncated",
			})
			return nil, errors.New("wsframe: masking key truncated")
		}
		off += 4
	}

	// A3-payload: 声明负载必须落在剩余缓冲区内且不超过上限。
	if n > MaxPayload || n > uint64(len(data)-off) {
		*events = append(*events, AnchorEvent{
			Anchor: AnchorPayload, RawOffset: off,
			DeclaredLen: n, AvailLen: len(data) - off,
			Detail: fmt.Sprintf("declared payload %d exceeds available %d", n, len(data)-off),
		})
		return nil, errors.New("wsframe: declared payload length out of bounds")
	}
	f.Payload = data[off : off+int(n)]
	f.PayloadLen = n
	f.HeaderLen = off
	return f, nil
}
