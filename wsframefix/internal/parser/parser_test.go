package parser

import "testing"

func TestAnchors(t *testing.T) {
	cases := []struct {
		name   string
		data   []byte
		anchor string
		offset int
	}{
		{"A1 基础头截断", []byte{0x81}, AnchorHeader, 0},
		{"A2 16位扩展长度截断", []byte{0x81, 0x7e, 0x01}, AnchorExtLen, 2},
		{"A2 64位扩展长度截断", []byte{0x81, 0x7f, 0xff}, AnchorExtLen, 2},
		{"A2 64位长度最高位", []byte{0x81, 0x7f, 0x80, 0, 0, 0, 0, 0, 0, 1}, AnchorExtLen, 2},
		{"A2 掩码键截断", []byte{0x81, 0x85, 1, 2}, AnchorExtLen, 2},
		{"A3 负载越界", []byte{0x81, 0x7e, 0xff, 0xff, 'x'}, AnchorPayload, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := Parse(c.data, "fixed")
			if res.Err == nil || len(res.Events) == 0 {
				t.Fatalf("期望拒绝并记录锚点事件, 实际 %+v", res)
			}
			ev := res.Events[len(res.Events)-1]
			if ev.Anchor != c.anchor || ev.RawOffset != c.offset {
				t.Fatalf("锚点=%s 偏移=%d, 期望 %s@%d", ev.Anchor, ev.RawOffset, c.anchor, c.offset)
			}
			vuln := Parse(c.data, "vulnerable")
			if vuln.Panic == nil && vuln.Err == nil && c.anchor != AnchorPayload {
				t.Fatalf("原始版未暴露缺陷: %+v", vuln)
			}
		})
	}
}

func TestValidFrame(t *testing.T) {
	data := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'}
	res := Parse(data, "fixed")
	if res.Err != nil || res.Frame.PayloadLen != 5 || string(res.Frame.Payload) != "hello" {
		t.Fatalf("合法帧解析失败: %+v", res)
	}
}
