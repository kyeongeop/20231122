package lockout

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// 原始抓包文件格式 (raw_capture.bin):
//   [4B magic "LGR1"][4B 记录数 N]
//   每条记录:
//     [4B payload 长度 L][16B 请求 ID][8B unix-nano 时间戳]
//     [2B 用户名长度][用户名][2B 密码长度][密码][1B 结果 0=失败 1=成功]
//
// 每条记录的 RawOffset 是它在原始文件中的起始字节偏移, 验收锚定到该偏移。

const (
	Magic         = "LGR1"
	headerLen     = 8
	MaxRecordSize = 4096 // 超过即视为超大输入
	MaxFieldLen   = 1024
)

var (
	ErrEmptyInput     = errors.New("empty input")
	ErrBadMagic       = errors.New("bad magic")
	ErrOversized      = errors.New("record exceeds MaxRecordSize")
	ErrTruncated      = errors.New("truncated record")
	ErrEmptyRecord    = errors.New("empty record payload")
	ErrFieldOversized = errors.New("field exceeds MaxFieldLen")
)

type Request struct {
	RawOffset int64  // 在原始抓包文件中的起始偏移
	Length    uint32 // 声明的 payload 长度
	RequestID string
	Timestamp int64
	Username  string
	Password  string
	Success   bool
}

// ParseError 携带出错位置的原始偏移, 便于证据定位。
type ParseError struct {
	Offset int64
	Err    error
}

func (e *ParseError) Error() string { return fmt.Sprintf("offset %d: %v", e.Offset, e.Err) }
func (e *ParseError) Unwrap() error { return e.Err }

// ParseRequests 解析整个抓包文件。空输入与超大输入在此被显式拒绝。
func ParseRequests(raw []byte) ([]Request, error) {
	if len(raw) == 0 {
		return nil, ErrEmptyInput
	}
	if len(raw) < headerLen {
		return nil, &ParseError{Offset: 0, Err: ErrTruncated}
	}
	if string(raw[:4]) != Magic {
		return nil, &ParseError{Offset: 0, Err: ErrBadMagic}
	}
	count := binary.LittleEndian.Uint32(raw[4:8])
	// 每条记录至少 4 字节长度前缀, 据此上限校验, 防止恶意 count 导致巨量预分配
	if uint64(count) > uint64(len(raw)-headerLen)/4 {
		return nil, &ParseError{Offset: 4, Err: fmt.Errorf("%w: declared count=%d", ErrTruncated, count)}
	}
	reqs := make([]Request, 0, count)
	pos := headerLen
	for i := uint32(0); i < count; i++ {
		recOff := int64(pos)
		if pos+4 > len(raw) {
			return reqs, &ParseError{Offset: recOff, Err: ErrTruncated}
		}
		l := binary.LittleEndian.Uint32(raw[pos : pos+4])
		if l == 0 {
			return reqs, &ParseError{Offset: recOff, Err: ErrEmptyRecord}
		}
		if l > MaxRecordSize {
			return reqs, &ParseError{Offset: recOff, Err: fmt.Errorf("%w: declared=%d", ErrOversized, l)}
		}
		if pos+4+int(l) > len(raw) {
			return reqs, &ParseError{Offset: recOff, Err: ErrTruncated}
		}
		req, err := parseRecord(raw[pos+4 : pos+4+int(l)])
		if err != nil {
			return reqs, &ParseError{Offset: recOff, Err: err}
		}
		req.RawOffset = recOff
		req.Length = l
		reqs = append(reqs, req)
		pos += 4 + int(l)
	}
	return reqs, nil
}

func parseRecord(p []byte) (Request, error) {
	var r Request
	if len(p) < 16+8 {
		return r, ErrTruncated
	}
	r.RequestID = fmt.Sprintf("%x", p[:16])
	r.Timestamp = int64(binary.LittleEndian.Uint64(p[16:24]))
	rest := p[24:]
	name, rest, err := takeField(rest)
	if err != nil {
		return r, err
	}
	pass, rest, err := takeField(rest)
	if err != nil {
		return r, err
	}
	if len(rest) < 1 {
		return r, ErrTruncated
	}
	r.Username = string(name)
	r.Password = string(pass)
	r.Success = rest[0] == 1
	return r, nil
}

func takeField(b []byte) ([]byte, []byte, error) {
	if len(b) < 2 {
		return nil, nil, ErrTruncated
	}
	n := int(binary.LittleEndian.Uint16(b[:2]))
	if n > MaxFieldLen {
		return nil, nil, fmt.Errorf("%w: %d", ErrFieldOversized, n)
	}
	if len(b) < 2+n {
		return nil, nil, ErrTruncated
	}
	return b[2 : 2+n], b[2+n:], nil
}

// EncodeCapture 构造原始抓包字节流, 供重建程序生成原始材料。
func EncodeCapture(reqs []Request) []byte {
	var buf bytes.Buffer
	buf.WriteString(Magic)
	binary.Write(&buf, binary.LittleEndian, uint32(len(reqs)))
	for _, r := range reqs {
		var rec bytes.Buffer
		id := make([]byte, 16)
		if len(r.RequestID) == 32 {
			fmt.Sscanf(r.RequestID, "%x", &id)
		} else {
			copy(id, r.RequestID)
		}
		rec.Write(id)
		binary.Write(&rec, binary.LittleEndian, uint64(r.Timestamp))
		putField(&rec, []byte(r.Username))
		putField(&rec, []byte(r.Password))
		if r.Success {
			rec.WriteByte(1)
		} else {
			rec.WriteByte(0)
		}
		binary.Write(&buf, binary.LittleEndian, uint32(rec.Len()))
		buf.Write(rec.Bytes())
	}
	return buf.Bytes()
}

func putField(buf *bytes.Buffer, v []byte) {
	binary.Write(buf, binary.LittleEndian, uint16(len(v)))
	buf.Write(v)
}
