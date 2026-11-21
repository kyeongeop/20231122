package proto

// Op is a protocol command opcode.
type Op byte

const (
	OpNop Op = iota
	OpHello
	OpAuth
	OpOpen
	OpSend
	OpClose
)

func (o Op) String() string {
	switch o {
	case OpNop:
		return "NOP"
	case OpHello:
		return "HELLO"
	case OpAuth:
		return "AUTH"
	case OpOpen:
		return "OPEN"
	case OpSend:
		return "SEND"
	case OpClose:
		return "CLOSE"
	}
	return "UNKNOWN"
}

// Command is one decoded protocol command.
type Command struct {
	Op      Op
	Payload []byte
}

// Record is a decoded byte stream: a sequence of commands plus a flag
// indicating the trailing bytes formed a truncated (incomplete) record.
type Record struct {
	Cmds      []Command
	Truncated bool
	Tail      []byte // undecodable trailing bytes when Truncated
}

// Decode parses the wire format: [op:1][len:1][payload:len]*.
// If len exceeds the remaining bytes the record is truncated; decoding
// stops and the remainder is reported as the tail.
func Decode(data []byte) Record {
	var rec Record
	i := 0
	for i < len(data) {
		if i+2 > len(data) {
			rec.Truncated = true
			rec.Tail = data[i:]
			return rec
		}
		op := Op(data[i])
		n := int(data[i+1])
		if i+2+n > len(data) {
			rec.Truncated = true
			rec.Tail = data[i:]
			return rec
		}
		payload := make([]byte, n)
		copy(payload, data[i+2:i+2+n])
		rec.Cmds = append(rec.Cmds, Command{Op: op, Payload: payload})
		i += 2 + n
	}
	return rec
}
