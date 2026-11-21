package proto

import (
	"encoding/hex"
	"fmt"
)

// StepLog captures one executed step: input, state transition, result.
type StepLog struct {
	Seq         int
	InputHex    string
	StateBefore string
	StateAfter  string
	Result      string
}

// Execute runs a decoded record against a fresh machine of the given
// version, logging every step. A truncated tail is logged as a final
// TRUNCATED_REJECTED step with no state change. A panic in any step is
// recovered, logged as an EXCEPTION step, and execution of that record
// stops; the caller continues with the remaining objects.
func Execute(version int, rec Record) (steps []StepLog) {
	m := New(version)
	defer func() {
		if r := recover(); r != nil {
			steps = append(steps, StepLog{
				Seq:         len(steps),
				InputHex:    "-",
				StateBefore: m.State.String(),
				StateAfter:  m.State.String(),
				Result:      fmt.Sprintf("EXCEPTION: %v", r),
			})
		}
	}()
	for i, c := range rec.Cmds {
		before := m.State.String()
		result := m.Step(c)
		steps = append(steps, StepLog{
			Seq:         i,
			InputHex:    hex.EncodeToString(encodeCmd(c)),
			StateBefore: before,
			StateAfter:  m.State.String(),
			Result:      result,
		})
	}
	if rec.Truncated {
		steps = append(steps, StepLog{
			Seq:         len(steps),
			InputHex:    hex.EncodeToString(rec.Tail),
			StateBefore: m.State.String(),
			StateAfter:  m.State.String(),
			Result:      "TRUNCATED_REJECTED",
		})
	}
	return steps
}

func encodeCmd(c Command) []byte {
	out := []byte{byte(c.Op), byte(len(c.Payload))}
	return append(out, c.Payload...)
}

// Signature compresses a step list into a comparable string.
func Signature(steps []StepLog) string {
	sig := ""
	for _, s := range steps {
		sig += fmt.Sprintf("%d:%s>%s=%s;", s.Seq, s.StateBefore, s.StateAfter, s.Result)
	}
	return sig
}
