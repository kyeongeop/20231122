package audit

import "math"

// Principal is the identity whose privilege is evaluated at an anchor hit.
const Principal = "parser:untrusted-input"

// Decision is the result of a permission check.
type Decision struct {
	Granted bool
	Reason  string
}

// JudgePermission models the gate in front of each arithmetic anchor.
// Untrusted input is never granted the privilege of wrapping arithmetic;
// any value pair that would overflow uint32 is denied.
func JudgePermission(anchor string, a, b uint32) Decision {
	switch anchor {
	case "A1:count*9":
		if a != 0 && b > math.MaxUint32/a {
			return Decision{false, "multiply would wrap uint32; untrusted count denied"}
		}
	case "A2:offset+length", "A3:cursor+length":
		if b > math.MaxUint32-a {
			return Decision{false, "addition would wrap uint32; untrusted field denied"}
		}
	}
	return Decision{true, "arithmetic stays within uint32 bounds"}
}
