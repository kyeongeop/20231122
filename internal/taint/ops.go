package taint

import (
	"fmt"
	"math"
)

func applyOperation(value int64, kind string, operand int64, width int) (int64, bool, error) {
	switch kind {
	case "add":
		after := int64(uint64(value) + uint64(operand))
		return after, addOverflow(value, operand), nil
	case "sub":
		after := int64(uint64(value) - uint64(operand))
		return after, subOverflow(value, operand), nil
	case "mul":
		after := int64(uint64(value) * uint64(operand))
		return after, mulOverflow(value, operand, after), nil
	case "div":
		if operand == 0 {
			return value, false, fmt.Errorf("division by zero")
		}
		return value / operand, false, nil
	case "mod":
		if operand == 0 {
			return value, false, fmt.Errorf("modulo by zero")
		}
		return value % operand, false, nil
	case "and":
		return value & operand, false, nil
	case "or":
		return value | operand, false, nil
	case "xor":
		return value ^ operand, false, nil
	case "shl":
		if operand < 0 || operand > 63 {
			return value, false, fmt.Errorf("shift operand %d is outside 0..63", operand)
		}
		return int64(uint64(value) << uint(operand)), false, nil
	case "shr":
		if operand < 0 || operand > 63 {
			return value, false, fmt.Errorf("shift operand %d is outside 0..63", operand)
		}
		return int64(uint64(value) >> uint(operand)), false, nil
	case "neg":
		return int64(-uint64(value)), value == math.MinInt64, nil
	case "not":
		return ^value, false, nil
	case "trunc":
		after, err := truncateSigned(value, width)
		return after, false, err
	default:
		return value, false, fmt.Errorf("unknown operation")
	}
}

func truncateSigned(value int64, width int) (int64, error) {
	var bits uint
	switch width {
	case 8, 16, 32, 64:
		bits = uint(width)
	default:
		return value, fmt.Errorf("width_bits %d is not one of 8, 16, 32, 64", width)
	}
	if bits == 64 {
		return value, nil
	}
	mask := uint64(1)<<bits - 1
	unsigned := uint64(value) & mask
	if unsigned&(uint64(1)<<(bits-1)) != 0 {
		unsigned |= ^mask
	}
	return int64(unsigned), nil
}

func addOverflow(a, b int64) bool {
	return (b > 0 && a > math.MaxInt64-b) || (b < 0 && a < math.MinInt64-b)
}

func subOverflow(a, b int64) bool {
	return (b < 0 && a > math.MaxInt64+b) || (b > 0 && a < math.MinInt64+b)
}

func mulOverflow(a, b, result int64) bool {
	if a == 0 || b == 0 {
		return false
	}
	if a == math.MinInt64 && b == -1 || b == math.MinInt64 && a == -1 {
		return true
	}
	return result/b != a
}
