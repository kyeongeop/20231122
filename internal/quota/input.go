package quota

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"quotabypass/internal/model"
)

var (
	ErrEmptyInput  = errors.New("input is empty")
	ErrOversized   = errors.New("input exceeds size limit")
	ErrMalformed   = errors.New("malformed attack input")
	ErrFragmentGap = errors.New("rejection response fragment is missing")
)

// ParseInput 解析原始攻击输入并生成输入证据。
// 空输入与超大输入不返回 error，而是产出带 parse_error 的证据记录，
// 与参考重建流程保持一致（证据必须保留，不能直接丢弃）。
func ParseInput(raw []byte) (model.AttackInput, model.InputEvidence, error) {
	sum := sha256.Sum256(raw)
	ev := model.InputEvidence{
		SHA256:        hex.EncodeToString(sum[:]),
		DigestScope:   "full_input",
		Bytes:         len(raw),
		Truncated:     false,
		Raw:           string(raw),
		MissingFields: []string{},
	}

	if len(raw) == 0 {
		ev.ParseError = ErrEmptyInput.Error()
		return model.AttackInput{}, ev, ErrEmptyInput
	}
	if len(raw) >= MaxInputBytes {
		// 保留前缀证据：哈希仍覆盖完整输入，raw 字段截断并标记。
		ev.DigestScope = "retained_prefix"
		ev.Truncated = true
		ev.ParseError = ErrOversized.Error()
		return model.AttackInput{}, ev, ErrOversized
	}

	var input model.AttackInput
	if err := json.Unmarshal(raw, &input); err != nil {
		ev.ParseError = fmt.Sprintf("%v: %v", ErrMalformed, err)
		return model.AttackInput{}, ev, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	if input.RejectionResponse.Fragment == "" {
		ev.MissingFields = []string{FragmentField}
		msg := fmt.Sprintf("%v: %s is missing", ErrFragmentGap, FragmentField)
		ev.ParseError = msg
		return input, ev, fmt.Errorf("%w: %s", ErrFragmentGap, FragmentField)
	}
	return input, ev, nil
}

// IsFragmentMissing 判断错误是否由缺失片段引起。
func IsFragmentMissing(err error) bool {
	return errors.Is(err, ErrFragmentGap)
}
