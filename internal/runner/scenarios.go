package runner

import (
	"bytes"
	"fmt"

	"bombverify/internal/decomp"
)

// Scenario names used across the CLI, the database and the audit log.
const (
	ScenarioOK              = "ok"
	ScenarioMissingFragment = "missing_fragment"
	ScenarioZipBomb         = "zip_bomb"
	ScenarioEmpty           = "empty_input"
	ScenarioOversize        = "oversize_input"
)

// AttackVector describes, per scenario, which bytes of the container carry
// the attack. It is stored verbatim in the evidence record.
var AttackVector = map[string]string{
	ScenarioOK:              "none: well-formed container",
	ScenarioMissingFragment: "block[0].frag_id references fragment id 9, absent from the fragment table",
	ScenarioZipBomb:         "block[0] is a flate stream of 8 MiB zeros, ulen exceeds MaxOutputBytes",
	ScenarioEmpty:           "zero-length input",
	ScenarioOversize:        "input length exceeds Quota.MaxInputBytes",
}

// BuildInput constructs the attack (or reference) input for a scenario.
func BuildInput(scenario string, q decomp.Quota) ([]byte, error) {
	dict := []byte("common-dictionary-fragment-for-bmb1")
	switch scenario {
	case ScenarioOK:
		return decomp.Build(
			[]decomp.Fragment{{ID: 7, Data: dict}},
			[]decomp.BlockSpec{{Codec: 1, Frag: 7, Raw: bytes.Repeat([]byte("hello "), 64)}},
		)
	case ScenarioMissingFragment:
		// The fragment table only carries id 7; block 0 references id 9.
		return decomp.Build(
			[]decomp.Fragment{{ID: 7, Data: dict}},
			[]decomp.BlockSpec{{Codec: 1, Frag: 9, Raw: []byte("payload")}},
		)
	case ScenarioZipBomb:
		return decomp.Build(nil,
			[]decomp.BlockSpec{{Codec: 1, Frag: decomp.NoFragment,
				Raw: make([]byte, 8<<20)}},
		)
	case ScenarioEmpty:
		return nil, nil
	case ScenarioOversize:
		return make([]byte, q.MaxInputBytes+1), nil
	default:
		return nil, fmt.Errorf("unknown scenario %q", scenario)
	}
}

// Scenarios lists every built-in scenario in deterministic order.
func Scenarios() []string {
	return []string{ScenarioOK, ScenarioMissingFragment, ScenarioZipBomb, ScenarioEmpty, ScenarioOversize}
}
