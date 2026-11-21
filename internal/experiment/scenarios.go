package experiment

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"pathaliaslab/internal/model"
)

//go:embed scenarios.json
var scenarioSource []byte

type Expectation struct {
	ConflictSteps      []int  `json:"conflict_steps"`
	CancelSteps        []int  `json:"cancel_steps"`
	DuplicateNoopSteps []int  `json:"duplicate_noop_steps"`
	FinalAlias         string `json:"final_alias"`
	FinalTarget        string `json:"final_target"`
	ConflictFree       bool   `json:"conflict_free"`
}

type Scenario struct {
	Name         string      `json:"name"`
	Role         string      `json:"role"`
	Description  string      `json:"description"`
	CancelAtStep int         `json:"cancel_at_step"`
	Steps        []model.Op  `json:"steps"`
	Expect       Expectation `json:"expect"`
}

func Scenarios() ([]Scenario, error) {
	var scenarios []Scenario
	if err := json.Unmarshal(scenarioSource, &scenarios); err != nil {
		return nil, fmt.Errorf("decode embedded scenarios: %w", err)
	}
	return scenarios, nil
}

func ScenarioSource() []byte {
	return append([]byte(nil), scenarioSource...)
}

func ScenarioJSON(scenario Scenario) ([]byte, error) {
	return json.MarshalIndent(scenario, "", "  ")
}

func DecodeScenario(data []byte) (Scenario, error) {
	var scenario Scenario
	if err := json.Unmarshal(data, &scenario); err != nil {
		return Scenario{}, fmt.Errorf("decode stored scenario: %w", err)
	}
	return scenario, nil
}
