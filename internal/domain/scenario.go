package domain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const ScenarioSchemaVersion = 1

type Device struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
}

type Replica struct {
	Name        string `json:"name"`
	DeviceID    string `json:"device_id"`
	Revision    uint32 `json:"revision"`
	UpdatedAtMS int64  `json:"updated_at_ms"`
	ACL         byte   `json:"acl"`
	Deleted     bool   `json:"deleted"`
}

type DuplicateObject struct {
	Key         string     `json:"key"`
	CanonicalID string     `json:"canonical_id"`
	Replicas    [2]Replica `json:"replicas"`
}

type Scenario struct {
	SchemaVersion int             `json:"schema_version"`
	Object        DuplicateObject `json:"object"`
	Devices       [2]Device       `json:"devices"`
}

func DefaultScenario() Scenario {
	return Scenario{
		SchemaVersion: ScenarioSchemaVersion,
		Object: DuplicateObject{
			Key:         "invoice:dup-42",
			CanonicalID: "obj_01J8DUP42",
			Replicas: [2]Replica{
				{
					Name:        "replica-a",
					DeviceID:    "device-a",
					Revision:    7,
					UpdatedAtMS: 1_700_000_003_000,
					ACL:         PermRead | PermUpdate | PermDelete,
					Deleted:     false,
				},
				{
					Name:        "replica-b",
					DeviceID:    "device-b",
					Revision:    5,
					UpdatedAtMS: 1_700_000_003_000,
					ACL:         PermRead | PermUpdate | PermDelete,
					Deleted:     true,
				},
			},
		},
		Devices: [2]Device{
			{ID: "device-a", Name: "Device A", Role: "primary"},
			{ID: "device-b", Name: "Device B", Role: "offline-replica"},
		},
	}
}

func (s Scenario) Validate() error {
	if s.SchemaVersion != ScenarioSchemaVersion {
		return fmt.Errorf("scenario schema_version must be %d", ScenarioSchemaVersion)
	}
	if s.Object.Key == "" || s.Object.CanonicalID == "" {
		return errors.New("object key and canonical_id are required")
	}
	if s.Devices[0].ID == "" || s.Devices[1].ID == "" {
		return errors.New("both device ids are required")
	}
	if s.Devices[0].ID == s.Devices[1].ID {
		return errors.New("device ids must be distinct")
	}
	for i, replica := range s.Object.Replicas {
		if replica.Name == "" {
			return fmt.Errorf("replica %d name is required", i)
		}
		if replica.DeviceID != s.Devices[0].ID && replica.DeviceID != s.Devices[1].ID {
			return fmt.Errorf("replica %q references unknown device %q", replica.Name, replica.DeviceID)
		}
		if replica.ACL&^(PermRead|PermUpdate|PermDelete) != 0 {
			return fmt.Errorf("replica %q acl has unknown bits", replica.Name)
		}
	}
	if s.Object.Replicas[0].DeviceID == s.Object.Replicas[1].DeviceID {
		return errors.New("duplicate replicas must belong to different devices")
	}
	return nil
}

func DecodeScenario(r io.Reader) (Scenario, error) {
	var scenario Scenario
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&scenario); err != nil {
		return Scenario{}, err
	}
	if decoder.More() {
		return Scenario{}, errors.New("scenario contains multiple JSON values")
	}
	if err := scenario.Validate(); err != nil {
		return Scenario{}, err
	}
	return scenario, nil
}

func LoadScenario(path string) (Scenario, error) {
	file, err := os.Open(path)
	if err != nil {
		return Scenario{}, err
	}
	defer file.Close()
	return DecodeScenario(file)
}

func (s Scenario) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func (s Scenario) CanonicalJSON() ([]byte, error) {
	return json.Marshal(s)
}

func (s Scenario) Hash() (string, error) {
	data, err := s.CanonicalJSON()
	if err != nil {
		return "", err
	}
	return SHA256Hex(data), nil
}

func DecodeScenarioJSON(data []byte) (Scenario, error) {
	return DecodeScenario(bytes.NewReader(data))
}
