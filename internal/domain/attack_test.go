package domain

import (
	"errors"
	"testing"
)

func TestAttackCodecRoundTrip(t *testing.T) {
	input := MustEncodeAttack(Attack{
		ActorRole:     RoleEditor,
		Action:        ActionUpdate,
		TenantMatch:   true,
		RequestDevice: "device-b",
		SkewAMS:       -1250,
		SkewBMS:       4500,
	})
	if len(input) != SampleSize {
		t.Fatalf("sample size = %d, want %d", len(input), SampleSize)
	}
	decoded, err := DecodeAttack(input)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != (Attack{
		ActorRole:     RoleEditor,
		Action:        ActionUpdate,
		TenantMatch:   true,
		RequestDevice: "device-b",
		SkewAMS:       -1250,
		SkewBMS:       4500,
	}) {
		t.Fatalf("decoded attack = %#v", decoded)
	}
}

func TestAttackCodecRejectsInvalidSamples(t *testing.T) {
	valid := MustEncodeAttack(Attack{
		ActorRole:   RoleEditor,
		TenantMatch: true,
	})
	cases := map[string][]byte{
		"short":       valid[:SampleSize-1],
		"magic":       append([]byte("NOPE"), valid[4:]...),
		"version":     append([]byte{}, valid...),
		"actor role":  append([]byte{}, valid...),
		"action code": append([]byte{}, valid...),
	}
	cases["version"][4] = 9
	cases["actor role"][5] = 9
	cases["action code"][6] = 9
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeAttack(input)
			if !errors.Is(err, ErrInvalidSample) {
				t.Fatalf("error = %v, want ErrInvalidSample", err)
			}
		})
	}
}
