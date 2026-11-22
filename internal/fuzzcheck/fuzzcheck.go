package fuzzcheck

import (
	"example.com/migration-review/internal/manifest"
	"example.com/migration-review/internal/model"
	"example.com/migration-review/internal/policy"
)

const maxInputBytes = 4 << 20

func Parse(data []byte) (*model.Manifest, error) {
	if len(data) > maxInputBytes {
		return nil, errTooLarge
	}
	return manifest.Parse(data, "libfuzzer-input")
}

func Options() policy.Options {
	return policy.Options{
		AllowDestructive: false,
		AllowAttach:      false,
		AllowAdmin:       false,
	}
}

func Evaluate(data []byte, engine *policy.Engine) (*model.Manifest, model.PermissionDecision, error) {
	m, err := Parse(data)
	if err != nil {
		return nil, model.PermissionDecision{}, err
	}
	return m, engine.Authorize(m, Options()), nil
}

var errTooLarge = &sizeError{}

type sizeError struct{}

func (*sizeError) Error() string { return "input exceeds fuzz size limit" }
