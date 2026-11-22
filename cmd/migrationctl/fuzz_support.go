package main

import (
	"example.com/migration-review/internal/fuzzcheck"
	"example.com/migration-review/internal/model"
	"example.com/migration-review/internal/policy"
)

func parseFuzzManifest(data []byte) (*model.Manifest, error) {
	return fuzzcheck.Parse(data)
}

func policyOptionsForFuzz() policy.Options {
	return fuzzcheck.Options()
}
