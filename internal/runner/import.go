package runner

import (
	"context"
	"encoding/json"
	"fmt"

	"idorfix/internal/domain"
	"idorfix/internal/exchange"
	"idorfix/internal/store"
)

// ImportResult reports what happened when a sample file was ingested.
type ImportResult struct {
	Sample  domain.Sample
	Skipped bool
	Reason  string
}

// ImportSample validates, hashes and stores one sample. Re-importing the same
// content is idempotent: the existing row is returned and nothing is written.
func ImportSample(ctx context.Context, workspace *store.Store, raw []byte) (*ImportResult, error) {
	sample, err := exchange.LoadSampleFile(raw)
	if err != nil {
		return nil, err
	}
	if sample.SampleID == "" {
		return nil, fmt.Errorf("sample_id is required")
	}

	canonical, err := exchange.CanonicalJSON(sample)
	if err != nil {
		return nil, err
	}

	// Keep the caller-supplied created_at so the digest is reproducible on a
	// colleague's machine after export and reload.
	canonical, err = exchange.CanonicalJSON(sample)
	if err != nil {
		return nil, err
	}
	// ContentHash is computed over the sample with its hash field still empty,
	// so it can be verified byte-for-byte after any round trip.
	contentHash := exchange.SHA256Hex(canonical)
	// Blank the field while doing identity comparisons; only the eventually
	// persisted row carries the recorded digest.
	incomingForCompare := *sample
	incomingForCompare.InputSHA256 = ""
	sample.InputSHA256 = contentHash

	exists, err := workspace.SampleExists(ctx, sample.SampleID)
	if err != nil {
		return nil, err
	}
	if exists {
		stored, err := workspace.SamplePayload(ctx, sample.SampleID)
		if err != nil {
			return nil, err
		}
		var storedSample domain.Sample
		if err := json.Unmarshal([]byte(stored), &storedSample); err != nil {
			return nil, err
		}
		storedSample.InputSHA256 = ""
		storedCanonical, err := exchange.CanonicalJSON(storedSample)
		if err != nil {
			return nil, err
		}
		incomingCanonical, err := exchange.CanonicalJSON(incomingForCompare)
		if err != nil {
			return nil, err
		}
		if string(storedCanonical) == string(incomingCanonical) {
			return &ImportResult{Sample: *sample, Skipped: true, Reason: "identical sample already imported"}, nil
		}
		return nil, fmt.Errorf("sample_id %q already exists with different content", sample.SampleID)
	}

	seq, err := workspace.NextSampleSeq(ctx)
	if err != nil {
		return nil, err
	}
	persistedPayload, err := exchange.CanonicalJSON(sample)
	if err != nil {
		return nil, err
	}
	if err := workspace.InsertSample(ctx, sample, string(persistedPayload), seq); err != nil {
		return nil, err
	}
	return &ImportResult{Sample: *sample}, nil
}
