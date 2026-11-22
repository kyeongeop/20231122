package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"serrfix/internal/model"
	"serrfix/internal/redact"
	"serrfix/internal/store"
)

const SchemaEvidence = "serrfix.evidence/v1"

type LocalizedEdit struct {
	UnchangedPrefixBytes int `json:"unchanged_prefix_bytes"`
	UnchangedSuffixBytes int `json:"unchanged_suffix_bytes"`
	ModifiedBytes        int `json:"modified_bytes"`
	InsertedBytes        int `json:"inserted_bytes"`
}

type Evidence struct {
	Schema         string          `json:"schema"`
	Phase          string          `json:"phase"`
	CreatedAt      string          `json:"created_at"`
	Run            model.RunResult `json:"run"`
	Material       store.Material  `json:"material"`
	MaterialPath   string          `json:"material_path"`
	SampleOffset   int64           `json:"sample_offset"`
	SampleLength   int64           `json:"sample_length"`
	SampleSHA256   string          `json:"sample_sha256"`
	RedactedBase64 string          `json:"redacted_base64"`
	LocalizedEdit  LocalizedEdit   `json:"localized_edit"`
}

type RequestEvidence struct {
	Schema       string       `json:"schema"`
	Phase        string       `json:"phase"`
	CreatedAt    string       `json:"created_at"`
	RunID        string       `json:"run_id"`
	SampleID     string       `json:"sample_id"`
	Attempt      int          `json:"attempt"`
	Repetition   int          `json:"repetition"`
	StartedAt    string       `json:"started_at"`
	MaterialID   string       `json:"material_id"`
	MaterialSHA  string       `json:"material_sha256"`
	SampleOffset int64        `json:"sample_offset"`
	SampleLength int64        `json:"sample_length"`
	SampleSHA256 string       `json:"sample_sha256"`
	Params       model.Params `json:"params"`
}

func (a *App) writeRequest(path string, r model.Run, sample model.Sample, material store.Material) (string, error) {
	ev := RequestEvidence{
		Schema: SchemaEvidence, Phase: "requested", CreatedAt: model.Timestamp(r.StartedAt),
		RunID: r.ID, SampleID: sample.ID, Attempt: r.Attempt, Repetition: r.Repetition,
		StartedAt: model.Timestamp(r.StartedAt), MaterialID: material.ID,
		MaterialSHA: material.SHA256, SampleOffset: sample.Offset,
		SampleLength: sample.Length, SampleSHA256: sample.SHA256,
	}
	if err := json.Unmarshal([]byte(sample.ParamsJSON), &ev.Params); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	if err := a.atomicWrite(path, data, 0o444); err != nil {
		return "", err
	}
	return model.SHA256(data), nil
}

func buildEvidence(sample model.Sample, material store.Material, run model.Run,
	result redact.Result, materialPath string) Evidence {
	edit := LocalizedEdit{}
	if len(result.Spans) == 0 {
		edit.UnchangedPrefixBytes = len(result.Original)
	} else {
		first := result.Spans[0]
		last := result.Spans[len(result.Spans)-1]
		edit.UnchangedPrefixBytes = first.SourceOffset
		edit.UnchangedSuffixBytes = len(result.Original) - (last.SourceOffset + last.SourceLength)
		for _, span := range result.Spans {
			edit.ModifiedBytes += span.SourceLength
			edit.InsertedBytes += len(span.Replacement)
		}
	}
	runResult := model.RunResult{
		Schema: model.SchemaRun, SampleID: sample.ID, RunID: run.ID,
		Attempt: run.Attempt, Repetition: run.Repetition, State: run.State,
		StartedAt: model.Timestamp(run.StartedAt), FinishedAt: model.Timestamp(run.FinishedAt),
		DurationNS: run.DurationNS,
		Source: model.SourceRef{
			MaterialID: material.ID, Offset: sample.Offset,
			Length: sample.Length, SHA256: sample.SHA256,
		},
		BeforeLeaks: run.BeforeLeaks, AfterLeaks: run.AfterLeaks,
		Spans: result.Spans, RedactedSHA256: model.SHA256(result.Redacted),
		OriginalSHA256:  sample.SHA256,
		RedactedPreview: redact.Preview(result.Redacted, 600),
		EvidenceNote:    "byte offsets are zero-based within the sample; line and column are one-based; columns count bytes",
		Error:           run.Error,
	}
	if err := json.Unmarshal([]byte(sample.ParamsJSON), &runResult.Params); err != nil {
		runResult.Params = model.DefaultParams(sample.Label)
	}
	return Evidence{
		Schema: SchemaEvidence, Phase: "result",
		CreatedAt: model.Timestamp(run.FinishedAt), Run: runResult,
		Material: material, MaterialPath: materialPath,
		SampleOffset: sample.Offset, SampleLength: sample.Length,
		SampleSHA256:   sample.SHA256,
		RedactedBase64: base64.StdEncoding.EncodeToString(result.Redacted),
		LocalizedEdit:  edit,
	}
}

func (a *App) writeEvidence(path string, ev Evidence) (string, error) {
	data, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	if err := a.atomicWrite(path, data, 0o444); err != nil {
		return "", err
	}
	return model.SHA256(data), nil
}

func readEvidence(path string) (Evidence, error) {
	var ev Evidence
	data, err := os.ReadFile(path)
	if err != nil {
		return ev, err
	}
	if err := json.Unmarshal(data, &ev); err != nil {
		return ev, fmt.Errorf("decode evidence: %w", err)
	}
	return ev, nil
}
