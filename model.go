package main

import "time"

type Case struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Status    string `json:"status"`
	Severity  string `json:"severity"`
	Summary   string `json:"summary"`
	Target    string `json:"target"`
	Toolchain string `json:"toolchain"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

type Evidence struct {
	ID         string `json:"id"`
	CaseID     string `json:"caseId"`
	Label      string `json:"label"`
	Kind       string `json:"kind"`
	SHA256     string `json:"sha256"`
	Size       int    `json:"size"`
	MediaType  string `json:"mediaType"`
	Content    string `json:"content"`
	CapturedAt string `json:"capturedAt"`
	Origin     string `json:"origin"`
	Immutable  bool   `json:"immutable"`
}

type Step struct {
	ID         string   `json:"id"`
	CaseID     string   `json:"caseId"`
	Sequence   int      `json:"sequence"`
	Kind       string   `json:"kind"`
	Title      string   `json:"title"`
	Detail     string   `json:"detail"`
	Status     string   `json:"status"`
	OccurredAt string   `json:"occurredAt"`
	EvidenceID string   `json:"evidenceId,omitempty"`
	Command    string   `json:"command,omitempty"`
	Output     string   `json:"output,omitempty"`
	Refs       []string `json:"refs"`
}

type Finding struct {
	ID          string   `json:"id"`
	CaseID      string   `json:"caseId"`
	Title       string   `json:"title"`
	Detail      string   `json:"detail"`
	Severity    string   `json:"severity"`
	Confidence  int      `json:"confidence"`
	Disposition string   `json:"disposition"`
	Refs        []string `json:"refs"`
	CreatedAt   string   `json:"createdAt"`
}

type Review struct {
	ID        string   `json:"id"`
	CaseID    string   `json:"caseId"`
	Decision  string   `json:"decision"`
	Reviewer  string   `json:"reviewer"`
	Note      string   `json:"note"`
	Refs      []string `json:"refs"`
	CreatedAt string   `json:"createdAt"`
}

type Followup struct {
	ID        string   `json:"id"`
	CaseID    string   `json:"caseId"`
	Title     string   `json:"title"`
	Reason    string   `json:"reason"`
	Commands  []string `json:"commands"`
	Status    string   `json:"status"`
	Owner     string   `json:"owner"`
	CreatedAt string   `json:"createdAt"`
}

type Replay struct {
	ID         string `json:"id"`
	CaseID     string `json:"caseId"`
	Attempt    int    `json:"attempt"`
	Status     string `json:"status"`
	Command    string `json:"command"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	ExitCode   int    `json:"exitCode"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
}

type CaseDetail struct {
	Case       Case       `json:"case"`
	Evidence   []Evidence `json:"evidence"`
	Steps      []Step     `json:"steps"`
	Findings   []Finding  `json:"findings"`
	Reviews    []Review   `json:"reviews"`
	Followups  []Followup `json:"followups"`
	Replays    []Replay   `json:"replays"`
	Revision   int64      `json:"revision"`
	ServerTime string     `json:"serverTime"`
}

type ReplayResult struct {
	Replay        Replay   `json:"replay"`
	Decoded       string   `json:"decoded"`
	LegacyPath    string   `json:"legacyPath"`
	HardenedPath  string   `json:"hardenedPath"`
	Extension     string   `json:"extension"`
	ExtensionSeen string   `json:"extensionSeen"`
	Diverged      bool     `json:"diverged"`
	MatchedInput  bool     `json:"matchedInput"`
	Steps         []string `json:"steps"`
	RecordedAt    string   `json:"recordedAt"`
}

func nowISO() string {
	return time.Now().Format(time.RFC3339)
}
