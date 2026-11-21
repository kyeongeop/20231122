package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"sort"

	"auditfix/internal/db"
	"auditfix/internal/model"
)

type compareRow struct {
	SampleIndex int      `json:"sample_index"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Changed     []string `json:"changed_fields"`
	LeftClass   string   `json:"left_classification"`
	RightClass  string   `json:"right_classification"`
}

func (a *App) compareRuns(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("compare", flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	dbPath := flags.String("db", "", "SQLite database path")
	runID := flags.String("run-id", "", "compare first and latest attempts in one run")
	leftID := flags.String("left", "", "left run identifier")
	rightID := flags.String("right", "", "right run identifier")
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	failOnChange := flags.Bool("fail-on-change", false, "return an error if any result changed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := a.requireDB(flags, *dbPath); err != nil {
		return err
	}
	if *runID == "" && (*leftID == "" || *rightID == "") {
		return errors.New("provide --run-id or both --left and --right")
	}
	if *runID != "" && (*leftID != "" || *rightID != "") {
		return errors.New("use either --run-id or --left/--right, not both")
	}
	store, err := db.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	var rows []compareRow
	if *runID != "" {
		rows, err = compareWithinRun(ctx, store, *runID)
	} else {
		rows, err = compareTwoRuns(ctx, store, *leftID, *rightID)
	}
	if err != nil {
		return err
	}
	changed := false
	for _, row := range rows {
		if row.Status != "STABLE" && row.Status != "SINGLE" {
			changed = true
		}
	}
	if *jsonOutput {
		if err := printJSON(a.Stdout, struct {
			Schema  string       `json:"schema"`
			Rows    []compareRow `json:"rows"`
			Changed bool         `json:"changed"`
		}{Schema: "auditfix.compare.v1", Rows: rows, Changed: changed}); err != nil {
			return err
		}
	} else {
		for _, row := range rows {
			fmt.Fprintf(a.Stdout, "%d\t%s\t%s", row.SampleIndex, row.Name, row.Status)
			if len(row.Changed) > 0 {
				fmt.Fprintf(a.Stdout, "\tchanged=%s", joinComma(row.Changed))
			}
			fmt.Fprintf(a.Stdout, "\tleft=%s\tright=%s\n",
				row.LeftClass, row.RightClass)
		}
	}
	if changed && *failOnChange {
		return errors.New("comparison contains changed or missing samples")
	}
	return nil
}

func compareWithinRun(ctx context.Context, store *db.Store, runID string) ([]compareRow, error) {
	run, err := store.GetRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	attempts, err := store.ListAttempts(ctx, runID)
	if err != nil {
		return nil, err
	}
	samples, err := store.ListSamples(ctx, run.CaseID)
	if err != nil {
		return nil, err
	}
	bySample := make(map[string][]model.Attempt)
	for _, attempt := range attempts {
		if isTerminalStatus(attempt.Status) && attempt.ResultJSON != "" {
			bySample[attempt.SampleID] = append(bySample[attempt.SampleID], attempt)
		}
	}
	var rows []compareRow
	for _, sample := range samples {
		list := bySample[sample.SampleID]
		if len(list) == 0 {
			continue
		}
		if len(list) == 1 {
			rows = append(rows, compareRow{
				SampleIndex: sample.SampleIndex,
				Name:        sample.Name,
				Status:      "SINGLE",
				LeftClass:   classificationOf(list[0].ResultJSON),
				RightClass:  classificationOf(list[0].ResultJSON),
			})
			continue
		}
		left, right := list[0], list[len(list)-1]
		changed := evidenceDifferences(left.ResultJSON, right.ResultJSON)
		status := "STABLE"
		if len(changed) > 0 {
			status = "CHANGED"
		}
		rows = append(rows, compareRow{
			SampleIndex: sample.SampleIndex,
			Name:        sample.Name,
			Status:      status,
			Changed:     changed,
			LeftClass:   classificationOf(left.ResultJSON),
			RightClass:  classificationOf(right.ResultJSON),
		})
	}
	return rows, nil
}

func compareTwoRuns(ctx context.Context, store *db.Store, leftID, rightID string) ([]compareRow, error) {
	leftRun, err := store.GetRun(ctx, leftID)
	if err != nil {
		return nil, err
	}
	rightRun, err := store.GetRun(ctx, rightID)
	if err != nil {
		return nil, err
	}
	if leftRun.CaseID != rightRun.CaseID {
		return nil, fmt.Errorf("runs belong to different cases: %s and %s",
			leftRun.CaseID, rightRun.CaseID)
	}
	leftAttempts, err := latestTerminalBySample(ctx, store, leftID)
	if err != nil {
		return nil, err
	}
	rightAttempts, err := latestTerminalBySample(ctx, store, rightID)
	if err != nil {
		return nil, err
	}
	samples, err := store.ListSamples(ctx, leftRun.CaseID)
	if err != nil {
		return nil, err
	}
	var rows []compareRow
	for _, sample := range samples {
		left, hasLeft := leftAttempts[sample.SampleID]
		right, hasRight := rightAttempts[sample.SampleID]
		row := compareRow{SampleIndex: sample.SampleIndex, Name: sample.Name}
		switch {
		case hasLeft && hasRight:
			row.LeftClass = classificationOf(left.ResultJSON)
			row.RightClass = classificationOf(right.ResultJSON)
			row.Changed = evidenceDifferences(left.ResultJSON, right.ResultJSON)
			row.Status = "STABLE"
			if len(row.Changed) > 0 {
				row.Status = "CHANGED"
			}
		case hasLeft:
			row.LeftClass = classificationOf(left.ResultJSON)
			row.Status = "ONLY_LEFT"
			row.Changed = []string{"sample"}
		case hasRight:
			row.RightClass = classificationOf(right.ResultJSON)
			row.Status = "ONLY_RIGHT"
			row.Changed = []string{"sample"}
		default:
			continue
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func latestTerminalBySample(ctx context.Context, store *db.Store, runID string) (map[string]model.Attempt, error) {
	attempts, err := store.ListAttempts(ctx, runID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]model.Attempt)
	for _, attempt := range attempts {
		if isTerminalStatus(attempt.Status) && attempt.ResultJSON != "" {
			out[attempt.SampleID] = attempt
		}
	}
	return out, nil
}

func evidenceDifferences(leftJSON, rightJSON string) []string {
	var left, right map[string]json.RawMessage
	if err := json.Unmarshal([]byte(leftJSON), &left); err != nil {
		return []string{"invalid_left_evidence"}
	}
	if err := json.Unmarshal([]byte(rightJSON), &right); err != nil {
		return []string{"invalid_right_evidence"}
	}
	fields := []string{
		"sample_sha256", "harness_sha256", "verdict", "classification",
		"chain_ok", "anchor_pairs", "clock_offset_ns", "findings",
		"missing_segments", "exit_code", "signal", "timed_out",
	}
	var changed []string
	for _, field := range fields {
		if string(left[field]) != string(right[field]) {
			changed = append(changed, field)
		}
	}
	sort.Strings(changed)
	return changed
}

func isTerminalStatus(status string) bool {
	return status == "complete" || status == "crash" || status == "timeout"
}

func joinComma(values []string) string {
	out := ""
	for i, value := range values {
		if i > 0 {
			out += ","
		}
		out += value
	}
	return out
}
