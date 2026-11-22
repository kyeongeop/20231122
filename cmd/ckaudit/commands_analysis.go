package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"ckaudit/internal/store"
)

func cmdBoundary(workDir string, args []string) error {
	runID, err := resolveRunID(workDir, args)
	if err != nil {
		return err
	}
	st, err := openStore(workDir)
	if err != nil {
		return err
	}
	defer st.Close()
	samples, err := st.AllSamples(runID)
	if err != nil {
		return err
	}

	byBoundary := map[string][]store.Sample{}
	var order []string
	for _, smp := range samples {
		if smp.Scenario != "extreme-boundary" {
			continue
		}
		if _, ok := byBoundary[smp.Boundary]; !ok {
			order = append(order, smp.Boundary)
		}
		byBoundary[smp.Boundary] = append(byBoundary[smp.Boundary], smp)
	}

	for _, boundary := range order {
		pair := byBoundary[boundary]
		fmt.Printf("boundary: %s\n", boundary)
		for _, smp := range pair {
			findings, _ := st.Findings(smp.ID)
			codes := make([]string, 0, len(findings))
			for _, f := range findings {
				codes = append(codes, f.Severity+":"+f.Code)
			}
			if len(codes) == 0 {
				codes = []string{"(clean)"}
			}
			fmt.Printf("  %-5s param=%-12s status=%-7s len=%-5d findings=%s\n",
				smp.Side, smp.ParamValue, smp.Status, len(smp.Input),
				joinCodes(codes))
		}
	}
	return nil
}

func joinCodes(codes []string) string {
	out := ""
	for i, c := range codes {
		if i > 0 {
			out += ","
		}
		out += c
	}
	return out
}

func cmdCompare(workDir string, args []string) error {
	runID, err := resolveRunID(workDir, args)
	if err != nil {
		return err
	}
	keyA := flagValue(args, "--a", "")
	keyB := flagValue(args, "--b", "")
	if keyA == "" || keyB == "" {
		return fmt.Errorf("--a and --b are required")
	}
	st, err := openStore(workDir)
	if err != nil {
		return err
	}
	defer st.Close()

	a, err := st.SampleByKey(runID, keyA)
	if err != nil {
		return err
	}
	b, err := st.SampleByKey(runID, keyB)
	if err != nil {
		return err
	}
	fa, _ := st.Findings(a.ID)
	fb, _ := st.Findings(b.ID)

	fmt.Printf("A: %s (status=%s, len=%d)\nB: %s (status=%s, len=%d)\n",
		a.SampleKey, a.Status, len(a.Input), b.SampleKey, b.Status, len(b.Input))
	fmt.Printf("length delta: %d bytes\n", len(b.Input)-len(a.Input))

	setA := findingSet(fa)
	setB := findingSet(fb)
	var added, removed, common []string
	for code := range setB {
		if setA[code] {
			common = append(common, code)
		} else {
			added = append(added, code)
		}
	}
	for code := range setA {
		if !setB[code] {
			removed = append(removed, code)
		}
	}
	fmt.Printf("common findings (%d): %v\n", len(common), common)
	fmt.Printf("added in B     (%d): %v\n", len(added), added)
	fmt.Printf("removed in B   (%d): %v\n", len(removed), removed)
	return nil
}

func findingSet(fs []store.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range fs {
		out[f.Severity+":"+f.Code] = true
	}
	return out
}

type exportSample struct {
	Key      string           `json:"key"`
	Scenario string           `json:"scenario"`
	Boundary string           `json:"boundary,omitempty"`
	Side     string           `json:"side,omitempty"`
	Param    string           `json:"param,omitempty"`
	Status   string           `json:"status"`
	Attempts int              `json:"attempts"`
	Input    string           `json:"input"`
	Findings []store.Finding  `json:"findings"`
	Evidence []store.Evidence `json:"evidence,omitempty"`
}

func cmdExport(workDir string, args []string) error {
	runID, err := resolveRunID(workDir, args)
	if err != nil {
		return err
	}
	outPath := flagValue(args, "--out", "")
	if outPath == "" {
		return fmt.Errorf("--out is required")
	}
	format := flagValue(args, "--format", "json")
	evDir := flagValue(args, "--evidence", "")

	st, err := openStore(workDir)
	if err != nil {
		return err
	}
	defer st.Close()
	samples, err := st.AllSamples(runID)
	if err != nil {
		return err
	}

	rows := make([]exportSample, 0, len(samples))
	for _, smp := range samples {
		findings, _ := st.Findings(smp.ID)
		evidence, _ := st.Evidence(smp.ID)
		rows = append(rows, exportSample{
			Key: smp.SampleKey, Scenario: smp.Scenario, Boundary: smp.Boundary,
			Side: smp.Side, Param: smp.ParamValue, Status: smp.Status,
			Attempts: smp.Attempts, Input: smp.Input,
			Findings: findings, Evidence: evidence,
		})
	}

	if evDir != "" {
		if err := copyEvidenceTree(workDir, evDir, samples, st); err != nil {
			return err
		}
	}

	switch format {
	case "json":
		data, err := json.MarshalIndent(rows, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(outPath, append(data, '\n'), 0o644)
	case "csv":
		return writeCSV(outPath, rows)
	default:
		return fmt.Errorf("unsupported format %q (json|csv)", format)
	}
}

func writeCSV(outPath string, rows []exportSample) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"key", "scenario", "boundary", "side", "param",
		"status", "attempts", "input_len", "findings"}); err != nil {
		return err
	}
	for _, r := range rows {
		codes := make([]string, 0, len(r.Findings))
		for _, fd := range r.Findings {
			codes = append(codes, fd.Severity+":"+fd.Code)
		}
		if err := w.Write([]string{r.Key, r.Scenario, r.Boundary, r.Side,
			r.Param, r.Status, fmt.Sprintf("%d", r.Attempts),
			fmt.Sprintf("%d", len(r.Input)), joinCodes(codes)}); err != nil {
			return err
		}
	}
	return nil
}

func copyEvidenceTree(workDir, dest string, samples []store.Sample, st *store.Store) error {
	for _, smp := range samples {
		evidence, err := st.Evidence(smp.ID)
		if err != nil {
			return err
		}
		for _, ev := range evidence {
			rel, err := filepath.Rel(workDir, ev.Path)
			if err != nil {
				return err
			}
			target := filepath.Join(dest, rel)
			data, err := os.ReadFile(ev.Path)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(target, data, 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}
