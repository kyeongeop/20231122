package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kyeongeop/20231122/internal/evidence"
	"github.com/kyeongeop/20231122/internal/scenario"
	"github.com/kyeongeop/20231122/internal/smuggle"
	"github.com/kyeongeop/20231122/internal/store"
)

type logFunc func(level, layer, msg string)

// processScenario runs one input through the pipeline and persists every
// artifact: input evidence, parse results per layer, smuggled requests,
// permission decisions, boundary samples and log lines.
func processScenario(st *store.Store, runID int64, sc scenario.Scenario,
	evidenceDir, corpusDir string, logf logFunc) error {

	input := sc.Build()
	opts := scenario.OptionsFor(sc)

	// Preserve the attack input itself as evidence (hash + bounded snippet;
	// oversized inputs also get a full on-disk copy).
	if err := st.Evidence(runID, sc.Name, "input", evidence.Hash(input), len(input),
		evidence.Snippet(input, 128)); err != nil {
		return err
	}
	if sc.Kind == "oversize" {
		p, err := evidence.SaveFile(evidenceDir, sc.Name, input)
		if err != nil {
			return err
		}
		logf("WARN", "frontend", fmt.Sprintf("oversize input preserved at %s (%d bytes)", p, len(input)))
	}
	if corpusDir != "" && len(input) <= 1<<20 {
		if err := os.MkdirAll(corpusDir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(corpusDir, sc.Name+".http"), input, 0o644); err != nil {
			return err
		}
	}

	a := smuggle.Analyze(sc.Name, input, opts, sc.Frontend, sc.Backend)
	logf("INFO", "frontend", fmt.Sprintf("case=%s input=%d bytes sha256=%s",
		sc.Name, a.InputSize, a.InputHash[:16]))

	findings := append(append([]smuggle.Finding{}, a.Frontend...), a.Backend...)
	for _, f := range findings {
		if err := st.ParseResult(runID, sc.Name, f.Layer, f.Profile, f.Index,
			f.Status, f.Method, f.Path, f.Consumed, f.Detail); err != nil {
			return err
		}
		if f.Status != "ok" && f.Status != "empty" {
			logf("WARN", f.Layer, fmt.Sprintf("case=%s trigger=%s idx=%d detail=%s",
				sc.Name, f.Status, f.Index, f.Detail))
		}
	}

	for _, sm := range a.Smuggled {
		p, err := evidence.SaveFile(evidenceDir, sc.Name+"-smuggled", sm.Raw)
		if err != nil {
			return err
		}
		if err := st.Smuggled(runID, sc.Name, sm.Method, sm.Path, sm.SHA256, p); err != nil {
			return err
		}
		logf("ALERT", "backend", fmt.Sprintf("case=%s smuggled: %s %s sha256=%s evidence=%s",
			sc.Name, sm.Method, sm.Path, sm.SHA256[:16], p))
	}

	for _, d := range a.Decisions {
		decision := "allow"
		if !d.Allowed {
			decision = "deny"
		}
		if err := st.Permission(runID, sc.Name, d.Path, d.Identity.Name, decision, d.Reason); err != nil {
			return err
		}
		logf("INFO", "backend", fmt.Sprintf("case=%s permission: path=%s identity=%s decision=%s reason=%q",
			sc.Name, d.Path, d.Identity.Name, decision, d.Reason))
	}

	if sc.Kind == "boundary-before" || sc.Kind == "boundary-after" {
		side := "before"
		if sc.Kind == "boundary-after" {
			side = "after"
		}
		status, detail := boundaryStatus(a)
		if err := st.Boundary(runID, scenario.BoundaryParameter, scenario.BoundaryLimit,
			side, a.InputSize, status, detail); err != nil {
			return err
		}
		logf("INFO", "frontend", fmt.Sprintf("case=%s boundary: parameter=%s limit=%d side=%s status=%s",
			sc.Name, scenario.BoundaryParameter, scenario.BoundaryLimit, side, status))
	}

	if a.Desync {
		logf("ALERT", "analysis", fmt.Sprintf("case=%s desync confirmed: frontend=%d backend=%d smuggled=%d",
			sc.Name, a.Reuse.FrontendServed, a.Reuse.BackendServed, len(a.Smuggled)))
	}
	return nil
}

// boundaryStatus summarizes how the boundary sample was handled.
func boundaryStatus(a *smuggle.Analysis) (status, detail string) {
	for _, f := range a.Frontend {
		if f.Status == "ok" {
			return "accepted", fmt.Sprintf("parsed %s %s within limit", f.Method, f.Path)
		}
		if f.Status == "rejected" {
			return "rejected", f.Detail
		}
	}
	return "unknown", "no frontend parse result"
}
