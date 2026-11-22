package scenario

import "github.com/kyeongeop/20231122/internal/smuggle"

// BoundaryParameter names the extreme limit exercised by the boundary pair.
const BoundaryParameter = "MaxBodyBytes"

// BoundaryLimit is the extreme body-size limit used by the boundary pair:
// BOUNDARY-BEFORE carries exactly this many body bytes, BOUNDARY-AFTER two more.
const BoundaryLimit = 4

// OptionsFor returns the extreme parameter set for one scenario. Boundary
// scenarios tighten MaxBodyBytes to BoundaryLimit so the pair straddles it.
func OptionsFor(s Scenario) smuggle.Options {
	opts := smuggle.DefaultOptions()
	opts.Limits.MaxBodyBytes = 1024
	if s.Kind == "boundary-before" || s.Kind == "boundary-after" {
		opts.Limits.MaxBodyBytes = BoundaryLimit
	}
	return opts
}
