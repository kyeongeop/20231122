package exchange

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"idorfix/internal/domain"
)

func renderReview(sample *domain.Sample, run *domain.Run, verdict *domain.Verdict, orderedEvents []domain.EvidenceEvent) []byte {
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "# IDOR Review Sheet\n\n")
	fmt.Fprintf(&buffer, "- Sample ID: `%s`\n", sample.SampleID)
	fmt.Fprintf(&buffer, "- Title: %s\n", sample.Title)
	fmt.Fprintf(&buffer, "- Attack class: %s\n", sample.AttackClass)
	fmt.Fprintf(&buffer, "- Run ID: `%s` (attempt %d)\n", run.RunID, run.Attempt)
	fmt.Fprintf(&buffer, "- Rule version: `%s`\n", verdict.RuleVersion)
	fmt.Fprintf(&buffer, "- Outcome: **%s**\n", verdict.Outcome)
	fmt.Fprintf(&buffer, "- Input SHA-256: `%s`\n", sample.InputSHA256)
	if run.FinishedAt != nil {
		fmt.Fprintf(&buffer, "- Finished at: %s\n", run.FinishedAt.UTC().Format(time.RFC3339Nano))
	}

	fmt.Fprintf(&buffer, "\n## Missing fragments (clock desync)\n\n")
	if len(verdict.MissingFragments) == 0 {
		buffer.WriteString("None. Cross-device event ordering is fully resolvable.\n")
	} else {
		buffer.WriteString("| Fragment | Start (ns) | End (ns) | Anchor event | Reason |\n")
		buffer.WriteString("|---|---:|---:|---|---|\n")
		for _, fragment := range verdict.MissingFragments {
			fmt.Fprintf(&buffer, "| %s | %d | %d | %s | %s |\n",
				fragment.FragmentID, fragment.StartNS, fragment.EndNS,
				fragment.AnchorEventID, fragment.Reason)
		}
	}

	fmt.Fprintf(&buffer, "\n## Findings\n\n")
	if len(verdict.Findings) == 0 {
		buffer.WriteString("No rule findings.\n")
	} else {
		buffer.WriteString("| Rule | Severity | Event | Message |\n")
		buffer.WriteString("|---|---|---|---|\n")
		for _, finding := range verdict.Findings {
			fmt.Fprintf(&buffer, "| %s | %s | %s | %s |\n",
				finding.RuleID, finding.Severity, finding.EventID, finding.Message)
		}
	}

	fmt.Fprintf(&buffer, "\n## Evidence chain (ordered)\n\n")
	buffer.WriteString("| Seq | Event | Device | Adjusted (ns) | Actor tenant | Requested tenant | Decision |\n")
	buffer.WriteString("|---:|---|---|---:|---|---|---|\n")
	for _, event := range orderedEvents {
		fmt.Fprintf(&buffer, "| %d | %s | %s | %d | %s | %s | %s |\n",
			event.Seq, event.EventID, event.DeviceID, event.AdjustedNS,
			event.Actor.TenantID, event.Actor.RequestedTenant, event.Decision)
	}

	buffer.WriteString("\n## Reviewer checklist\n\n")
	buffer.WriteString("- [ ] Re-run `idorfix replay` and confirm the outcome matches.\n")
	buffer.WriteString("- [ ] Verify every checksum in `manifest.json`.\n")
	buffer.WriteString("- [ ] Inspect each missing fragment against the raw evidence.\n")
	buffer.WriteString("- [ ] Confirm tenant boundaries and resource ownership manually.\n")
	return buffer.Bytes()
}

// LoadSampleFile parses a sample file while enforcing canonical field order.
func LoadSampleFile(raw []byte) (*domain.Sample, error) {
	if err := AssertFieldOrder(raw, domain.Sample{}); err != nil {
		return nil, fmt.Errorf("sample field-order contract: %w", err)
	}
	var sample domain.Sample
	if err := json.Unmarshal(raw, &sample); err != nil {
		return nil, fmt.Errorf("parse sample: %w", err)
	}
	if sample.SchemaVersion != domain.SchemaVersion {
		return nil, fmt.Errorf("unsupported schema version %d (want %d)",
			sample.SchemaVersion, domain.SchemaVersion)
	}
	return &sample, nil
}
