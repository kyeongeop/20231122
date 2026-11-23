package detect

import (
	"fmt"
	"sort"

	"idorfix/internal/domain"
)

const (
	severityHigh   = "HIGH"
	severityMedium = "MEDIUM"
	severityLow    = "LOW"
)

// Analyse is deterministic: the same sample and rule version always produce
// the same verdict, findings, fragment set and evidence ordering.
func Analyse(sample *domain.Sample) (domain.Verdict, error) {
	events, fragments, err := NormalizeClocks(sample)
	if err != nil {
		return domain.Verdict{}, err
	}

	var findings []domain.Finding
	evidenceIDs := make([]string, 0, len(events))
	eventsInsideGap := 0

	for _, event := range events {
		evidenceIDs = append(evidenceIDs, event.EventID)
		fragmentID, inGap := InsideFragment(fragments, event.AdjustedNS)
		if inGap {
			eventsInsideGap++
			findings = append(findings, domain.Finding{
				RuleID:   "GAP-001",
				Severity: severityLow,
				EventSeq: event.Seq,
				EventID:  event.EventID,
				Message: fmt.Sprintf(
					"event lies inside missing fragment %s; cross-device ordering not provable",
					fragmentID),
			})
		}

		actor := event.Actor
		switch {
		case actor.RequestedTenant != "" && actor.RequestedTenant != actor.TenantID:
			findings = append(findings, domain.Finding{
				RuleID:   "IDOR-T1",
				Severity: severityHigh,
				EventSeq: event.Seq,
				EventID:  event.EventID,
				Message: fmt.Sprintf(
					"user %s of tenant %s requested resource %s in foreign tenant %s",
					actor.UserID, actor.TenantID, actor.ResourceID, actor.RequestedTenant),
			})
		case actor.ResourceID != "" && actor.RequestedTenant == actor.TenantID && event.Decision == "ALLOW" && isOtherUserResource(event):
			findings = append(findings, domain.Finding{
				RuleID:   "IDOR-H1",
				Severity: severityMedium,
				EventSeq: event.Seq,
				EventID:  event.EventID,
				Message: fmt.Sprintf(
					"user %s accessed resource %s owned by another user in the same tenant",
					actor.UserID, actor.ResourceID),
			})
		}

		if actor.Role != "admin" && actor.RequestedTenant != "" && actor.RequestedTenant != actor.TenantID && actor.ResourceID != "" {
			findings = append(findings, domain.Finding{
				RuleID:   "IDOR-V1",
				Severity: severityHigh,
				EventSeq: event.Seq,
				EventID:  event.EventID,
				Message: fmt.Sprintf(
					"non-admin role %q attempted cross-tenant access; privilege boundary crossed",
					actor.Role),
			})
		}
	}

	outcome := decideOutcome(findings, events, eventsInsideGap)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].EventSeq < findings[j].EventSeq
	})

	return domain.Verdict{
		RuleVersion:      RuleVersion,
		Outcome:          outcome,
		Findings:         findings,
		MissingFragments: fragments,
		EvidenceIDs:      evidenceIDs,
	}, nil
}

// isOtherUserResource treats an event as same-tenant horizontal access when
// the detail field names an owner that differs from the acting user.
func isOtherUserResource(event domain.EvidenceEvent) bool {
	owner := event.Detail
	return owner != "" && owner != event.Actor.UserID
}

func decideOutcome(findings []domain.Finding, events []domain.EvidenceEvent, gapEvents int) string {
	hasTenantRule := false
	hasVertical := false
	hasHorizontal := false
	for _, finding := range findings {
		switch finding.RuleID {
		case "IDOR-T1":
			hasTenantRule = true
		case "IDOR-V1":
			hasVertical = true
		case "IDOR-H1":
			hasHorizontal = true
		}
	}
	switch {
	case hasTenantRule && hasVertical:
		return domain.VerdictVerticalIDOR
	case hasTenantRule:
		return domain.VerdictConfirmedIDOR
	case hasHorizontal:
		return domain.VerdictHorizontalIDOR
	}

	// No positive IDOR signal. If material evidence sits inside a clock gap,
	// a clean verdict cannot be defended: report inconclusive instead.
	if len(events) > 0 && gapEvents == len(events) {
		return domain.VerdictInconclusive
	}
	if gapEvents > 0 {
		return domain.VerdictInconclusive
	}
	if len(events) == 0 {
		return domain.VerdictInconclusive
	}
	return domain.VerdictBenign
}
