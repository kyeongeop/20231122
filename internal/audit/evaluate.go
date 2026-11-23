package audit

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// evaluate runs the ordered processing steps for one object and builds the
// conclusion with its full provenance trail.
func (p *Pipeline) evaluate(obj Object, sha string) (rec ConclusionRecord) {
	step := func(name, detail string) {
		rec.Steps = append(rec.Steps, Step{Name: name, Detail: detail})
	}
	evidence := func(key, value string) {
		rec.Evidence = append(rec.Evidence, Evidence{Key: key, Value: value})
	}
	evidence("raw_sha256", sha)
	step("ingest", fmt.Sprintf("received %d bytes, kind=%s", len(obj.Raw), obj.Kind))
	if err := p.stageTemp(obj.Label, sha); err != nil {
		rec.Verdict = VerdictError
		rec.Reason = "staging failed: " + err.Error()
		return rec
	}
	step("stage", "normalized into temporary staging table")
	tok, err := ParseToken(obj.Raw)
	if err != nil {
		if errors.Is(err, ErrUnknownExtension) {
			step("classify", "PRT prefix with unregistered extension tag")
			rec.Verdict = VerdictUnknownExtension
			rec.Reason = err.Error()
			evidence("extension_tag", strings.SplitN(obj.Raw, ":", 2)[0])
			return rec
		}
		step("parse", "failed: "+err.Error())
		rec.Verdict = VerdictError
		rec.Reason = "parse error: " + err.Error()
		evidence("parse_error", err.Error())
		return rec
	}
	step("parse", fmt.Sprintf("snapshot=%s id=%s expiry=%d", tok.Snapshot, tok.ID, tok.Expiry))
	evidence("snapshot", tok.Snapshot)
	evidence("token_id", tok.ID)
	evidence("expiry_unix", fmt.Sprintf("%d", tok.Expiry))
	// Integrity gate: v2 ids must be alphanumeric; anything else is an
	// internal inconsistency and raises an exception for this object.
	if tok.Snapshot == SnapshotV2 && !isAlnum(tok.ID) {
		step("verify", "v2 id contains non-alphanumeric characters")
		panic(fmt.Sprintf("integrity check failed for v2 id %q", tok.ID))
	}
	step("verify", "integrity checks passed")
	expiry := time.Unix(tok.Expiry, 0).UTC()
	switch {
	case expiry.Equal(p.Now.UTC()):
		// Boundary: token expires exactly at the audit clock reading.
		// Clock skew makes valid/expired indistinguishable -> undecidable.
		step("decide", "expiry equals audit clock exactly; within clock-skew window")
		rec.Verdict = VerdictUndecidable
		rec.Reason = "expiry boundary equals audit time; cannot decide valid vs expired"
		evidence("audit_clock", p.Now.UTC().Format(time.RFC3339Nano))
		evidence("expiry_utc", expiry.Format(time.RFC3339Nano))
		evidence("clock_skew_window", "±5s")
	case expiry.Before(p.Now.UTC()):
		step("decide", "expiry is before audit clock")
		rec.Verdict = VerdictExpired
		rec.Reason = "token expired at " + expiry.Format(time.RFC3339)
	default:
		step("decide", "expiry is after audit clock")
		rec.Verdict = VerdictValid
		rec.Reason = "token valid until " + expiry.Format(time.RFC3339)
	}
	return rec
}

func isAlnum(s string) bool {
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z') {
			return false
		}
	}
	return len(s) > 0
}
