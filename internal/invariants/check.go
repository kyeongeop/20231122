package invariants

import (
	"encoding/hex"
	"fmt"

	"taintlab/internal/canonical"
	"taintlab/internal/model"
)

func Check(result model.Result) error {
	if result.SchemaVersion != model.ResultSchema {
		return fmt.Errorf("schema_version=%q", result.SchemaVersion)
	}
	if len(result.Input.SHA256) != 64 {
		return fmt.Errorf("input sha256 length=%d", len(result.Input.SHA256))
	}
	if len(result.Input.PreviewHex) > 512 {
		return fmt.Errorf("preview hex length=%d", len(result.Input.PreviewHex))
	}
	if result.Input.SizeBytes < 0 {
		return fmt.Errorf("negative input size")
	}
	if result.Input.RawComplete {
		raw, err := hex.DecodeString(result.Input.RawHex)
		if err != nil {
			return fmt.Errorf("decode raw_hex: %w", err)
		}
		if len(raw) != result.Input.SizeBytes {
			return fmt.Errorf("raw input size=%d declared=%d", len(raw), result.Input.SizeBytes)
		}
		if canonical.SumBytes(raw) != result.Input.SHA256 {
			return fmt.Errorf("raw input digest mismatch")
		}
	}
	switch result.Status {
	case "accepted":
		if !result.Permission.Evaluated {
			return fmt.Errorf("accepted input did not evaluate permission")
		}
	case "empty", "oversized", "malformed":
		if result.Permission.Decision != "deny" {
			return fmt.Errorf("%s input decision=%q", result.Status, result.Permission.Decision)
		}
		if result.Status == "oversized" && result.Input.RawComplete {
			return fmt.Errorf("oversized input marked raw_complete")
		}
	default:
		return fmt.Errorf("unknown status=%q", result.Status)
	}
	if result.Status == "accepted" && len(result.Evidence.Events) != 4 {
		return fmt.Errorf("accepted input event count=%d", len(result.Evidence.Events))
	}
	for index, event := range result.Evidence.Events {
		if event.Ordinal != index+1 || event.CausalOrder != index+1 {
			return fmt.Errorf("event %d order ordinal=%d causal=%d",
				index, event.Ordinal, event.CausalOrder)
		}
		if len(event.PayloadSHA256) != 64 {
			return fmt.Errorf("event %d payload hash length=%d", index, len(event.PayloadSHA256))
		}
	}
	for index, step := range result.Attack.TaintPath {
		if step.Ordinal != index+1 {
			return fmt.Errorf("taint step %d ordinal=%d", index, step.Ordinal)
		}
	}
	if result.Trigger.Detected && !result.Attack.Source.Tainted {
		return fmt.Errorf("untainted source produced a trigger")
	}
	if result.Permission.TaintedEscalation &&
		(!result.Permission.Mismatch || !result.Trigger.Detected) {
		return fmt.Errorf("escalation without mismatch/trigger")
	}
	if len(result.Evidence.Key) == 0 {
		return fmt.Errorf("key evidence is empty")
	}
	if len(result.Evidence.SHA256) != 64 {
		return fmt.Errorf("evidence sha256 length=%d", len(result.Evidence.SHA256))
	}
	return nil
}
