// Package runner ties the decompressor, the permission gate and the audit
// log together and turns each verification run into an evidence record.
package runner

// ActionDecompress is the privileged operation a subject must hold before
// any block is expanded.
const ActionDecompress = "decompress.execute"

// Subject is the principal requesting a decompression run.
type Subject struct {
	ID          string
	Permissions []string
}

// Decide evaluates whether the subject may perform action.
func (s Subject) Decide(action string) (allowed bool, reason string) {
	for _, p := range s.Permissions {
		if p == action || p == "*" {
			return true, "permission " + action + " granted to " + s.ID
		}
	}
	return false, "permission " + action + " denied for " + s.ID
}
