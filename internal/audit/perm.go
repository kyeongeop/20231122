package audit

import "strings"

// Rule IDs emitted by the permission classifier.
const (
	RuleSetUID        = "SETUID"
	RuleSetGID        = "SETGID"
	RuleWorldWritable = "WORLD_WRITABLE"
	RuleRootWritable  = "ROOT_GROUP_OTHER_WRITABLE"
	RuleAllPermissive = "MODE_0777"
	RuleShadowExposed = "SHADOW_WORLD_READABLE"
)

// Finding is one permission-audit hit for a single tar entry.
type Finding struct {
	Rule     string
	Severity string
	Path     string
	Mode     uint32
	UID      int
	GID      int
}

// sensitiveFiles that must never be world-readable.
var sensitiveFiles = map[string]bool{
	"etc/shadow":  true,
	"etc/gshadow": true,
}

// ClassifyMode inspects a tar entry's metadata and returns all triggered
// findings. It is a pure function so it can be fuzzed directly.
func ClassifyMode(path string, mode uint32, uid, gid int, isDir bool) []Finding {
	var out []Finding
	perm := mode & 0o777
	special := mode & 0o7000

	add := func(rule, sev string) {
		out = append(out, Finding{Rule: rule, Severity: sev, Path: path, Mode: mode, UID: uid, GID: gid})
	}

	if special&0o4000 != 0 {
		add(RuleSetUID, "high")
	}
	if special&0o2000 != 0 {
		add(RuleSetGID, "high")
	}
	if perm&0o002 != 0 {
		sev := "medium"
		if isDir {
			sev = "high"
		}
		add(RuleWorldWritable, sev)
	}
	if perm == 0o777 {
		add(RuleAllPermissive, "high")
	}
	if uid == 0 && perm&0o022 != 0 {
		add(RuleRootWritable, "medium")
	}
	clean := strings.TrimPrefix(strings.TrimPrefix(path, "./"), "/")
	if sensitiveFiles[clean] && perm&0o004 != 0 {
		add(RuleShadowExposed, "critical")
	}
	return out
}
