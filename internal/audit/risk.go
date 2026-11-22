package audit

import (
	"fmt"
	"sort"
	"strings"
)

var severityRank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}

func SeverityRank(severity string) int {
	return severityRank[severity]
}

func classifyMount(record MountRecord) []Finding {
	findings := make([]Finding, 0, 4)
	add := func(severity, code, detail string) {
		findings = append(findings, Finding{
			Stage:       record.Stage,
			Severity:    severity,
			Code:        code,
			MountPoint:  record.MountPoint,
			Source:      record.Source,
			Detail:      detail,
			StartOffset: record.StartOffset,
			EndOffset:   record.EndOffset,
			Line:        record.Line,
		})
	}

	mountPoint := cleanPath(record.MountPoint)
	if isDockerSocket(mountPoint) || isDockerSocket(cleanPath(record.Source)) {
		add("critical", "container_socket_mount",
			"container runtime socket is visible inside the mount namespace")
	}
	if mountPoint == "/proc" && !record.Permissions.ReadOnly {
		add("high", "proc_mounted_writable",
			"procfs is writable; kernel and process metadata may be altered")
	}
	if mountPoint == "/sys" && !record.Permissions.ReadOnly {
		add("high", "sysfs_mounted_writable",
			"sysfs is writable; host kernel controls may be exposed")
	}
	if sensitiveMount(mountPoint) {
		severity := "high"
		if record.Permissions.ReadOnly {
			severity = "medium"
		}
		add(severity, "sensitive_path_mount",
			fmt.Sprintf("sensitive host path %q is mounted (read_only=%t)", mountPoint, record.Permissions.ReadOnly))
	}
	if !record.Permissions.ReadOnly && hasSharedPropagation(record.Optional) {
		add("high", "shared_mount_propagation",
			"writable mount uses shared propagation and can affect the host mount namespace")
	}
	if !record.Permissions.ReadOnly && isDeviceBacked(record) {
		add("high", "writable_device_backed_mount",
			fmt.Sprintf("writable mount is backed by host filesystem %q (%s)", record.Source, record.FSType))
	}
	if !record.Permissions.ReadOnly && !record.Permissions.NoSUID {
		add("medium", "suid_capable_writable_mount",
			"writable mount does not set nosuid")
	}
	if !record.Permissions.ReadOnly && !record.Permissions.NoDev &&
		(mountPoint == "/dev" || strings.HasPrefix(mountPoint, "/dev/")) {
		add("medium", "device_capable_writable_mount",
			"writable /dev mount does not set nodev")
	}
	return findings
}

func AggregateFindings(records []MountRecord) []Finding {
	byMountPoint := make(map[string]MountRecord)
	findings := make([]Finding, 0)
	for _, record := range records {
		key := cleanPath(record.MountPoint)
		first, exists := byMountPoint[key]
		if exists {
			findings = append(findings, Finding{
				Stage:       3,
				Severity:    "medium",
				Code:        "duplicate_mountpoint",
				MountPoint:  record.MountPoint,
				Source:      record.Source,
				Detail:      fmt.Sprintf("mountpoint is already covered by mount %s at offset %d", first.MountID, first.StartOffset),
				StartOffset: record.StartOffset,
				EndOffset:   record.EndOffset,
				Line:        record.Line,
			})
			continue
		}
		byMountPoint[key] = record
	}
	SortFindings(findings)
	return findings
}

func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].StartOffset != findings[j].StartOffset {
			return findings[i].StartOffset < findings[j].StartOffset
		}
		if findings[i].Code != findings[j].Code {
			return findings[i].Code < findings[j].Code
		}
		return SeverityRank(findings[i].Severity) > SeverityRank(findings[j].Severity)
	})
}

func cleanPath(path string) string {
	if len(path) > 1 {
		return strings.TrimRight(path, "/")
	}
	return path
}

func isDockerSocket(path string) bool {
	return path == "/var/run/docker.sock" || path == "/run/docker.sock"
}

func sensitiveMount(path string) bool {
	switch path {
	case "/etc", "/root", "/home", "/boot", "/var/lib/docker", "/run", "/var/run":
		return true
	}
	return strings.HasPrefix(path, "/etc/") ||
		strings.HasPrefix(path, "/root/") ||
		strings.HasPrefix(path, "/home/") ||
		strings.HasPrefix(path, "/var/lib/docker/")
}

func hasSharedPropagation(optional string) bool {
	for _, field := range strings.Fields(optional) {
		if strings.HasPrefix(field, "shared:") {
			return true
		}
	}
	return false
}

func isDeviceBacked(record MountRecord) bool {
	switch record.FSType {
	case "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs":
		return record.Source != "none" && record.Source != ""
	}
	return strings.HasPrefix(record.Source, "/dev/")
}
