package report

func Legacy(report Report) map[string]any {
	input := report.Automatic.Mapping.AttackInput
	result := "unknown_extension_denied"
	stack := ""
	if report.Automatic.Mapping.Trigger != nil {
		trigger := report.Automatic.Mapping.Trigger
		stack = trigger.File + ":" + itoa(trigger.Line) + " " + trigger.Function
	}
	if !report.Automatic.ReplaySucceeded {
		result = report.Automatic.Failure.Code
	}
	permission := ""
	if report.Automatic.Mapping.Permission != nil {
		permission = report.Automatic.Mapping.Permission.Actual
	}
	extension := ""
	if report.Automatic.Mapping.UnknownExtension != nil {
		extension = report.Automatic.Mapping.UnknownExtension.Name
	}
	return map[string]any{
		"timestamp":         report.Run.CompletedAt,
		"version":           report.Run.AppVersion,
		"seed":              report.Run.RecoveredSeed,
		"input":             input.Path,
		"input_sha256":      input.SHA256,
		"result":            result,
		"stacktrace":        stack,
		"unknown_extension": extension,
		"permission":        permission,
		"evidence_ok":       report.Automatic.EvidenceIntegrity.OK,
		"manual_status":     report.Manual.Status,
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
