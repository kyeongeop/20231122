package audit

import "fmt"

func attachArtifact(steps []Step, artifactID string) {
	for i := range steps {
		if steps[i].Evidence != nil {
			steps[i].Evidence.ArtifactID = artifactID
		}
	}
}

func stepByKey(steps []Step, key string) *Step {
	for i := range steps {
		if steps[i].Key == key {
			return &steps[i]
		}
	}
	return nil
}

func conclusion(id, code string, step *Step, status Status, severity, title, detail string) Conclusion {
	evidence := Evidence{}
	if step != nil {
		if step.Evidence != nil {
			evidence = *step.Evidence
		}
		return Conclusion{
			ID: id, Code: code, Status: status, Severity: severity,
			Title: title, Detail: detail, StepID: step.ID, Evidence: evidence,
		}
	}
	return Conclusion{ID: id, Code: code, Status: status, Severity: severity, Title: title, Detail: detail}
}

func truncatedConclusions(result Result) []Conclusion {
	capture := stepByKey(result.Steps, "capture.complete")
	origin := stepByKey(result.Steps, "policy.origin")
	detail := "首个错误状态是 capture.complete。输入在字段值中段结束，因此没有完整报文可用。"
	if capture != nil {
		detail = fmt.Sprintf("%s 偏移 %d..%d 保留原始尾部；后续状态停在 blocked，不生成通过结论。",
			capture.Summary, capture.Evidence.Start, capture.Evidence.End)
	}
	gap := conclusion("c_trunc_02", "ORIGIN-GAP", origin, StatusBlocked, "info",
		"来源匹配没有结论", "截断阻止了响应头解析。系统不把未知来源写成通过，也不把缺失字节补成猜测。")
	if capture != nil && capture.Evidence != nil {
		gap.Evidence = *capture.Evidence
	}
	return []Conclusion{
		conclusion("c_trunc_01", "CAP-TRUNC", capture, StatusTruncated, "critical",
			"首个错误：采集在字段值中途截断", detail),
		gap,
	}
}

func replayConclusions(result Result, seam, recoveredBytes int) []Conclusion {
	vary := stepByKey(result.Steps, "policy.vary")
	origin := stepByKey(result.Steps, "policy.origin")
	credentials := stepByKey(result.Steps, "policy.credentials")
	replay := stepByKey(result.Steps, "replay.verify")

	varyDetail := "具体允许来源会随请求变化，但响应缓存键只含 Accept-Encoding。共享缓存可能把一个来源的 CORS 判定复用给另一个来源。"
	if vary != nil {
		varyDetail = fmt.Sprintf("首个错误状态是 policy.vary。证据：%s", vary.Summary)
	}
	originDetail := "请求 Origin 只留下脱敏占位符。无法证明请求来源与允许来源等价，因此保留 undecided。"
	if origin != nil {
		originDetail = origin.Detail
	}

	replayConclusion := conclusion("c_replay_01", "SEAM-OK", replay, StatusPass, "info",
		"恢复接缝已独立核验",
		fmt.Sprintf("截断前缀保持不变；追加 %d bytes 后重新解析。恢复块可从接缝偏移 %d 单独取出。", recoveredBytes, seam))
	if replayConclusion.Evidence.ArtifactID != "" {
		replayConclusion.Detail += " 证据范围覆盖接缝两侧上下文。"
	}

	return []Conclusion{
		conclusion("c_replay_02", "CORS-VARY", vary, StatusFail, "high",
			"首个错误：带凭据的 CORS 响应未按 Origin 分区", varyDetail),
		conclusion("c_replay_03", "ORIGIN-UNDECIDED", origin, StatusUndecided, "warning",
			"边界未决：脱敏来源无法做等价判断", originDetail),
		replayConclusion,
		conclusion("c_replay_04", "CRED-OK", credentials, StatusPass, "info",
			"具体来源与凭据组合未触发冲突", "Access-Control-Allow-Origin 为具体来源，Access-Control-Allow-Credentials 为 true；组合本身合法。"),
	}
}
