package replay

import (
	"strings"

	"seedreview/internal/model"
)

func failureActions(recovery model.Recovery, execution execution) []model.NextAction {
	if execution.status == "ok" {
		return []model.NextAction{}
	}
	artifact := shellQuote(recovery.Artifact)
	target := shellQuote(recovery.Target)
	var actions []model.NextAction
	switch execution.failureCode {
	case "artifact_missing":
		actions = append(actions, model.NextAction{
			Code:   "RESTORE_ARTIFACT",
			Action: "恢复路径 `" + artifact + "` 对应的 libFuzzer 产物，或修正清单后重新执行 replay。",
			Reason: "没有攻击输入就无法建立输入、触发点、权限与日志的复核链。",
		})
	case "target_missing":
		actions = append(actions,
			model.NextAction{
				Code:   "BUILD_TARGET",
				Action: "运行 `make fuzz-build`，确认清单目标 `" + target + "` 存在后重新重放。",
				Reason: "重放目标不存在，当前结论不能视为已复核。",
			},
			model.NextAction{
				Code:   "CAPTURE_TOOLCHAIN",
				Action: "保存 `clang --version`、编译参数和生成的目标哈希。",
				Reason: "需要证明后续重放使用的是同一构建环境。",
			},
		)
	case "target_not_executable":
		actions = append(actions, model.NextAction{
			Code:   "FIX_TARGET_MODE",
			Action: "执行 `chmod +x " + target + "`，并重新运行 `seedreview replay`。",
			Reason: "目标存在但不可执行，未产生可采信的重放证据。",
		})
	case "replay_timeout":
		actions = append(actions,
			model.NextAction{
				Code:   "REPRODUCE_WITH_TIMEOUT",
				Action: "直接运行 `" + target + " -runs=1 -timeout=30 " + artifact + "` 并保留 stderr。",
				Reason: "需要区分目标死循环、资源耗尽和调度超时。",
			},
			model.NextAction{
				Code:   "MINIMIZE_INPUT",
				Action: "运行 `" + target + " -minimize_crash=1 -exact_artifact_path=minimized " + artifact + "` 缩小输入。",
				Reason: "缩小后的输入更适合定位触发位置和权限路径。",
			},
		)
	case "replay_crash":
		actions = append(actions,
			model.NextAction{
				Code:   "KEEP_CRASH_EVIDENCE",
				Action: "冻结输入、目标和 stderr 哈希，不要覆盖原始 libFuzzer 产物。",
				Reason: "崩溃证据是后续根因分析和责任确认的基线。",
			},
			model.NextAction{
				Code:   "SYMBOLIZE_CRASH",
				Action: "使用同一目标执行 `ASAN_OPTIONS=symbolize=1:abort_on_error=1 " + target + " -runs=1 " + artifact + "`。",
				Reason: "需要把崩溃地址映射到源码触发位置。",
			},
		)
	case "trace_unreadable", "trace_missing":
		actions = append(actions, model.NextAction{
			Code:   "FIX_TRACE_CAPTURE",
			Action: "确认目标写入 `SEED_AUDIT_TRACE`，重新构建后执行一次 `-runs=1` 重放。",
			Reason: "缺少结构化 trace 时无法自动关联扩展、权限与触发位置。",
		})
	default:
		actions = append(actions, model.NextAction{
			Code:   "ISOLATE_REPLAY",
			Action: "在干净目录重新执行 `" + target + " -runs=1 " + artifact + "`，保存命令、退出码和 stderr。",
			Reason: "需要排除环境污染后再判断是否为产品问题。",
		})
	}
	if !strings.Contains(execution.failureMsg, "SEED_AUDIT_TRACE") {
		actions = append(actions, model.NextAction{
			Code:   "ATTACH_FAILURE_EVIDENCE",
			Action: "把退出码、signal、stderr 和原始输入哈希附到复核记录，再关闭人工确认项。",
			Reason: "失败结论必须能由证据库独立复核。",
		})
	}
	return actions
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
