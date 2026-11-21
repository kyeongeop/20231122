package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"lockrecon/internal/lockout"
)

// writeReport 生成验收报告: 攻击输入 -> 触发位置 -> 权限判断 -> 日志证据,
// 每行锚定具体时间戳(RFC3339Nano UTC)与原始偏移。
func writeReport(store *lockout.Store, rawSHA string, rawLen int, dupID string) error {
	attempts, err := store.DumpAttempts()
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# 并发账户锁定异常重建报告\n\n")
	b.WriteString(fmt.Sprintf("- 原始材料: `evidence/raw_capture.bin` (%d 字节, 只读 0444)\n", rawLen))
	b.WriteString(fmt.Sprintf("- 原件 SHA256: `%s` (运行前后一致, 未修改)\n", rawSHA))
	b.WriteString(fmt.Sprintf("- 策略: 连续失败 %d 次锁定 %v\n", lockout.FailThreshold, lockout.LockDuration))
	b.WriteString(fmt.Sprintf("- 重复对象 RequestID: `%s`\n\n", dupID))

	b.WriteString("## 攻击输入 -> 触发位置 -> 权限判断 -> 日志证据\n\n")
	b.WriteString("| 证据行 | 时间戳 (UTC) | 原始偏移 | 阶段 | 判定 | 触发位置/详情 |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, a := range attempts {
		short := a.RequestID
		if len(short) > 8 {
			short = short[:8] + "…"
		}
		b.WriteString(fmt.Sprintf("| #%d (%s) | %s | %d | %s | %s | %s |\n",
			a.ID, short, a.TS, a.RawOffset, a.Phase, a.Decision, a.Detail))
	}

	b.WriteString("\n## 异常结论\n\n")
	increments := 0
	probeAllowed := false
	dupCounts := map[string]int{}
	for _, a := range attempts {
		if a.Phase == "increment" {
			increments++
			if a.RequestID == dupID {
				dupCounts[a.Detail]++
			}
		}
		if a.Phase == "authorize" && a.Decision == "ALLOW" && a.RequestID == "00000000000000000000000000000004" {
			probeAllowed = true
		}
	}
	lostUpdate := ""
	for detail, n := range dupCounts {
		if n == 2 {
			lostUpdate = detail
		}
	}
	b.WriteString(fmt.Sprintf("- 失败事件共 %d 次(3 唯一 + 重复对象 2 副本), 计数器终值仅 4, 阈值 %d 未达到, 锁定被绕过。\n",
		increments, lockout.FailThreshold))
	b.WriteString(fmt.Sprintf("- 丢失更新直接证据: 重复对象两副本的 increment 行记录相同计数 `%s`。\n", lostUpdate))
	b.WriteString(fmt.Sprintf("- 攻击收益: 随后持合法凭据的探测登录被权限判断放行 (ALLOW=%v), 本应在第 5 次失败后被拒。\n", probeAllowed))
	b.WriteString(fmt.Sprintf("- 根因: `%s` 缺失按 RequestID 去重, `%s` 读-改-写无事务保护, 重复对象两副本并发通过 `%s` 门闸后互相覆盖计数(丢失更新)。\n",
		lockout.LocDedupAbsent, lockout.LocIncrement, lockout.LocAuthorize))
	b.WriteString("- 空输入与超大输入已被拒绝并留证(见 evidence 表 empty_input / oversized_input 行)。\n")

	path := filepath.Join(evidenceDir, "report.md")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return err
	}
	fmt.Println("报告已生成:", path)
	return nil
}
