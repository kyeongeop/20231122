// Command seed populates the SQLite store with the demonstration dataset:
// a libFuzzer campaign with two mid-run cancellations, an evaluation run
// whose conclusions trace back to original inputs and processing steps, an
// undetermined edge case with retained evidence, and a failed run with
// actionable follow-ups.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"wsauthz/internal/checker"
	"wsauthz/internal/store"
)

func main() {
	dbPath := flag.String("db", "artifacts/wsauthz.db", "SQLite database path")
	flag.Parse()

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	must(seedFuzzRun(st))
	must(seedEvaluationRun(st))
	must(seedFailedRun(st))
	fmt.Println("seeded:", *dbPath)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func tailLog(path string, lines int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "(log unavailable: " + err.Error() + ")"
	}
	all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return strings.Join(all, "\n")
}

// seedFuzzRun records the libFuzzer campaign, including the two real
// mid-run cancellations (SIGINT) captured in artifacts/fuzz_run*.log.
func seedFuzzRun(st *store.Store) error {
	runID, err := st.CreateRun("libfuzzer-campaign", "libFuzzer 18.1.8 (clang -fsanitize=fuzzer,address)")
	if err != nil {
		return err
	}
	if err := st.AddEvent(runID, "cancelled",
		"中途取消 #1：操作员中断首轮模糊测试（SIGINT），已执行约 420 万次输入；日志 artifacts/fuzz_run1.log"); err != nil {
		return err
	}
	if err := st.AddEvent(runID, "resumed", "以相同语料库重启第二轮"); err != nil {
		return err
	}
	if err := st.AddEvent(runID, "cancelled",
		"中途取消 #2：CI 时间预算超限，第二轮在约 420 万次执行后再次中断；日志 artifacts/fuzz_run2.log"); err != nil {
		return err
	}
	if err := st.AddEvent(runID, "resumed", "缩短 max_total_time=8s 后执行收尾轮"); err != nil {
		return err
	}
	if err := st.FinishRun(runID, "completed",
		"收尾轮完成 7,937,360 次执行，无崩溃；不变量（判定结果恒为已知枚举）成立"); err != nil {
		return err
	}

	// Keep the campaign logs as evidence attached to a synthetic input so
	// they show up in the evidence section with full provenance.
	inputID, err := st.RecordInput(runID, "fuzz-campaign-logs",
		shaOf(tailLog("artifacts/fuzz_run1.log", 6)+tailLog("artifacts/fuzz_run2.log", 6)+tailLog("artifacts/fuzz_run3.log", 4)),
		"# libFuzzer 三轮执行日志（首轮与次轮被中途取消）",
		nil)
	if err != nil {
		return err
	}
	for _, ev := range []struct{ label, path string; lines int }{
		{"fuzz_run1.log（首轮，中途取消）", "artifacts/fuzz_run1.log", 6},
		{"fuzz_run2.log（次轮，中途取消）", "artifacts/fuzz_run2.log", 6},
		{"fuzz_run3.log（收尾轮，完成）", "artifacts/fuzz_run3.log", 4},
	} {
		if err := st.AddEvidence(inputID, ev.label, tailLog(ev.path, ev.lines)); err != nil {
			return err
		}
	}
	return st.AddConclusion(inputID, "automated", "no_bypass",
		"模糊测试未发现使判定管线崩溃或产生非法结论的输入", "wsauthz-seed")
}

func shaOf(s string) string {
	return checker.Input{Content: s}.Digest()
}

// evalCase is one handshake scenario fed through the real checker pipeline.
type evalCase struct {
	label   string
	content string
	manual  *struct{ verdict, rationale, by string }
	actions []struct{ action, reason string }
}

// seedEvaluationRun runs the real checker over the scenario set and stores
// inputs, steps, automated conclusions, evidence and manual confirmations.
func seedEvaluationRun(st *store.Store) error {
	runID, err := st.CreateRun("handshake-case-evaluation", "wsauthz/checker (Go 1.x)")
	if err != nil {
		return err
	}

	cases := []evalCase{
		{
			label: "case-A: 无凭证握手被 101 接受",
			content: `# unauthenticated upgrade attempt against /ws/admin
policy.auth_required: true
request.credential: none
response.status: 101`,
			manual: &struct{ verdict, rationale, by string }{
				"bypass_detected",
				"人工复核确认 /ws/admin 在网关注册表中标记为需认证端点，绕过成立",
				"security-reviewer-01",
			},
			actions: []struct{ action, reason string }{
				{"在网关层对 /ws/admin 强制前置鉴权并回归验证", "已确认授权绕过，需修复"},
			},
		},
		{
			label: "case-B: 无凭证握手被 401 拒绝",
			content: `# unauthenticated upgrade attempt against /ws/feed
policy.auth_required: true
request.credential: none
response.status: 401`,
			manual: &struct{ verdict, rationale, by string }{
				"no_bypass",
				"人工确认 401 由统一鉴权中间件返回，行为符合策略",
				"security-reviewer-01",
			},
		},
		{
			label: "case-C: 边界——响应完成前连接中断（无法判断）",
			content: `# capture interrupted when the fuzz campaign was cancelled mid-run
policy.auth_required: true
request.credential: none
response.connection: reset`,
			actions: []struct{ action, reason string }{
				{"使用 tcpdump 环形缓冲重抓该端点握手，超时上调至 30s", "连接在状态行返回前被重置，证据不完整"},
				{"若重抓仍 reset，向端点负责人确认服务是否在鉴权前主动断连", "需区分 WAF 阻断与服务异常"},
			},
		},
		{
			label: "case-D: 边界——非预期状态码 302（无法判断）",
			content: `# upgrade attempt redirected
policy.auth_required: true
request.credential: none
response.status: 302`,
			actions: []struct{ action, reason string }{
				{"跟随 302 的 Location 重放握手，确认重定向目标是否仍要求认证", "302 可能把未授权请求引向公开端点"},
			},
		},
	}

	for _, c := range cases {
		in := checker.Input{Label: c.label, Content: c.content}
		res := checker.Evaluate(in)

		steps := make([]struct{ Name, Detail string }, 0, len(res.Steps))
		for _, s := range res.Steps {
			steps = append(steps, struct{ Name, Detail string }{s.Name, s.Detail})
		}
		inputID, err := st.RecordInput(runID, in.Label, in.Digest(), in.Content, steps)
		if err != nil {
			return err
		}
		if err := st.AddConclusion(inputID, "automated", string(res.Verdict),
			res.Rationale, "wsauthz/checker"); err != nil {
			return err
		}
		for label, content := range res.Evidence {
			if err := st.AddEvidence(inputID, label, content); err != nil {
				return err
			}
		}
		if c.manual != nil {
			if err := st.AddConclusion(inputID, "manual", c.manual.verdict,
				c.manual.rationale, c.manual.by); err != nil {
				return err
			}
		}
		for _, a := range c.actions {
			if err := st.AddNextAction(0, inputID, a.action, a.reason); err != nil {
				return err
			}
		}
	}
	return st.FinishRun(runID, "completed", "4 个场景评估完毕：1 绕过、1 正常、2 无法判断")
}

// seedFailedRun records a failed run with actionable follow-ups.
func seedFailedRun(st *store.Store) error {
	runID, err := st.CreateRun("endpoint-reachability-scan", "wsauthz/checker (Go 1.x)")
	if err != nil {
		return err
	}
	if err := st.FinishRun(runID, "failed",
		"目标 wss://staging.internal/ws/billing 连接超时（3 次重试均失败），扫描中止"); err != nil {
		return err
	}
	for _, a := range []struct{ action, reason string }{
		{"执行 `nc -vz staging.internal 443` 确认网络可达性，必要时申请防火墙放行", "连接超时通常源于网络隔离"},
		{"确认 staging 环境证书未过期：`openssl s_client -connect staging.internal:443`", "TLS 握手失败也会表现为超时"},
		{"恢复后以 `--resume` 重跑扫描并补齐缺失端点的判定", "本次失败未产生任何结论，需补齐覆盖"},
	} {
		if err := st.AddNextAction(runID, 0, a.action, a.reason); err != nil {
			return err
		}
	}
	return nil
}
