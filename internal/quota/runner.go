package quota

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"quotabypass/internal/evidence"
	"quotabypass/internal/model"
)

// clock 产生单调递增的纳秒时间戳，保证记录可确定性复现。
type clock struct{ base time.Time }

func newClock() *clock {
	return &clock{base: time.Date(2026, 11, 22, 7, 23, 37, 808000000, time.UTC)}
}

func (c *clock) now() string {
	c.base = c.base.Add(time.Microsecond)
	return c.base.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

// Runner 执行一次场景重建。
type Runner struct {
	mode string
	clk  *clock
	logs []model.LogEntry
	seq  int
	name string
}

func NewRunner(mode string) *Runner {
	return &Runner{mode: mode, clk: newClock(), logs: []model.LogEntry{}}
}

func (r *Runner) log(level, event string, attempt int, message string) {
	r.seq++
	r.logs = append(r.logs, model.LogEntry{
		Seq: r.seq, At: r.clk.now(), Level: level, Event: event,
		Attempt: attempt, Message: message,
	})
}

// Run 重建单个场景。raw 为原始攻击输入字节，ordinal 为记录序号。
func (r *Runner) Run(scenario string, ordinal int, raw []byte) model.Record {
	input, inputEv, parseErr := ParseInput(raw)
	r.name = scenario
	runID := newRunID(scenario, r.mode, raw)

	rec := model.Record{
		Ordinal:     ordinal,
		RunID:       runID,
		Scenario:    scenario,
		Mode:        r.mode,
		CreatedAt:   r.clk.now(),
		AttackInput: input,
		Input:       inputEv,
		Attempts:    []model.Attempt{},
		Logs:        []model.LogEntry{},
	}
	rec.Input.MissingFields = ensureStrings(rec.Input.MissingFields)

	// 第一条日志固定为输入证据。
	r.log("info", "input_evidence", -1,
		fmt.Sprintf("sha256=%s bytes=%d truncated=%t",
			inputEv.SHA256, inputEv.Bytes, inputEv.Truncated))

	switch {
	case parseErr != nil && !IsFragmentMissing(parseErr):
		rec.Permission = r.invalidPermission(parseErr)
		rec.Summary = model.Summary{}
		r.log("info", "quota_enforced", -1,
			fmt.Sprintf("allowed=%d denied=%d", 0, 0))
		rec.Logs = append(rec.Logs, r.logs...)
		rec.RecordSHA256 = evidence.FingerprintRecord(rec)
		return rec
	}

	fragmentMissing := IsFragmentMissing(parseErr)
	if fragmentMissing {
		r.log("warn", "missing_fragments", -1,
			fmt.Sprintf("fields=[%s]", FragmentField))
		rec.Permission = r.fragmentPermission(fragmentMissing)
	} else {
		rec.Permission = model.Permission{
			Decision:   "allow",
			Authorized: true,
			Reason:     "rejection response complete; quota enforced",
			Policy:     PolicyReserve,
			Trigger:    gateTrigger(),
		}
	}

	rec.Attempts, rec.Summary = r.simulate(input, fragmentMissing)

	if rec.Summary.BypassDetected {
		r.log("error", "quota_bypass_detected", -1,
			fmt.Sprintf("allowed=%d expected=%d",
				rec.Summary.Allowed, rec.Summary.ExpectedAllowed))
	} else {
		r.log("info", "quota_enforced", -1,
			fmt.Sprintf("allowed=%d denied=%d",
				rec.Summary.Allowed, rec.Summary.Denied))
	}

	rec.Logs = append(rec.Logs, r.logs...)
	rec.RecordSHA256 = evidence.FingerprintRecord(rec)
	return rec
}

func ensureStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func (r *Runner) invalidPermission(err error) model.Permission {
	return model.Permission{
		Decision:   "deny",
		Authorized: false,
		Reason:     err.Error(),
		Policy:     PolicyFragment,
		Trigger:    runnerTrigger(),
	}
}

func (r *Runner) fragmentPermission(missing bool) model.Permission {
	if r.mode == ModeVulnerable {
		return model.Permission{
			Decision:   "allow",
			Authorized: false,
			Reason:     "missing rejection fragment: fail-open",
			Policy:     PolicyFragment,
			Trigger:    gateTrigger(),
		}
	}
	return model.Permission{
		Decision:   "deny",
		Authorized: true,
		Reason:     "missing rejection fragment: fail-closed",
		Policy:     PolicyFragment,
		Trigger:    gateTrigger(),
	}
}

// simulate 按确定性乱序重放并发请求并采集尝试证据。
func (r *Runner) simulate(input model.AttackInput, fragmentMissing bool) ([]model.Attempt, model.Summary) {
	total := input.ConcurrentRequests
	order := deterministicOrder(randSeed(input, r.mode), total)
	gate := NewGate(input.QuotaCount)

	attempts := make([]model.Attempt, total)
	allowed, denied := 0, 0

	for _, idx := range order {
		requestID := fmt.Sprintf("%s-req-%04d", r.name, idx)
		decision, status, reason, responseTpl := gate.Decide(r.mode, input, fragmentMissing)
		response := responseTpl
		if decision == "allow" {
			response = allowResponse(responseTpl, requestID)
		}
		level := "warn"
		if fragmentMissing && r.mode == ModeVulnerable {
			level = "error"
		}
		r.log(level, "attempt_decision", idx,
			fmt.Sprintf("%s status=%d reason=%q", decision, status, reason))

		attempts[idx] = model.Attempt{
			Ordinal:    idx,
			RequestID:  requestID,
			Decision:   decision,
			HTTPStatus: status,
			Reason:     reason,
			Response:   response,
			Trigger:    gateTrigger(),
			At:         r.clk.now(),
		}
		if decision == "allow" {
			allowed++
		} else {
			denied++
		}
	}

	expected := 0
	if !fragmentMissing {
		expected = input.QuotaCount
	}
	summary := model.Summary{
		ExpectedAllowed: expected,
		Allowed:         allowed,
		Denied:          denied,
		BypassDetected:  r.mode == ModeVulnerable && fragmentMissing && allowed > expected,
	}
	return attempts, summary
}

// randSeed 从输入与模式派生确定性种子。
func randSeed(input model.AttackInput, mode string) int64 {
	blob, _ := json.Marshal(struct {
		Tenant string `json:"tenant_id"`
		Quota  int    `json:"quota_count"`
		Reqs   int    `json:"concurrent_requests"`
		Mode   string `json:"mode"`
	}{input.TenantID, input.QuotaCount, input.ConcurrentRequests, mode})
	var seed int64
	for _, b := range sha256Sum(blob) {
		seed = seed*31 + int64(b)
	}
	return seed
}

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func sha256Bytes(data []byte) [32]byte { return sha256.Sum256(data) }

// deterministicOrder 用种子化的 Fisher–Yates 洗牌生成确定性乱序。
func deterministicOrder(seed int64, n int) []int {
	rng := newSeededRNG(seed)
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j := int(rng.int63n(int64(i + 1)))
		order[i], order[j] = order[j], order[i]
	}
	return order
}

func newRunID(scenario, mode string, raw []byte) string {
	sum := sha256Bytes(append(append([]byte(scenario), []byte(mode)...), raw...))
	return fmt.Sprintf("%s-%s-%s", scenario, mode, hex.EncodeToString(sum[:12]))
}
