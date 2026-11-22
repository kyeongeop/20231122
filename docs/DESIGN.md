# 设计说明：验证码重放检测的可暂停处理流程

## 1. 场景与领域模型

输入是来自多台设备的验证码事件流，每条事件包含全局 `sequence`、`device_id`、
`code`、`user_id`、`kind`（`issue` 签发 / `consume` 消费）、设备本地时钟
`observed_at` 和时钟偏移 `offset_ms`。参考时间统一为

```
reference_at = observed_at + offset_ms
```

设备之间时钟不同步：`dev-a` 已对齐参考时钟，`dev-b` 本地时钟落后 120 秒，
需要靠 `offset_ms` 还原参考时间。检测逻辑只使用参考时间，不直接比较本地时钟。

判定规则（`internal/detect/detector.go`）：

- `ok`：窗口内首次消费。
- `replay`（critical）：同一 `code+user_id` 在有效期内被再次消费。
- `expired`：超过有效期；或时钟倒挂导致消费参考时间早于签发（负 age）。
- `unknown_code`（warning）：找不到对应签发记录。

## 2. 缺失片段（围绕时钟不同步组织）

每台设备维护独立游标（最后序列号、最后参考时间、边界事件）。两类缺口都会
作为证据落库，而不是静默跳过：

- `sequence_gap`：同一设备相邻序列号不连续，记录缺失区间。
- `clock_gap`：同一设备相邻事件的参考时间跳变超过
  `clock_gap_threshold_ms`。

检查点的设备游标保存了**边界事件**，恢复后缺口检测可以跨越分段边界，
因此分段运行与一次性运行产生完全相同的缺口序列（由
`TestBudgetPauseAndResumeIsEquivalent` 与 CLI `compare` 双重保证）。

## 3. 暂停、中间状态与恢复

处理以“段（segment）”为单位，暂停条件在处理事件**之前**检查，保证任一事件
不会被重复处理或遗漏：

- `budget_exhausted`：本段事件预算（`max_events`）耗尽。
- `fault_injected`：确定性故障注入，用于演练外部挂起。
- `completed`：输入流全部消费完毕。

每段结束时在一个 SQLite 事务内原子写入：决策、缺口、校验错误、issue 状态、
设备游标和检查点（`next_input_pos`、检测器 JSON 快照）。恢复时从最新检查点
重建检测器，并把分段预算计数清零——累计进度在检查点里，预算是每段独立的。

## 4. 资源不足与降级路径

内存中的 issue 缓存有硬上限 `max_tracked_issues`。达到上限后：

1. 检测器置 `degraded=true`，新签发记录直接写入 SQLite `issues` 表
   （`IssueSink`）。
2. 后续消费优先查持久化表（`IssueFinder`），内存表不再作为权威来源，
   避免用过零计数器漏报重放。
3. 消费后的计数更新同样落库；检查点与导出清单都记录降级状态。

降级路径的输出与内存路径逐字段一致，由
`TestDegradedDurablePathMatchesInMemory` 和演示脚本中的 `compare` 验证。

## 5. 关键证据

- 原始事件以规范化 JSON 的 SHA-256 摘要存入 `input_events.raw_sha256`，
  重放证据可回溯到具体输入记录。
- 所有决策、缺口、校验错误、检查点只追加不覆盖（upsert 仅用于状态表与
  可重入的检查点），并带 `segment_id` 标注来源分段。
- 导出包内每个 JSONL 文件都有 SHA-256、字节数和行数清单。

## 6. 独立复核与字段顺序

导出包（`internal/export`）包含：

- `manifest.json`：版本、计数、降级标志、配置、文件校验和（固定文件顺序）。
- `events.jsonl` / `decisions.jsonl` / `gaps.jsonl` / `checkpoints.jsonl`：
  每行一个紧凑 JSON，字段顺序由 Go 结构体定义固定。

同事只需 `replayctl verify --bundle DIR` 即可离线重算校验和与行数；
`replayctl compare --before A --after B` 逐行比较两次运行的决策与缺口。
重新载入产物时使用带类型的 JSONL 读取器（`review.LoadJSONL`），保持字段和
顺序不变，再与 SQLite 投影比对（见流水线集成测试）。

## 7. libFuzzer 集成

纯检测逻辑没有数据库依赖，通过 `go build -buildmode=c-shared` 导出
`RRFuzzInit/RRFuzzRun`，由 `fuzz/libfuzzer/harness.cc` 接入 libFuzzer。
每个输入是可读 JSON（配置 + 事件 + 切分点），目标内置不变量：

- 分段执行（含 JSON 快照往返）与一次性执行的决策必须一致。
- 快照往返不丢失 issue 与设备游标。
- 所有判定标签必须来自已知集合；任何 panic 即视为缺陷。

注意：c-shared 模式下 Go 代码不暴露 SanitizerCoverage 插桩，libFuzzer 报告的
覆盖率数字偏低属于预期；语料仍会持续变异并执行 Go 侧逻辑。
