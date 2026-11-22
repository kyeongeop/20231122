# 依赖版本风险清单 · 可复核流程（riskflow）

把“依赖版本风险清单”从一次性打分改造成**可复核、可重放、证据可追溯**的流程。
技术栈固定为 **Go + libFuzzer + SQLite**：

- **Go**：解析、状态机、权限判断、CLI 与重放器（SQLite 采用纯 Go 驱动 `modernc.org/sqlite`，无需系统 libsqlite3 开发头文件）。
- **SQLite（WAL 模式）**：批次、记录、每次状态转移、首错状态全部落库；中断后可由 WAL 恢复。
- **libFuzzer**：通过 `go build -buildmode=c-archive` 把 Go 核心导出为 C 归档，再由 C harness 链成 libFuzzer 目标，对真实解析/状态机路径做模糊测试。

## 目录

```
internal/model     领域模型、状态词汇、状态排序（首错判定依据）
internal/ingest    v1(旧)/v2(新) 格式识别、校验和、截断检测
internal/engine    确定性状态机、权限判断、风险评分、首错捕获
internal/store     SQLite 证据库（WAL、事务、只读证据查询）
internal/replay    导入/恢复/重放编排，转移轨迹逐条 diff
internal/fuzz      Go 侧 libFuzzer 桥接（//export RiskflowFuzz）
cmd/riskflow       CLI：generate/ingest/recover/replay/evidence
fuzz/harness       C 侧 LLVMFuzzerTestOneInput
fuzz/build.sh      构建 libFuzzer 目标
run_demo.sh        一键端到端复现
```

## 两种数据格式

- **旧格式 v1**：每行一个扁平 JSON（JSON-Lines），无信封、无校验和。
- **新格式 v2**：长度前缀帧 `<len>\n<envelope-json>\n`，信封内含负载的
  sha256 `checksum`、`schema`、`batch_id`。

解析器只用结构特征自动判别格式；末帧/末行不完整时显式返回
`ErrTruncated`，而不是静默丢弃。

## 状态机与“第一个错误状态”

状态按固定顺序排列（`model.StateRank`）：

```
RECEIVED -> PARSED -> [TRUNCATED -> RECOVERED] -> PERMISSION_CHECKED
        -> RISK_SCORED -> BLOCKED | ACCEPTED | REJECTED
```

错误状态为 `TRUNCATED / BLOCKED / REJECTED`。每条记录一旦首次进入错误状态，
就把该状态（含序号、原因、输入哈希）写入 `first_errors` 表。报告按状态序位
指出**第一个错误状态**，而不是只给一个汇总分数。

## 四维证据绑定

每次状态转移同时持久化：

| 维度 | 字段 | 含义 |
| --- | --- | --- |
| 攻击输入 | `attack_input` | `package@version`，另存原始字节与 `input_hash`(sha256) |
| 触发位置 | `trigger_site` | `ingest.gate / recovery.gate / authz.gate / risk.gate / decision.gate` |
| 权限判断 | `permit` + `granted` | 角色策略是否允许该 `allow/deny` 请求 |
| 日志证据 | `reason` | 人类可读原因，随转移一并入库 |

权限策略：`approver/reviewer` 可 allow/deny；`ci-bot` 仅可 deny；`guest` 无权限。

## 快速开始

```bash
source ./env.sh          # 用户目录下的 Go 1.24 + clang-18/libFuzzer
go test ./...            # 单元/集成测试
./run_demo.sh            # 端到端：截断 -> 恢复 -> 重放 -> 证据
```

## libFuzzer

```bash
./fuzz/build.sh                                   # 产出 fuzz/build/riskflow_fuzz
./fuzz/build/riskflow_fuzz -max_total_time=60 \
    -artifact_prefix=fuzz/artifacts/ fuzz/corpus
```

Go 侧在安全不变量被破坏时主动 `panic`，libFuzzer 记为 `deadly signal` 并把
原始输入落为 `crash-<sha1>` artifact。固定哨兵 `POISON_RISKFLOW_INVARIANT`
可确定性演示该取证闭环（artifact 内容即攻击输入本身）。

崩溃分类（把 artifact 接回审计流程）：

```bash
./fuzz/triage.sh fuzz/artifacts/crash-<sha1>
```

脚本会输出输入的 sha256 与原始字节，并区分：
- 哨兵/不变量崩溃（harness 级，无 SQLite 写入）；
- 可解析输入（含截断）——直接走 ingest/replay/evidence，给出四维证据与首错。

## 重放正确性

`replay` 从 SQLite 中保留的原始证据重新驱动同一状态机，并把新轨迹与库存轨迹
逐条比对（状态、触发位置、原因、授权结果、输入哈希）；任何分歧立即报
`replay divergence`。`replayed_ok=true` 表示重放与历史完全一致。
