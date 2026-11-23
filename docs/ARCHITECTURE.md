# 复核流程设计说明

## 1. 目标

把 OAuth 回调校验做成**可复核流程**：每条输入都能把
「攻击输入 → 触发位置 → 权限判断 → 日志证据」四类信息通过同一个
`case_id` 与 `sha256(input)` 串联起来，并且自动结论与人工确认分开存放、分开呈现。

## 2. 两种回调格式

| 维度 | 旧格式 (legacy) | 新格式 (v2) |
|---|---|---|
| Content-Type | `application/x-www-form-urlencoded` | `application/json` |
| 编码 | query/form 编码 | JSON 对象 |
| 字段别名 | `redirect_url`、`resp_mode` 归一化 | 标准 `redirect_uri`、`response_mode` |
| 特有检查 | 参数污染（重复参数）检测 | `iss` 白名单、`response_mode` 限制、`token_hash` 完整性 |
| 嗅探 | 内容以 `{` 开头且无 Content-Type 时按 JSON 处理 | 同左 |

两种格式解析后统一映射到 `callback.Callback`，下游校验流水线完全共用，
避免规则在两套实现间分叉。

## 3. 校验流水线与触发位置

顺序固定，任何一步拒绝即短路，但已产生的事件链全部保留：

1. `cancellation`：`error` 参数存在 → 判定 `CANCELLED`，不换码；
   同时核对服务端 state 上的 `cancelled` 标记，标记缺失记为 `INDETERMINATE` 事件。
2. `parse`：HTTP 参数污染（重复参数）→ `DENY / parse.duplicate_parameter`。
3. `state_binding`：无绑定 → `state.unbound`；已消费 → `state.replayed`。
4. `redirect_uri`：精确白名单匹配 + 会话绑定一致性。
5. `authorization_code`：存在性与长度上限。
6. `issuer` / `response_mode` / `signature`：仅 v2 格式执行。
7. `permission`：全部通过才记录 `rule.allow.all_checks_passed`。

## 4. 中途取消的处理

取消既不是攻击放行也不是普通拒绝，而是独立结论 `CANCELLED`：

- `C03-cancel-midflow`：服务端 state 带 `cancelled=true`，事件链含确认事件。
- `C04-cancel-orphan`：错误回调存在但没有服务端取消标记，
  自动结论仍为 `CANCELLED`，但事件链出现 `INDETERMINATE`，
  报告要求人工回溯会话日志（演示中复核人驳回并转安全团队）。

## 5. 证据模型（SQLite）

| 表 | 作用 | 不可变性 |
|---|---|---|
| `cases` | 原始字节、哈希、格式、来源 | 主键冲突返回 `ErrCaseExists`，不可覆盖 |
| `events` | 每个检查点一条事件，含原因码与证据哈希 | 仅追加 |
| `decisions` | 自动结论、触发位置、权限规则 | 仅插入 |
| `reviews` | 人工确认/驳回、复核人、备注 | 可更新，与自动结论物理分表 |

解析失败的输入同样入库（`RecordParseFailure`），不会因为畸形而丢证据。

## 6. libFuzzer 集成

Go 无法直接暴露 libFuzzer 入口，采用两段式桥接：

1. `go build -buildmode=c-archive` 把 `fuzz/` 编译成 `libfuzz.a`，
   导出 `Fuzz(data, size)`。
2. `fuzz/fuzzentry.c` 实现 `LLVMFuzzerTestOneInput` 并与
   `libclang_rt.fuzzer-x86_64.a` 链接。

模糊测试不变量：**任意输入都不允许 panic，且所有可解析输入必须产生非空结论**。
Go 侧 panic 会被 libFuzzer 捕获为 deadly signal 并落盘崩溃样本。
种子语料（`fuzz/seed/`，14 条精选用例）与运行期变异语料
（`fuzz/runtime-corpus/`）分离，崩溃样本写入 `fuzz/crashers/`。

## 7. 复核闭环

```
seed 语料 --replay--> SQLite 证据库 --report--> review-report.md（自动结论分区）
                                    ^
人工 --review --confirm/--reject----┘  回填后重新 report（人工确认分区）
```

失败（`DENY` / `CANCELLED` / `INDETERMINATE`）在报告第三节给出
按结论类型区分的可执行后续操作与具体 CLI 命令。
