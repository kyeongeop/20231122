# JSON 深层嵌套限制：可复核流程

本流程围绕一条**被截断的深层嵌套攻击记录**，在两个版本快照（旧格式 v1、
新格式 v2）中复现、拦截并留存证据。每个对象的处理结果都可在 SQLite
证据库中逐行复核：**攻击输入 → 触发位置 → 权限判断 → 日志证据**。

## 技术栈

- Go（迭代式深度受限 JSON 校验器，不递归，攻击输入无法撑爆栈）
- libFuzzer 风格的 Go 原生模糊测试（`testing.F`，覆盖引导）
- SQLite（`modernc.org/sqlite`，纯 Go 驱动）作为证据库

## 流程步骤

1. **输入**：JSONL 快照，每行一个对象。
   - `testdata/snapshot_v1.jsonl`：旧格式 `{"id","subject","action","payload"}`
   - `testdata/snapshot_v2.jsonl`：新格式 `{"version":2,"record_id","principal","op","body"}`
   - 两个快照的第 2 行是同一条攻击记录（rec-666）：约 5000 层 `{"a":`
     嵌套且被截断（无闭合括号）。
2. **深度校验**（`internal/depthjson`）：超过 `-max-depth`（默认 128）即
   在触发点停止，记录 `offset / depth / JSON path`。
3. **格式归一化**（`internal/record`）：自动识别 v1/v2 并归一为统一记录，
   两种格式走同一条权限策略。
4. **权限判断**：解析失败 → `deny:unparseable`；动作不在允许列表
   （read/write）→ `deny:policy`；否则 `allow`。
5. **证据留存**（`internal/evidence`）：每个对象一行，含输入 sha256、
   输入头部摘录、触发类型与位置、权限决定、处理日志原文。
6. **异常续跑**：单行失败只影响该行，隔离后继续处理其余对象。
7. **临时状态清理**：被拒输入的完整副本在运行期间放在临时隔离目录，
   运行结束（`defer`）整体删除并验证；关键证据（哈希+摘录+日志）已
   持久化在 SQLite 中，不随临时目录丢失。

## 复现与复核

```sh
# 跑完整流程，输出复核报告（证据写入 evidence.db）
go run ./cmd/jsondepth-review -db evidence.db \
    testdata/snapshot_v1.jsonl testdata/snapshot_v2.jsonl

# 直接查证据库复核
sqlite3 evidence.db 'SELECT snapshot,line_no,trigger,location,decision FROM evidence;'

# 单元测试（含端到端：异常续跑 + 清理验证）
go test ./...

# libFuzzer 模糊测试
go test -fuzz=FuzzValidate -fuzztime=30s ./internal/depthjson/
```

## 证据链对应关系（预期结果）

| 快照：行 | 记录 | 触发 | 权限判断 | 说明 |
|---|---|---|---|---|
| snapshot_v1:2 | rec-666 | depth_exceeded @ offset=698 depth=128 | deny:unparseable | 旧格式攻击记录 |
| snapshot_v2:2 | rec-666 | depth_exceeded @ offset=712 depth=128 | deny:unparseable | 新格式同一攻击记录 |
| snapshot_v1:3 | rec-002 | ok | deny:policy | 动作 delete 不在允许列表 |
| 其余各行 | rec-001/003/101/102 | ok | allow | 正常对象，异常后仍被处理 |
