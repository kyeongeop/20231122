# 解析器整数溢出审计（重建）

固定技术栈：**Go + libFuzzer(clang/ASan/UBSan) + SQLite**。

本项目从零重建一次“解析器整数溢出审计”的完整处理过程：给定整数长度、
偏移字段和解析状态，用三段锚点构造异常场景，把攻击输入、触发位置、权限
判断和日志证据一一对应，并覆盖空输入与超大输入，同时保留一份未修改的
原始材料。

## 线协议与输入

小端长度前缀二进制帧（见 `internal/parser/format.go`）：

```
magic "PF01" | uint32 record_count | record[record_count]
record = uint8 tag | uint32 length | uint32 offset        // 9 字节头
```

解析状态 `ParseState` 记录游标、剩余预算、锚点命中位置与回绕证据。

## 三段锚点

| 锚点 | 触发位置 | 攻击字段 | 原始偏移 | 回绕证据 |
|------|----------|----------|---------:|----------|
| `A1:count*9` | 头表宽度乘法 | record_count | 4 | `0x20000000*9 -> 0x20000000` |
| `A2:offset+length` | 终点加法 | offset/length | 13 | `0xFFFFFFF0+0x20 -> 0x10` |
| `A3:cursor+length` | 游标推进 | cursor/length | 9 | `8+0xFFFFFFF9 -> 0x01` |

另有两个边界场景：`CASE-EMPTY`（0 字节，失败闭合）与 `CASE-OVERSIZE`
（16 MiB 帧但声明 4 GiB 载荷，`8+0xFFFFFFFF -> 7`）。

## 双实现对照

- `internal/parser/vulnerable.go`：保留历史无检查 uint32 运算，记录实际回绕值。
- `internal/parser/hardened.go`：每个锚点显式 `add32/mul32` 溢出守卫，越界即拒绝。
- `internal/audit/permission.go`：权限闸门，非信任输入的回绕运算一律 `DENY`。

## 证据链

- 攻击输入：`evidence/corpus/CASE-*.bin`
- 未修改原始材料（只读 0444 快照）：`evidence/original/`
- 哈希清单：`evidence/reports/SHA256SUMS`
- 结构化日志：`evidence/reports/audit.log`
- SQLite 证据库：`evidence/audit.db`（表 `evidence` / `permission_decisions` / `anchor_hits`）
- 验收报告（含具体 UTC 时间点与原始偏移）：`evidence/reports/ACCEPTANCE.md`
- libFuzzer 复现与模糊测试日志：`evidence/crashers/`

## 复现

需要 Go（1.26，构建时自动拉取工具链）与带 libFuzzer 的 clang。一键复现：

```bash
./scripts/reproduce.sh
```

分步：

```bash
go test ./...                         # 单元测试，钉住三锚点行为
go run ./cmd/audit -base .            # 跑审计并写 SQLite
go run ./cmd/query -base .            # 回读证据链
go run ./cmd/report -base .           # 生成 ACCEPTANCE.md
(cd fuzz && ./build.sh && ./run.sh)   # libFuzzer 60s，零崩溃为通过
```
