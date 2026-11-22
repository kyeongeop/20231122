# 整数截断污点传播证据实验

本仓库重建了一条可执行、可持久化、可独立复核的“整数截断污点传播”处理链：

- 输入：整数污点源、算术操作序列、边界值、两台设备时钟。
- 引擎：Go 实现 64 位算术、8/16/32/64 位截断、污点路径、边界越界和权限差异判断。
- 证据：攻击输入、触发位置、权限判断、四段因果日志和时钟异常一一关联。
- 存储：SQLite 保存规范化结果、明细行和完整输入证据。
- 导出：JSONL 记录带自校验哈希；完整输入可由同事重放并比对结果。
- 模糊测试：Go `c-archive` + Go 编译器 libFuzzer 覆盖插桩，由 libFuzzer 驱动。

`artifacts/` 已包含一次生成结果，可直接复核。

## 样例结论

样例 `testdata/cases/unsynced-truncation.json`：

| 项目 | 值 |
|---|---|
| 污点源 | `request.privilege_mask = 4294967295 (0xffffffff)` |
| 算术 | `+8`，得到 `4294967303 (0x1_00000007)` |
| 截断 | `int32`，得到 `7` |
| 边界 | `[0, 2147483647]`，截断前越界 |
| 触发点 | `internal/taint/ops.go:applyTruncation`，操作 `seq=2` |
| 基线权限 | `deny`（64 位检查值为 `4294967303`，不等同令牌 `7`） |
| 实际权限 | `allow`（截断后值为 `7`） |
| 结论 | `mismatch=true`、`tainted_escalation=true` |
| 时钟异常 | `edge-b` 比 `edge-a` 慢 `300000 ms`，负向墙钟差 |

该权限模型刻意模拟“宽类型校验、窄类型使用”的令牌比较缺陷，只用于验证污点传播与证据链，不是推荐的真实鉴权实现。

## 快速开始

要求：

- Go 1.26 或更高版本。
- SQLite 由纯 Go 驱动 `modernc.org/sqlite` 访问，无需系统 SQLite 开发头文件。
- 运行 libFuzzer 需要 clang/Clang++（包含 compiler-rt 的 fuzzer 运行库）。

```bash
make test
make demo
make verify
```

`make demo` 会生成：

```text
artifacts/evidence.sqlite
artifacts/runs/run-000001.json ... run-000004.json
artifacts/export/records.jsonl
artifacts/export/evidence.jsonl
artifacts/export/manifest.json
artifacts/export/README.txt
```

单次运行也可以直接使用 stdin，空 stdin 会被当作空输入并保存拒绝证据：

```bash
go run ./cmd/taintlab run \
  --db artifacts/evidence.sqlite \
  --input testdata/cases/unsynced-truncation.json \
  --created-at 2026-11-22T04:00:00Z

printf '' | go run ./cmd/taintlab run --db artifacts/evidence.sqlite
```

## 处理流程

1. 以流式方式读取输入，计算完整字节数与 SHA-256；最多保留前 256 字节预览。
2. 输入大于 `64 KiB` 时直接记录 `oversized`，不再分配完整输入或解析 JSON。
3. 空输入记录 `empty`；JSON 损坏记录 `malformed`；两者都保留哈希、大小、预览和拒绝原因。
4. 合法输入最多允许 256 个操作。引擎按输入顺序执行，不重排操作。
5. 每个操作的污点状态、前后值、是否改变、是否 64 位回绕和代码位置进入 `taint_path`。
6. 第一次“污点值经过截断”的操作成为 `trigger`，同时记录是否越过输入边界。
7. 权限引擎分别计算截断前检查值 `check_value` 和最终有效值 `effective_value`。
8. 生成 `attack_input -> trigger_location -> permission_decision -> log_evidence` 四段日志。
9. 使用 `causal_order/ordinal` 排序，不使用两台设备的 `wall_time` 排序。
10. 对输入、触发、权限、时钟异常和事件哈希做证据摘要。

## 空输入与超大输入

空输入：

- `status=empty`
- `input.size_bytes=0`
- `input.sha256=e3b0c442...b855`
- `permission.decision=deny`
- 关键证据保留空输入的哈希与拒绝诊断。

超大输入：

- 阈值固定为 `65536` 字节。
- `status=oversized`，`input.raw_complete=false`，`input.raw_hex=""`。
- 完整 SHA-256 和原始字节数仍然保留，用于证明实际收到了哪些字节。
- 仅保留前 256 字节的十六进制预览，避免超大输入拖垮内存或 SQLite。
- CLI 和 `ExecuteReader` 采用流式消费，不会把超大文件整体载入内存。

## 双设备时钟异常

样例中：

- `edge-a`：`2026-11-22T12:00:00+08:00`，单调钟 `5000000 ns`。
- `edge-b`：`2026-11-22T11:55:00+08:00`，单调钟 `9000000000 ns`。
- 因果顺序明确为 `edge-a` 上的攻击输入先于 `edge-b` 上的触发和权限判断。
- 但 `edge-b` 的墙钟早于 `edge-a`，得到 `skew_ms=-300000` 和 `wall_regression=true`。
- 因此复核时必须按 `causal_order` 阅读，不能按 `wall_time` 排序。

事件序列固定为：

| ordinal | kind | device | 作用 |
|---|---|---|---|
| 1 | `attack_input` | `edge-a` | 绑定原始输入摘要、污点源和操作数 |
| 2 | `trigger_location` | `edge-b` | 绑定操作序号、代码位置、截断前后值 |
| 3 | `permission_decision` | `edge-b` | 绑定基线/实际权限和升级标记 |
| 4 | `log_evidence` | `edge-b` | 封存前三段事件的哈希 |

## SQLite 与重载

`runs` 保存规范化结果 JSON 及其哈希；`operations`、`taint_steps`、`evidence_events`、`key_evidence`、`diagnostics` 保存有序明细。

重载时执行三类校验：

1. `result_json` 字节哈希必须等于 `result_sha256`。
2. 反序列化后重新编码的规范化 JSON 必须与原始字节完全一致，字段顺序不能变化。
3. 明细行按 `ordinal` 读取后必须与结果 JSON 中的数组逐字段一致，且序号从 1 连续递增。

```bash
go run ./cmd/taintlab show --db artifacts/evidence.sqlite --run 1
go run ./cmd/taintlab verify-db --db artifacts/evidence.sqlite
```

常用查询：

```sql
SELECT run_id, case_id, status, decision, trigger_detected,
       tainted_escalation, clock_skew_ms, result_sha256
FROM runs ORDER BY run_id ASC;

SELECT run_id, ordinal, event_id, device_id, kind, causal_order, wall_time
FROM evidence_events ORDER BY run_id ASC, ordinal ASC;

SELECT run_id, ordinal, seq, kind, before_value, after_value, tainted
FROM taint_steps ORDER BY run_id ASC, ordinal ASC;
```

## 导出与独立复核

导出包不依赖 SQLite 或生产端内存：

```bash
go run ./cmd/taintlab export \
  --db artifacts/evidence.sqlite \
  --out artifacts/export \
  --exported-at 2026-11-22T05:00:00Z

go run ./cmd/taintlab verify-export --dir artifacts/export
```

复核器会检查：

- `manifest.json` 中每个文件的字节数和 SHA-256。
- `records.jsonl` 的字段顺序、未知字段、记录哈希和结果哈希。
- `evidence.jsonl` 与结果内事件的逐字段一致性。
- `run_id` 升序以及事件 `ordinal/causal_order` 顺序。
- `input.raw_hex` 的字节数、哈希和完整结果重放一致性。
- 超大输入因 `raw_complete=false` 跳过重放，但仍验证完整哈希、大小和预览。

当前样例导出结果：

```json
{"verified":true,"directory":"artifacts/export","runs":4,"events":4,"replayed_runs":3,"incomplete_runs":1}
```

同事只需拿到 `artifacts/export/` 和构建好的 `taintlab`，即可执行上述复核命令，不需要信任数据库或导出方。

## libFuzzer

Go 代码通过 `-buildmode=c-archive` 导出 `LLVMFuzzerTestOneInput`，并使用 Go 编译器的 libFuzzer 覆盖插桩：

```bash
make fuzz
./fuzz/run.sh -runs=10000
```

构建关键参数：

```text
-tags=libfuzzer
-gcflags=all=-d=libfuzzer
-buildmode=c-archive
CGO_CFLAGS=-fsanitize=fuzzer
```

`fuzz/run.sh` 在临时目录中扩展语料，崩溃产物写入 `build/fuzz/artifacts/`，不会污染人工种子。人工种子包括完整攻击样例、边界值、空输入、malformed 输入和 66 KiB 超大输入；`-max_len=131072` 可继续探索超过 64 KiB 的拒绝路径。

另有 Go 原生回归入口：

```bash
go test ./internal/taint -run=^$ -fuzz=FuzzExecute -fuzztime=30s
```

## 目录

```text
cmd/taintlab/           CLI
internal/model/         固定字段模型
internal/taint/         解析、算术、截断、污点、权限、证据
internal/store/         SQLite 保存/重载/顺序校验
internal/export/        自校验导出与重放复核
internal/invariants/    不变量检查
fuzz/                   Go c-archive 入口、libFuzzer 脚本与种子
testdata/cases/         人工可读攻击场景
artifacts/              样例 SQLite、单次结果和导出包
```

## 限制与边界

- 本实验只模拟一条固定宽度整数处理链，不声称覆盖所有真实 CPU 或语言运行时行为。
- 权限策略和令牌比较是为复现“截断后判定差异”设计的极简模型。
- `raw_complete=false` 的超大输入无法逐字节重放，但完整摘要、大小和预览仍可审计。
- 墙钟用于暴露设备不同步；因果关系始终由显式 `causal_order` 和事件序号表达。
- 哈希链能发现字段、顺序或内容的局部不一致；若需要防恶意生产方伪造整包，应在仓库外增加签名或可信时间戳。
- 为支持独立重放，合法输入会以十六进制保存在证据中；含密钥的输入不应直接进入本实验库。
