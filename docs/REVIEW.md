# 同事独立复核手册

本手册不依赖原处理进程，只需要导出包（可选：SQLite 证据库与本仓库代码）。

## 1. 产物清单

一次完整演示会在 `artifacts/review/` 下生成四组运行：

| 目录 | 含义 |
| --- | --- |
| `baseline/` | 一次性完整运行（对照基准） |
| `paused/` | 每段 3 个事件的预算暂停 + 恢复运行 |
| `fault/` | 第 2 段前注入确定性故障后的恢复运行 |
| `degraded/` | issue 缓存上限为 1 的内存压力降级运行 |

每组包含 `evidence.sqlite` 与 `bundle/` 导出包；`fixture.json` 是输入流。

## 2. 只看导出包（无需数据库）

```
replayctl verify --bundle artifacts/review/paused/bundle
```

该命令重算 `manifest.json` 中每个文件的 SHA-256 与行数。校验失败会明确指出
文件名与期望值/实际值。

逐行比较两次运行：

```
replayctl compare \
  --before artifacts/review/baseline/bundle \
  --after  artifacts/review/paused/bundle
```

比较是字段值 + 顺序的严格比较，任何重放判定或缺口顺序差异都会报错并打印
第一条不一致记录。

## 3. 手工抽查

- `events.jsonl` 每行带 `raw_sha256`，可对照 `fixture.json` 中的原始记录。
- `decisions.jsonl` 中 `outcome=replay` 即关键证据；`reason` 给出首次消费
  序列号与重用次数，`age_ms/window_ms` 可独立复算。
- `gaps.jsonl` 的 `missing_from/missing_to` 是设备内缺失序列号区间；
  `clock_gap` 条目给出参考时钟跳变量与阈值。
- `checkpoints.jsonl` 的 `next_input_pos` 必须单调不减，且最终等于事件总数。

## 4. 从 SQLite 独立复核

证据库是普通 SQLite 文件，可用任意 SQLite 客户端打开。表结构见
`internal/store/schema.go`，关键查询：

```sql
SELECT seq, device_id, outcome, severity, reason FROM decisions ORDER BY id;
SELECT kind, device_id, missing_from, missing_to FROM gaps ORDER BY id;
SELECT segment_id, reason, paused, next_input_pos, degraded FROM checkpoints;
SELECT COUNT(*) FROM decisions WHERE outcome = 'replay';
```

## 5. 重新载入的字段与顺序保证

- JSONL 按结构体字段固定顺序输出，读取使用泛型 `LoadJSONL[T]`，
  不经过 map 反序列化，字段顺序与数值类型稳定。
- 集成测试会把 SQLite 投影与重新载入的 JSONL 行再做一次严格比较
  （`TestPauseResumeExportAndReview`）。
- `manifest.json` 的 `files` 数组按固定顺序排列，保证 manifest 自身可复现。

## 6. 复现实验

```
make test     # 单元 + 集成测试
make fuzz     # libFuzzer 会话（默认 20000 次）
make demo     # 重新生成全部 artifacts/review 产物
```

离线环境下使用仓库内工具链时：

```
export PATH=/tmp/go/bin:/tmp/clangroot/usr/bin:$PATH
export GOPATH=/home/hj/.gopath GOPROXY=off GOSUMDB=off GOFLAGS=-mod=mod
```
