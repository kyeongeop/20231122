# mountaudit

面向“容器挂载权限”采集材料的可暂停审计流程。实现固定使用 Go、SQLite
和 libFuzzer，处理对象是未修改的 `/proc/self/mountinfo` 风格原始字节。

## 核心保证

- 三个锚点把输入切成三个扫描区间，每个区间结束都提交一个 SQLite 检查点。
- 暂停后进程可退出；`resume` 从最后完成的检查点继续，不会重复消费前半段。
- 恢复时先从 SQLite 原始 BLOB 重放已完成阶段，逐阶段比较旧/新结果 SHA-256，
  再继续处理。任何不一致都会 fail closed，并写入 `integrity_mismatch` 证据。
- 原始字节先复制到 `original.raw`（只读 `0444`），再以 BLOB 写入 SQLite；
  导入前后分别校验源文件 SHA-256。后续分析只读这两份快照。
- 发现和证据都带 UTC 时间点、绝对原始偏移 `[start,end)`、行号、片段哈希；
  JSON 报告还带原始片段转义文本。
- 资源不足时保留完整原始材料，明确记录已扫描前缀、停止偏移和降级原因；
  流水线仍产出三阶段报告，但 `analysis_complete=false`。

## 三段锚点

显式锚点行格式：

```text
#@anchor 1 label=prelude captured_at=2026-11-22T08:00:00.120Z
#@anchor 2 label=host-mounts captured_at=2026-11-22T08:00:02.340Z
#@anchor 3 label=eof captured_at=2026-11-22T08:00:05.900Z
```

三个锚点分别是三个阶段的结束边界：

1. `[0, anchor1)`：采集头、命名空间和前置材料。
2. `[anchor1, anchor2)`：第一批挂载记录。
3. `[anchor2, EOF)`：剩余记录、聚合检查和最终摘要。

锚点必须落在行首。显式锚点缺失、重复或乱序时，自动退化为按行边界的
三分之一和三分之二位置，并写入 `anchor_fallback` 证据。第三锚点通常是
EOF 前的标记行；第三阶段仍扫描到真实 EOF，`checkpoint.anchor_offset` 与
`checkpoint.end_offset` 因此可能不同。

内置样本的固定锚点为：

```text
anchor 1: offset=83  line=3
anchor 2: offset=385 line=7
anchor 3: offset=787 line=13
```

## 使用

```bash
make build

./build/mountaudit init \
  --db artifacts/run.db \
  --input testdata/original/container-mount-capture.v1.txt \
  --artifacts artifacts/originals

./build/mountaudit run --db artifacts/run.db --pause-after 1
./build/mountaudit status --db artifacts/run.db
./build/mountaudit resume --db artifacts/run.db --pause-after 2
./build/mountaudit resume --db artifacts/run.db
./build/mountaudit verify --db artifacts/run.db
./build/mountaudit report --db artifacts/run.db --format json \
  --out artifacts/report.json
```

`run` 和 `resume` 使用同一个恢复入口。`--pause-after N` 在阶段 `N` 的
检查点事务提交后返回 `status=paused`；再次执行 `resume` 会先重算并比较
所有已完成阶段，再继续到下一阶段。

`extract-original` 可导出 SQLite 中的原始 BLOB：

```bash
./build/mountaudit extract-original --db artifacts/run.db --out /tmp/original.raw
```

## 证据字段

`report --format json` 的关键字段：

- `anchors[]`：`offset`、`line`、`captured_at`、`explicit`。
- `checkpoints[]`：`started_at`、`finished_at`、`start_offset`、`end_offset`、
  `anchor_offset`、`segment_sha256`、`result_sha256`、`degraded`。
- `findings[]`：`observed_at`、`start_offset`、`end_offset`、`line`、
  `raw_excerpt`、`raw_sha256`。
- `evidence[]`：`captured_at`、绝对偏移、片段 SHA-256 和结构化 `detail`。
- `comparisons[]`：`compared_at`、`prior_sha256`、`current_sha256`、
  `equal`，包括阶段重放和最终摘要比较。
- `original`：源路径、不可变快照路径、大小、SHA-256、权限模式。

SQLite 主要表：

```text
runs, anchors, checkpoints, records, findings, evidence, comparisons
```

阶段行、发现、证据、检查点和 `runs.next_stage` 在同一个 SQLite 事务中提交。
进程中断只会留下完整检查点或回滚到上一检查点。

## 资源不足和降级

- `--max-input-bytes`：导入硬上限；超过时拒绝创建不完整快照。
- `--max-scan-bytes`：分析预算。超过时只分析前缀，完整 BLOB 仍保留。
- `--max-records`：累计解析记录上限。达到后停止新增记录。

扫描预算或记录配额触发时，流程仍完成三个阶段并生成最终摘要，但：

- `run.status=degraded`；
- `summary.pipeline_complete=true`、`summary.analysis_complete=false`；
- 写入 `resource_scan_budget`、`resource_record_quota` 等证据；
- 证据与检查点给出实际扫描终点、停止偏移和片段哈希。

显式锚点回退、原始文件快照缺失也有独立降级证据，绝不静默继续。

## 构建与测试

依赖：

- Go 1.24+
- CGO 和 C 编译器（SQLite 驱动）
- Clang/libFuzzer（仅 fuzz target）

```bash
go mod download
make build
make test
scripts/acceptance.sh
```

验收脚本会执行两次暂停、恢复、最终校验、JSON 报告和资源降级场景，并断言
锚点偏移、检查点时间、发现原始偏移、比较结果及源文件哈希不变。

最近一次验收：

```text
acceptance_dir=artifacts/acceptance/final
original_sha256=ec54775835229f9dab1ae713fd503f771b28abef58890912e32207d0246d674b
```

具体检查点证据：

| stage | raw range | anchor | started_at | finished_at | result_sha256 |
|---|---|---|---|---|---|
| 1 | `[0,83)` | `83`/line 3 | `2026-11-22T09:07:49.293051805Z` | `2026-11-22T09:07:49.293053217Z` | `78f4cbf84307a0cc0aaae1aaeccbd2de4c34d73d948b4a8286d02ce717c98d57` |
| 2 | `[83,385)` | `385`/line 7 | `2026-11-22T09:07:49.302283155Z` | `2026-11-22T09:07:49.302344673Z` | `8529166c44ed919829853a11772fc9d441caf71a50244f485d9b188c36344f40` |
| 3 | `[385,845)` | `787`/line 13 | `2026-11-22T09:07:49.312341496Z` | `2026-11-22T09:07:49.31241912Z` | `1a0d96fdb12a5620e5af240f6a8a74687a72c1ba502729ac05fc57b9082b403d` |

关键发现 `container_socket_mount` 的原始区间为 `[507,573)`、line 9，
观测时间 `2026-11-22T09:07:49.31241912Z`。阶段 1 的暂停后重放比较发生在
`2026-11-22T09:07:49.299753479Z`，最终摘要比较发生在
`2026-11-22T09:07:49.323331103Z`，最终摘要为
`8f52fd8365d596e0c3f536c80ec15950b3673496c90a3300134734fa4d6da387`。

降级验收把扫描预算设为 420 字节、记录配额设为 2：实际扫描 `[0,420)`，
记录停止偏移为 `316`，`resource_scan_budget` 时间为
`2026-11-22T09:07:49.375813303Z`，`resource_record_quota` 时间为
`2026-11-22T09:07:49.378808676Z`。

## libFuzzer

Go 包以 `c-archive` 形式暴露 `MTAFuzz`，C++ 入口实现
`LLVMFuzzerTestOneInput`。Go 侧使用官方 libFuzzer 覆盖率插桩：

```bash
make fuzz-build
make fuzz-smoke
```

等价的本地工具链参数：

```bash
export PATH=/path/to/go/bin:/path/to/llvm/bin:$PATH
export LD_LIBRARY_PATH=/path/to/llvm/lib:$LD_LIBRARY_PATH
make fuzz-smoke CLANG=clang++ LLVM_LIB=/path/to/llvm/lib
```

Makefile 使用：

```text
-tags=libfuzzer
-gcflags=all=-d=libfuzzer
-fsanitize=fuzzer
```

一次 1000 次运行的验证覆盖了 Go 解析路径并达到 `cov: 964`。模糊测试语料
写入 `build/corpus/`，不会触碰 `testdata/original/`。
