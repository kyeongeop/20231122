# corpusd — 可暂停的 libFuzzer 语料库处理

固定技术栈：**Go + libFuzzer + SQLite**。流程以 libFuzzer 语料文件为输入，
用两台未同步的设备时钟观察同一个模糊测试对象，支持中途暂停、SQLite
检查点恢复、恢复前后结果比对、资源不足降级，以及可独立复核的导出证据。

## 快速开始

需要 Go 1.23+；完整 libFuzzer 链接还需要带 fuzzer sanitizer 的 clang。

```sh
go test ./...
go build -o corpusctl ./cmd/corpusctl

# 不间断基线
./corpusctl run --db state.db --corpus testdata/corpus --run-id baseline

# 处理两条后暂停（退出码 3），重复同一命令即从 SQLite 恢复
./corpusctl run --db state.db --corpus testdata/corpus \
  --run-id paused --pause-after 2
./corpusctl run --db state.db --corpus testdata/corpus \
  --run-id paused --pause-after 2

# 恢复完成后自动导出
./corpusctl run --db state.db --corpus testdata/corpus \
  --run-id paused --pause-after 2 --export export-paused

./corpusctl compare --db state.db --a baseline --b paused
./corpusctl verify-export --dir export-paused
```

暂停时 CLI 返回 `3`，便于脚本循环：

```sh
while true; do
  ./corpusctl run --db state.db --corpus testdata/corpus \
    --run-id job --pause-after 100
  code=$?
  [ "$code" -eq 3 ] && continue
  [ "$code" -eq 0 ] && break
  exit "$code"
done
```

## 关键机制

- **重复对象与双时钟**：每个语料条目由 `device-a` 和 `device-b` 两个时钟
  各观察一次。`device-b` 默认快 1500ms，原始时间和偏移都保留；时间统一
  校正到 `corrected_ts_ns` 后再排序。内容以 SHA-256 作为 `object_id`，
  相同内容再次出现时写 `duplicate_of_seq` 并复用同模式的分析结果。
- **可暂停状态**：`corpus_entries` 固化语料词法顺序，`checkpoints` 固化
  cursor、已处理数量、模式、结果摘要和检查点摘要。恢复时先重载有序结果，
  与检查点 `result_digest` 比较；不一致立即失败并留下证据。
- **恢复后继续比对**：完成时从同一份不可变语料快照全量重算，逐条比较
  `record_digest` 和整体结果摘要。`comparisons` 同时保留
  `resume_restore` 与 `final_recompute` 两类结论。
- **资源不足降级**：每条输入的估算成本为 `3*size + 64KiB`。超出
  `--mem-budget` 或 `--max-input-bytes` 时，运行单调切换到
  `metadata_only` 模式，不读取内容特征，并写入
  `resource_degraded` 事件（预算、剩余、估算和原因）。降级决定可重算。
- **SQLite 可靠性**：WAL、`synchronous=FULL`、`busy_timeout`，并对
  `database is locked` 做有限重试。结果、检查点、事件和比较分别持久化。

## 命令

| 命令 | 用途 |
|------|------|
| `run` | 新建或恢复运行；暂停退出码为 `3` |
| `status` | 显示游标、最新检查点和比较结论 |
| `report` | 打印有序记录、时钟、模式、事件和比较 |
| `compare` | 比较两次运行的逐条记录摘要 |
| `export` | 写出自包含证据目录 |
| `verify-export` | 不打开 SQLite，独立校验导出目录 |

常用运行参数：

```text
--base-ts 2026-01-01T00:00:00Z   规范化起始时间
--sample-interval-ms 1000        相邻语料条目的规范时间间隔
--clock-skew-ms 1500             device-b 偏移
--mem-budget 67108864            分析内存预算（字节）
--max-input-bytes 16777216       完整分析的单输入上限
--checkpoint-every 1             每 N 条写一次检查点
--pause-after N                  本次调用处理 N 条后暂停
```

恢复时必须沿用原运行配置；修改时钟、预算、输入上限或检查点间隔会被拒绝，
以保证暂停前后结果可比。

## 证据与独立复核

`export` 产物包含：

- `records.jsonl`：按 `seq` 有序的语料对象记录；
- `checkpoints.jsonl`：检查点及状态摘要；
- `events.jsonl`：启动、暂停、恢复、降级、比较和完成事件；
- `comparisons.jsonl`：恢复前/后及最终重算比对；
- `inputs/`：输入原文快照；
- `manifest.json`：字段顺序、计数、结果摘要、文件哈希；
- `SHA256SUMS`：包含 manifest 在内的完整文件清单；
- `README.md`：同事可照做的复核步骤。

每条记录顶层字段顺序固定为：

```text
schema, record_type, run_id, seq, object_id, input_name, input_sha256,
input_bytes, observations, canonical_device, canonical_ts_ns, duplicate,
duplicate_of_seq, mode, degraded_reason, decision, analysis, evidence
```

`verify-export` 会检查字段及嵌套字段顺序、记录连续性、输入文件哈希、
`object_id` 与输入哈希关系、时钟校正算术、重复引用、检查点摘要、
比较摘要和全部文件哈希。它只读取导出目录，不需要原语料或数据库。

仓库中的 `artifacts/reference/export-resumed` 与
`artifacts/reference/export-degraded` 是最近一次验收产物：

```sh
go run ./cmd/corpusctl verify-export \
  --dir artifacts/reference/export-resumed
```

## libFuzzer

`fuzz/harness.cc` 是真实 libFuzzer 入口，Go 探针通过
`-buildmode=c-archive` 暴露为 `CorpusProbe`：

```sh
./fuzz/build.sh
SECONDS_TO_RUN=60 ./fuzz/run.sh

# 无 clang 时的等价 Go 原生 fuzz 入口
go test ./internal/probe -run '^$' -fuzz FuzzAnalyze -fuzztime 30s
```

同一探针函数既用于语料处理，也用于 fuzz 目标，避免测试实现与生产路径分叉。

## 验收

```sh
./scripts/acceptance.sh
```

脚本执行单元测试，随后验证：基线；两轮暂停/恢复；基线 vs 恢复结果一致；
低预算降级；SQLite 事件与比较；两个导出目录的独立复核；Go c-archive
构建（clang 可用时继续链接 libFuzzer）。成功标志为 `ACCEPTANCE_OK`。

`artifacts/reference/evidence.db` 保留对应 SQLite 证据，可直接查询
`results`、`checkpoints`、`events`、`comparisons` 表。
