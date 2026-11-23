# 反序列化边界测试：可回放实验

本仓库实现一个固定技术栈的可回放实验：**Go** 负责二进制反序列化与场景编排，**libFuzzer** 以 C harness 驱动 Go 导出的解析入口，**SQLite** 保存逐步输入、状态、结果、已提交记录和自动检查。实验包含一次目标中途取消和一次对照中途取消，并验证解析/提交顺序改变与重复提交。

## 快速运行

```bash
./scripts/run-all.sh
./build/dfexp verify-manifest --dir artifacts/evidence
```

首次运行若缺少工具链，脚本会调用 `scripts/bootstrap.sh`，在 `.toolchain/` 下解包用户态 Go、Clang/libFuzzer 与 SQLite 头文件，不需要 `sudo`。默认 fuzz 时长为 10 秒，可用 `FUZZ_SECONDS=30 ./scripts/run-all.sh` 调整。

本次已生成的结果：

- 自动检查 **PASS**：23 项通过，0 项失败。
- libFuzzer 执行约 **1,370 万次**，退出码 0，崩溃/OOM/超时产物 0 个。
- 保留语料 18 个，逐文件回放，0 panic，15 个产生类型化边界拒绝。
- SQLite 记录 50 个核心与 fuzz 回放步骤，另含 6 个回放运行；取消运行提交行数均为 0。
- 证据清单 72 个文件，SHA-256 全部通过。

## 实验设计

### 帧格式与边界

单帧为 `DFB1 | version | count | flags | records | crc32`，每条记录为 `id uint16 | length uint16 | UTF-8 payload`。解析器强制以下边界：

- 总输入不超过 4096 字节，记录数 1..16，单条负载 1..512 字节。
- magic、version、flags、count、id、payload 长度、truncation、trailing bytes、CRC32 全部严格校验。
- payload 必须是 UTF-8 且不含 NUL；重复 id 返回 `invalid:duplicate_id`。
- 解析成功后按 id 规范化排序，因此 wire 顺序不进入语义摘要。

### 确定性场景

| 场景 | 作用 | 期望 |
|---|---|---|
| `order-asc` | 按 id 升序提交 4 条 | 提交 4 行 |
| `order-desc` | 按 id 降序提交同一批记录 | 4 行，摘要与升序相同 |
| `cancel-target` | 接受 2 条后中途取消，再提交 2 条并尝试 commit | 取消，0 行提交 |
| `cancel-control` | 在独立运行中重复同一取消点 | 与目标取消逐步等价 |
| `duplicate-submit` | 第 3 次事件重复提交 id=2 | 拒绝 1 次，仍只提交 4 个不同 id |
| `parser-boundary` | 相反 wire 顺序、重复 id、截断帧 | 顺序摘要相等；重复/截断被类型化拒绝 |
| `fuzz-corpus` | 回放 libFuzzer 保留语料 | 每个输入都有输入哈希、状态和分类结果 |

取消逻辑位于第 2 条记录之后：后续提交记为 `rejected_after_cancel`，commit 记为 `canceled_no_commit`。审计步骤与领域记录分离写入，因此取消后的 0 行提交不会抹掉 6 个取消步骤。

### 可回放性

- 每个步骤写入 `steps` 表，包含 `input_sha256`、`input_json`、可选 wire `input_hex`、`state_before`、`state_after`、`outcome`、`result_json`。
- `traces/<run>.jsonl` 是逐步导出副本。
- `replay` 只读取源库中记录的 `input_json`，在新进程和新 SQLite 文件中逐事件重建，比较状态摘要、结果序列、记录数和输入哈希。
- `parser_order_equivalence`、`db_order_equivalence`、`cancel_pair_equivalent`、`replay_core_equivalence` 分别覆盖解析顺序、提交顺序、取消对照和重建一致性。

## 报告与失败处理

报告明确分为两部分：

- `artifacts/report.md`：自动结论 + 人工确认 + 后续操作。
- `artifacts/automated-conclusions.json`：仅自动判定和 follow-up，不混入人工状态。
- `artifacts/manual-confirmation.md`：保持 `PENDING` 的人工检查单，不自动勾选。

任一自动检查失败时，报告会生成 `follow_ups`，每个失败项带优先级、原因和可直接执行的命令。例如：

```bash
make fuzz && ./build/dfexp ingest-fuzz --db artifacts/evidence/experiment.db \
  --corpus artifacts/evidence/fuzz/corpus --out artifacts/evidence
./build/dfexp replay \
  --source artifacts/evidence/experiment.db --dest artifacts/evidence/replay.db \
  --out artifacts/evidence
```

常用人工核对命令：

```bash
./build/dfexp query --db artifacts/evidence/experiment.db \
  --sql "SELECT seq,action,outcome,json_extract(result_json,'$.accepted_before_cancel') FROM steps WHERE run_id='cancel-target' ORDER BY seq;"
./build/dfexp query --db artifacts/evidence/experiment.db \
  --sql "SELECT run_id,status,state_digest FROM runs WHERE run_id IN ('order-asc','order-desc');"
./build/dfexp query --db artifacts/evidence/experiment.db \
  --sql "SELECT record_id,COUNT(*) FROM records WHERE run_id='duplicate-submit' GROUP BY record_id;"
```

## 证据布局

```text
artifacts/
  report.md
  report.json
  automated-conclusions.json
  manual-confirmation.md
  evidence/
    experiment.db
    replay.db
    MANIFEST.sha256
    unit-tests.log
    toolchain.txt
    traces/*.jsonl
    fuzz/
      fuzzer.log
      exit_code
      seed/
      corpus/
      ingest.json
      stats.json
```

`MANIFEST.sha256` 排除自身及 SQLite `-wal/-shm`，覆盖数据库、trace、fuzzer 日志、保留语料、回放库等关键证据。`verify-manifest` 重新计算并逐项比较。

## 单独命令

```bash
source scripts/env.sh
make build
go test -v ./...
./build/dfexp run --db artifacts/evidence/experiment.db --out artifacts/evidence
./build/dfexp seed --out artifacts/evidence/fuzz/seed
make fuzz FUZZ_SECONDS=10
./build/dfexp ingest-fuzz --db artifacts/evidence/experiment.db \
  --corpus artifacts/evidence/fuzz/corpus --out artifacts/evidence
./build/dfexp fuzz-stats --db artifacts/evidence/experiment.db \
  --log artifacts/evidence/fuzz/fuzzer.log --artifacts artifacts/evidence/fuzz \
  --corpus artifacts/evidence/fuzz/corpus
./build/dfexp replay --source artifacts/evidence/experiment.db \
  --dest artifacts/evidence/replay.db --out artifacts/evidence
./build/dfexp manifest --dir artifacts/evidence
./build/dfexp report --db artifacts/evidence/experiment.db \
  --evidence artifacts/evidence --out artifacts
```

## 技术说明与限制

- libFuzzer 的 `LLVMFuzzerTestOneInput` 是 C harness，调用 Go `c-shared` 导出的 `DFParse`。Go 侧 panic 返回 2，C harness 立即 `abort()`，因此会形成 libFuzzer crash 产物。
- c-shared Go 代码没有 SanitizerCoverage 插桩；`fuzzer.log` 中的 `cov` 仅反映 C harness。输入变异仍实际进入 Go 解析器，确定性边界矩阵和 SQLite 分类回放负责补足可解释覆盖。这是刻意的真实限制，报告中不把 harness coverage 冒称为 Go 覆盖率。
- `scripts/run-all.sh` 每次把旧的 `artifacts/evidence` 移到 `artifacts/archive/`，再生成新实验，避免旧证据污染当前清单。
