# 路径别名冲突可回放实验

本仓库用固定技术栈 **Go + libFuzzer + SQLite** 构造一个可重复的路径别名冲突实验。实验包含一次中途取消、一个同位置取消对照、逆序提交探针和重复提交探针。每一步的输入、取消前/后状态、结果和 SHA-256 证据链都写入 SQLite。

## 实验语义

- 路径使用 `path.Clean` 规范化：`/deploy//api/` 与 `/deploy/api` 指向同一别名。
- 同一别名出现两个不同目标时进入 `conflicted`，不会静默选择目标。
- 取消操作以提交操作 ID 为键，而不是按别名批量取消。
- 精确重复操作是 `duplicate_noop`，不改变状态，也不会复活已取消候选。
- 冲突消解后，别名重新变为 `active`，只剩一个有效目标。

## 场景矩阵

| 场景 | 目的 |
|---|---|
| `primary_cancel` | 冲突提交后，在第 3 步取消绿色候选 |
| `control_cancel` | 同一第 3 步取消，但两个别名不重叠 |
| `order_swap` | 交换冲突提交顺序，取消仍按操作 ID 定位 |
| `duplicate_probe` | 冲突中、取消后、重复取消时分别精确重放 |
| `primary_cancel-replay` | 从 SQLite 中的场景 JSON 逐步回放主实验 |

场景定义在 `internal/experiment/scenarios.json`，并由 Go `embed` 打包。

## 运行

本机已有工具链时：

```bash
make all
```

仓库内提供了用户目录工具链时，Makefile 会自动使用 `.tools/go/bin/go`。也可单独执行：

```bash
make experiment          # 重建 SQLite 并跑四个场景 + 回放
make fuzz FUZZ_SECONDS=10
make report              # 导出报告、JSONL 和证据清单
make verify              # 重新校验哈希链与 SQLite 完整性
make show RUN=primary_cancel
make test
```

`make all` 的最终产物：

- `artifacts/experiment.db`：主证据库。
- `artifacts/report.md`：自动结论、人工确认和失败后续操作。
- `artifacts/report.json`：同内容的机器可读版本。
- `artifacts/evidence/runs/*.jsonl`：每次运行每一步的完整输入、状态和结果。
- `artifacts/evidence/manifest.json`：数据库、报告、日志和 corpus 的哈希清单。
- `artifacts/fuzz/fuzz.log`、`status.txt`、`corpus/`：libFuzzer 证据。

## libFuzzer 集成

Go 目标以 `c-archive` 方式导出 `PathAliasFuzzOneInput`，C 侧 `fuzz/harness.c` 提供 `LLVMFuzzerTestOneInput`。构建时必须启用 Go 的 libFuzzer 插桩：

```bash
go build -tags=libfuzzer -gcflags=all=-d=libfuzzer \
  -buildmode=c-archive -o .build/libpathalias.a ./fuzzbridge
clang -fsanitize=fuzzer ... fuzz/harness.c .build/libpathalias.a
```

每次 fuzz 输入会被解码成最多 12 个提交/取消操作，并检查：

- 每一步状态不变量；
- 相同输入重放后的状态摘要一致；
- 最终状态上再次应用全部操作不改变状态；
- SQLite 每步证据链和记录条数一致。

失败时，fuzz bridge 在 `artifacts/fuzz/` 写出 `failure-input.bin`、`failure.json` 和 `failure.db`，然后由 C harness 终止，让 libFuzzer 保存原始 crash 工件。

## SQLite 证据

主要表：

- `runs`：场景、输入摘要、最终状态摘要、解析摘要、事件链头。
- `steps`：步骤号、输入 JSON、前状态、结果、后状态、各段摘要和链式 `evidence_sha256`。
- `checks`：每个场景和跨场景自动检查。
- `replays`：回放逐字节比对结果。
- `artifacts`：外部证据文件及其摘要。

链式摘要计算为：

```text
sha256(previous_evidence || run_id || step_no ||
       input || state_before || result || state_after)
```

`make verify` 会重算全部链，并执行 `PRAGMA integrity_check` 与 `PRAGMA foreign_key_check`。

## 自动结论与人工确认

`report.md` 明确分成两段：

- **自动结论**只由 `checks`、回放、哈希链和 SQLite 完整性派生，失败即标为失败。
- **人工确认**保持 `pending`，覆盖规范化规范、冲突阻塞策略、取消键选择、重复提交契约和证据保留期限。这些是产品/合规决策，自动断言不能替代。

总体状态为 `PASS` 需要：全部场景检查通过、回放逐字节一致、证据链完整、SQLite `ok`、libFuzzer 运行且无 crash/timeout/OOM 工件。

## 失败后续操作

失败时按报告中的命令执行：

```bash
make experiment
make verify
make show RUN=primary_cancel
make fuzz FUZZ_SECONDS=30
make report
```

若存在 crash 工件，报告会给出直接复现命令：

```bash
artifacts/fuzz/pathalias_fuzzer artifacts/fuzz/crash-<hash>
```
