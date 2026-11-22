# GraphQL 查询深度：可回放实验

本仓库实现一个固定技术栈的可回放实验：**Go + libFuzzer + SQLite**。
实验用 libFuzzer 生成一条超过深度上限的 GraphQL 记录，将该记录截断后运行，
再用“恢复缺失后缀”的记录做一次对照重放。每个阶段都写入 SQLite，
包括输入、状态迁移、结果、错误与哈希链。

判定标准不是总分，而是**首个错误状态**：

| 场景 | 首个错误状态 | 解读 |
|---|---|---|
| 截断记录 | `seq=3 stage=syntax code=UNCLOSED_DELIMITER` | 语法阶段首先发现括号未闭合 |
| 恢复后的对照 | `seq=5 stage=policy code=DEPTH_LIMIT_EXCEEDED` | 恢复后语法通过，深度 `5 > 4` |
| 顺序改变 | `seq=2 stage=replay_order code=STEP_OUT_OF_ORDER` | 第 2 个位置期望 seq 2，实际收到 seq 3 |
| 重复提交 | `seq=2 stage=submission code=DUPLICATE_STEP` | seq 2 已接受，重复提交被拒绝 |

`seq=4` 和 `seq=5` 在截断运行中也会报前置条件错误，但报告始终把
`seq=3` 标成首个错误，不做“错误总数”或分数聚合。

## 快速复现

```bash
make test
make experiment
make verify
```

`make experiment` 会：

1. 将 Go 代码编译为 `c-archive`，用 Clang 和 libFuzzer 链接出 fuzz 二进制。
2. 执行 libFuzzer。种子查询深度为 5，策略上限为 4，因此产生崩溃 artifact。
3. 从 artifact 自动选择截断点，构造截断记录与恢复记录。
4. 运行截断记录和恢复对照，将两套 5 阶段事件写入 SQLite。
5. 执行正常重放、换序重放和重复提交检查。
6. 生成 JSON/Markdown 报告与 SHA-256 artifact 清单。

## 技术实现

- **Go**：`internal/graphql` 是确定性的五阶段分析器：
  `ingest -> tokenize -> syntax -> depth -> policy`。
- **libFuzzer**：`fuzz/libfuzzer` 是 `LLVMFuzzerTestOneInput` 导出目标。
  `scripts/build_fuzzer.sh` 先 `go build -buildmode=c-archive`，再由
  `clang -fsanitize=fuzzer` 链接。目标在“语法完整且深度超限”时 `abort()`，
  libFuzzer 将输入保存为崩溃 artifact。
- **SQLite**：`internal/store` 用 Go cgo 调用系统 `libsqlite3.so.0`。
  `dlopen` 方式避免依赖 SQLite 开发头或 `libsqlite3.so` 符号链接。

SQLite 中的核心表：

| 表 | 内容 |
|---|---|
| `records` | 原始、截断、恢复字节，截断偏移，缺失后缀，文件哈希 |
| `runs` | 场景、来源运行、状态、首个错误、最终状态 |
| `steps` | 每一步的输入、前后状态、结果、错误、前序哈希、事件哈希 |
| `submissions` | 每次提交的接受/拒绝决策及错误 |
| `checks` | 普通重放、恢复重放、换序、重复提交的首错证据 |

`steps.entry_hash = SHA256(prev_hash + "\n" + canonical(step))`。
两个正常运行的 10 个步骤形成两条独立哈希链；换序重放会在
`prev_hash`/`seq` 校验处指出首个异常状态。

## 证据文件

运行后 `artifacts/` 包含：

- `evidence.sqlite`：完整事件、提交审计和检查记录。
- `report.json`：机器可读报告，含每个步骤的完整输入/状态/结果。
- `report.md`：人工阅读版，首错位于开头。
- `manifest.sha256`：所有证据文件的内容哈希。
- `fuzzer/seed.graphql`：libFuzzer 种子。
- `fuzzer/crash.graphql`：libFuzzer 实际保存的崩溃 artifact。
- `fuzzer/libfuzzer.log`：libFuzzer 启动、信号、artifact 路径和统计。
- `records/fuzzer-crash.graphql`：实验使用的原始记录副本。
- `records/truncated.graphql`：偏移 40 处的截断记录。
- `records/recovered.graphql`：恢复后记录，字节级等于原始记录。
- `records/omitted-suffix.bin`：用于恢复的 27 字节后缀。
- `records/record.json`：截断/恢复元数据。

`make verify` 会重新打开 SQLite，检查：

- `PRAGMA integrity_check` 与外键。
- 两条事件的序号、哈希链和每步非空证据。
- 运行级首错：截断 `seq=3/syntax`，恢复 `seq=5/policy`。
- 检查级首错：乱序 `seq=2/STEP_OUT_OF_ORDER`，重复 `seq=2/DUPLICATE_STEP`。
- 提交审计：10 次接受、1 次重复拒绝。
- `manifest.sha256` 中每个文件的内容哈希。

当前关键哈希：

```text
原始/恢复记录  a1885b3e5012e1239bbf3e5d353f5347ac12d91b84ca2af5d45ccbb8b7eee075
截断记录       2c6d612d1aebc78b93df9786226c30a5337f1d9c444436310c3e997a0929e8b1
```

## 设计说明

截断点不是手写常量，而是由程序扫描 fuzzer artifact：选择最接近 60% 位置、
且首错稳定落在 `syntax/UNCLOSED_DELIMITER` 的字节偏移。本次选择偏移 40。
恢复时只拼接原始记录在偏移 40 之后的后缀，因此恢复哈希与原始哈希一致，
排除“重新构造了另一条查询”的可能。

分析器面向本实验的深度检查，不是完整 GraphQL 规范实现：它识别名称、字符串、
注释、括号和字段嵌套，支持本实验所需的 operation/selection-set 结构。
生产接入时应替换为完整解析器，但事件模型、哈希链、首错定位和重放检查可直接复用。

完整实验输出请直接查看 `artifacts/report.md` 和 `artifacts/report.json`。
