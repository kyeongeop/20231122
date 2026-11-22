# serrfix

`serrfix` 是一个“错误信息敏感数据”局部修正与取证工具。它不是整条日志替换，而是按字节定位敏感片段，只替换该片段，并把原文偏移、替换后偏移、UTC 时间、运行结果和证据哈希写入 SQLite。

固定技术栈：

- Go：CLI、脱敏规则、运行编排、比较、导出与验收。
- libFuzzer：为极限参数生成独立攻击语料，C++ 目标位于 `fuzz/error_target.cpp`。
- SQLite：材料、样本、运行、跨度、事件与比较记录的单一事实源。

## 核心保证

- 初始化时把原始材料逐字节复制为只读快照，权限为 `0444`，记录 SHA-256、大小、原始 mtime 和捕获时间。
- 每个攻击样本是稳定的 `serrfix.case/v1` 对象，带材料 ID、零基原始偏移、长度、SHA-256 和极限参数。
- 每次执行都是独立 `serrfix.run/v1` 记录；可单样本重跑任意次数。
- 运行前先落 `requested` 证据；运行后原子写入结果证据；SQLite 保存完成时间、证据文件哈希和局部跨度。
- 支持 `--stop-after` 暂停和 `run --resume` 续跑；未提交的 `running` 记录会在下一次进入时标记为 `abandoned`，原请求证据仍保留。
- 比较默认取同一样本最近两次运行，输出字节差异区间并保存 `serrfix.compare/v1`。
- 导出 ZIP 包含未修改原始材料、精确样本切片、每次运行证据、脱敏输出、跨度、比较和 `SHA256SUMS`。
- `verify` / `accept` 会把验收落到具体 UTC 时间点、材料 SHA 和原始字节偏移。

已知敏感值不会写入运行证据：证据只保留敏感片段的 SHA-256、偏移、规则和替换标记。原始敏感材料仍只存在于不可变快照及其显式导出中。

## 快速开始

依赖：

- Go 1.23+
- C 编译器（`mattn/go-sqlite3` 使用 CGO 编译 SQLite）
- Clang/libFuzzer，仅在执行 `serrfix fuzz` 时需要

Ubuntu 上安装 libFuzzer：

```bash
sudo apt-get install clang libfuzzer-21-dev
```

构建和测试：

```bash
make build
make test
```

初始化样本工作区：

```bash
./dist/serrfix init \
  --workspace .serrfix \
  --original testdata/original/incident-errors.txt
```

先跑两个样本后暂停：

```bash
./dist/serrfix run --workspace .serrfix --resume --stop-after 2
./dist/serrfix list --workspace .serrfix
```

退出后重新进入并续跑：

```bash
./dist/serrfix run --workspace .serrfix --resume
```

单样本重复、比较和导出：

```bash
S=s-005-c871bea7b16a
./dist/serrfix rerun   --workspace .serrfix --sample "$S" --repeat 2
./dist/serrfix compare --workspace .serrfix --sample "$S" --json
./dist/serrfix export  --workspace .serrfix --sample "$S"
```

完整验收：

```bash
./dist/serrfix verify --workspace .serrfix --json
./dist/serrfix accept --workspace .serrfix --json
```

`accept` 在 `verify` 失败时返回非零退出码，同时仍输出完整 JSON 供归档。

## 命令

| 命令 | 作用 |
|---|---|
| `init` | 复制原始材料为只读快照，按行导入稳定样本对象 |
| `run` | 运行全部样本；`--resume` 只运行 pending/interrupted；`--stop-after` 可暂停 |
| `rerun` | 对单样本创建新的独立运行，必须指定 `--sample` |
| `list` | 查看样本、原始偏移、长度与最新状态 |
| `show` | 查看单个样本、全部运行和跨度 |
| `compare` | 比较两次运行；默认最近两次 |
| `export` | 导出单样本证据 ZIP |
| `verify` | 校验快照、偏移、时间、证据哈希与跨度边界 |
| `report` | 展示材料捕获时间、样本偏移和完整事件时间线 |
| `accept` | 组合 `verify` 与 `report` 的机器可读验收包 |
| `fuzz` | 构建并运行 libFuzzer，将生成语料封箱、导入 SQLite |

所有时间字段均为 UTC，格式为 RFC3339Nano。所有 `source_offset` 都是从材料起点或样本起点计算的零基字节偏移；`line` 从 1 开始，`column` 按字节从 1 开始。

## 样本对象与断点语义

初始材料的每一行是一个攻击样本，换行符不属于样本。样本对象示例：

```json
{
  "schema": "serrfix.case/v1",
  "sample_id": "s-005-c871bea7b16a",
  "label": "boundary-005-unicode",
  "origin": "original-lines",
  "params": {
    "max_output_bytes": 16384,
    "max_secret_bytes": 32768,
    "max_passes": 4,
    "timeout_ms": 3000,
    "repetitions": 1,
    "unicode_boundary": true,
    "allow_invalid_utf8": true,
    "preserve_prefix": true
  },
  "source": {
    "material_id": "mat-fb9570c2a271cc72",
    "offset": 498,
    "length": 103,
    "sha256": "c871bea7b16af2b08101d8346677e99e3a1f40757522d0eb280f17ccb45b390a"
  },
  "created_at": "2026-11-22T01:47:01.274505949Z",
  "rerun_command": "serrfix rerun --workspace ... --sample <sample-id>"
}
```

断点续跑规则：

1. `run --resume --stop-after N` 完成 N 次运行后写入 `run_paused` 事件并返回，不删除任何 pending 样本。
2. 再次执行 `run --resume` 时，已 `passed` 的样本跳过，pending 样本继续。
3. 如果进程在运行中被强制终止，SQLite 中会留下 `running` 行；下次进入先将其标记为 `abandoned`，再根据最新状态重跑。运行前写入的请求证据不会被覆盖或删除。
4. `failed` 样本默认不重试；需要显式使用 `run --resume --retry-failed`。

每次运行的 `attempt` 单调递增。`--repeat N` 会为同一样本产生 N 个独立运行，便于验证确定性和比较导出结果。

## libFuzzer 语料

先完成 `init`，再运行：

```bash
CLANGXX=clang++ ./dist/serrfix fuzz \
  --workspace .serrfix \
  --runs 500 \
  --max-seconds 3
```

Go 侧会执行以下步骤：

1. 把 SQLite 中已有样本写入本次 fuzz 的种子目录。
2. 使用 `clang++ -fsanitize=fuzzer,address` 编译 `fuzz/error_target.cpp`。
3. 用 `fuzz/secret.dict` 引导 `Authorization`、`password=`、URI 凭据、PEM、云密钥和 JWT 等输入形状。
4. 收集 `corpus/` 与 `artifacts/` 中的全部文件，按文件名排序，封装为带 `FILE <length> <base64-name>` 头的只读语料材料。
5. 每个文件在容器中有独立零基偏移；封装后的 SHA-256、文件和偏移写入 `manifest.json`。
6. 每个语料文件导入为新的 `serrfix.case/v1` 样本，之后可用 `run --resume`、`rerun`、`compare`、`export` 独立处理。

产物位于：

```text
.serrfix/
  evidence.db
  materials/
    original/                 # 用户原始材料，0444
    libfuzzer/                # fuzz 语料容器，0444
  fuzz/run-*/corpus/
  fuzz/run-*/artifacts/
  fuzz/run-*/libfuzzer.log
  fuzz/run-*/manifest.json
  runs/<sample-id>/*.json     # requested/result/compare 证据
  exports/*.zip
```

## 证据文件

每次运行的结果证据包含：

- `run.started_at` / `run.finished_at`：UTC RFC3339Nano。
- `run.source.offset` / `run.source.length` / `run.source.sha256`：样本在材料中的精确字节区间。
- `run.spans[]`：每个敏感片段的样本内偏移、长度、行列、规则、替换标记和片段 SHA-256。
- `redacted_base64`：脱敏后输出的精确字节，避免 UTF-8 往返改变数据。
- `localized_edit`：未修改前缀、未修改后缀、被替换字节数和插入字节数。

导出的 `SHA256SUMS` 覆盖 ZIP 内除自身外的所有文件。`verify` 会重新计算并拒绝任何篡改。

## 验收标准

一次通过验收必须同时满足：

1. 每份材料的当前 SHA-256 与捕获时一致，所有材料快照权限不含写位。
2. 每个样本的 `source_offset + source_length` 不越界，按该区间读取的字节 SHA-256 等于样本对象中的 SHA-256。
3. 每次运行均有 `started_at` 和 `finished_at`，两者都是 UTC，且 `finished_at >= started_at`。
4. 运行证据文件存在，文件 SHA-256 等于 SQLite 中的 `evidence_sha256`。
5. 证据中的样本偏移、长度、SHA 与 SQLite 记录一致。
6. 证据内脱敏输出 SHA、跨度布局与 SQLite 记录一致。
7. 所有 `passed` 运行的 `after_leaks` 为 0。
8. 每个跨度的源区间、替换区间都落在边界内，且敏感片段 SHA-256 与原文切片一致。
9. 比较记录的时间可解析，引用运行存在。
10. 事件时间全部可解析为 UTC RFC3339Nano。

本仓库已实际执行过一次全新验收：

```bash
./dist/serrfix accept --workspace .serrfix-acceptance2 --json
```

关键结果：

```json
{
  "schema": "serrfix.accept/v1",
  "accepted_at": "2026-11-22T02:00:23.791680468Z",
  "ok": true,
  "verify": {
    "material_count": 1,
    "sample_count": 12,
    "run_count": 14,
    "first_run_started_at": "2026-11-22T02:00:23.639028088Z",
    "last_run_finished_at": "2026-11-22T02:00:23.754965002Z"
  },
  "original_material": {
    "id": "mat-fb9570c2a271cc72",
    "sha256": "fb9570c2a271cc7206ecede2d1ae55cbfa39772c3eb8e3119e61fcafa7b9c48a",
    "size": 1348,
    "captured_at": "2026-11-22T02:00:23.623674134Z",
    "immutable": true
  }
}
```

同一材料上的 12 个原始字节区间：

| 样本 | 原始偏移 | 长度 | SHA-256 前缀 |
|---|---:|---:|---|
| `s-001-006f8767f175` | 0 | 188 | `006f8767f175` |
| `s-002-80edc46c3b59` | 189 | 106 | `80edc46c3b59` |
| `s-003-93965c69a34b` | 296 | 97 | `93965c69a34b` |
| `s-004-948a8de95994` | 394 | 103 | `948a8de95994` |
| `s-005-c871bea7b16a` | 498 | 103 | `c871bea7b16a` |
| `s-006-76be53efef11` | 602 | 81 | `76be53efef11` |
| `s-007-f3269c6f7ff7` | 684 | 96 | `f3269c6f7ff7` |
| `s-008-1e84d66c909d` | 781 | 134 | `1e84d66c909d` |
| `s-009-4b5a7581b04d` | 916 | 90 | `4b5a7581b04d` |
| `s-010-e6eaffd7a616` | 1007 | 143 | `e6eaffd7a616` |
| `s-011-18140e049964` | 1151 | 104 | `18140e049964` |
| `s-012-bcefeac906ad` | 1256 | 91 | `bcefeac906ad` |

单样本 `s-005-c871bea7b16a` 的两次重跑比较：

```json
{
  "comparison_id": "cmp-415f9bb90732ff51",
  "compared_at": "2026-11-22T02:00:23.76797622Z",
  "source_offset": 498,
  "source_length": 103,
  "same_original": true,
  "same_redacted": true,
  "same_span_layout": true
}
```

导出结果：

```json
{
  "sha256": "d8991fc1bde17450711ebbe3e0463570745a33962138d0311fb0690d6b710df1",
  "size": 12132,
  "sample_id": "s-005-c871bea7b16a",
  "runs": 3,
  "exported_at": "2026-11-22T02:00:23.781394391Z"
}
```

## 局部修正规则

当前规则按优先级处理：

- PEM 私钥块。
- URI 中的用户名/密码 userinfo。
- `Authorization: Bearer|Basic|Token ...` 凭据。
- JSON 字段：`password`、`passwd`、`pwd`、`secret`、`token`、`api_key`、`access_token`、`client_secret`、`authorization`。
- 键值对形式的同类字段和查询参数。
- 独立 Bearer token、AWS access key、GitHub token、JWT、邮箱。

替换只覆盖敏感片段，例如：

```text
Authorization: Bearer abc.def.ghi
Authorization: Bearer [REDACTED:AUTHORIZATION]
```

规则基于 Go RE2，不存在回溯爆炸；正则操作直接作用于 `[]byte`，因此中文和非法 UTF-8 输入不会破坏零基字节偏移。

## 失败与恢复

- `failed` 表示脱敏后仍检测到敏感跨度，或样本读取/哈希校验失败。证据仍会落盘。
- `abandoned` 表示进程未在运行提交前退出。请求证据保留，下一次 `run --resume` 会创建新 attempt。
- `verify` 失败时退出码为 1；`accept` 同样返回 1。
- 导出默认写到 `.serrfix/exports/`，ZIP 权限设置为只读。

## 开发

```bash
make build
make test
make demo
make fuzz-build
make fuzz WORKSPACE=.serrfix
```

关键路径：

- `cmd/serrfix/main.go`：CLI。
- `internal/redact/redact.go`：局部脱敏与字节跨度。
- `internal/store/store.go`：SQLite schema 与事务。
- `internal/app/run.go`：运行、停止、恢复。
- `internal/app/compare.go`：两次运行比较。
- `internal/app/export.go`：证据 ZIP。
- `internal/app/verify.go`：完整性验收。
- `internal/app/fuzz.go`：libFuzzer 编排和语料导入。
- `fuzz/error_target.cpp`：libFuzzer 目标。
