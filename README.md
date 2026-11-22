# 数据库迁移权限可复核流程

这是一个固定使用 **Go、libFuzzer、SQLite** 的最小实现。它把一次迁移拆成可复核的四个关联对象：

1. 原始输入/攻击载荷（字节与 SHA-256）
2. 精确触发位置（文件、语句、行、列、token）
3. 语句级权限判断（actor、能力、允许/拒绝原因）
4. 追加式日志与证据哈希链

示例覆盖三种结果：v2 格式正常提交、旧格式攻击被拒绝、迁移事务中途取消并回滚。报告将**自动结论**和**人工确认**严格分栏，失败/取消时给出可直接执行的后续命令。

## 快速开始

要求：Go 1.22+；运行 libFuzzer 时还需要带 `libclang_rt.fuzzer` 的 clang 15+。SQLite 使用纯 Go 驱动，不依赖系统 `sqlite3` 命令行。

```bash
go build -o build/migrationctl ./cmd/migrationctl
./build/migrationctl demo --out artifacts/review
./build/migrationctl verify --evidence artifacts/review/evidence.sqlite
```

生成：

- `artifacts/review/evidence.sqlite`：run、日志、原始输入、策略快照、权限判定、schema 快照
- `artifacts/review/review-report.md`：自动结论、人工确认、失败后续操作
- `artifacts/review/attack-input.bin`：与证据库中 SHA-256 一致的攻击输入副本
- `artifacts/review/target.db`：演示目标 SQLite 库
- `artifacts/review/summary.json`：运行状态索引

演示结果固定为：

| Run | 格式 | 预期 |
| --- | --- | --- |
| `demo-v2-success` | v2 | ALLOWED，事务提交 |
| `demo-legacy-attack` | legacy-v1 | DENIED，`DROP TABLE audit_log` 未执行 |
| `demo-cancel-midway` | v2 | CANCELLED，第 1 条后取消，schema 前后哈希一致 |

## 单次复核

```bash
./build/migrationctl review \
  --input testdata/migrations/new-add-orders.json \
  --db /tmp/review-target.db \
  --policy config/policy.json \
  --evidence /tmp/review-evidence.sqlite \
  --report /tmp/review-report.md
```

退出码：

- `0`：全部语句通过并提交
- `2`：权限拒绝，未执行
- `3`：中途取消，已回滚
- `1`：解析、证据或执行失败

危险能力需要独立于清单的操作员开关，不能由迁移文件自行授权：

```bash
--allow-destructive --approval-id CHG-1234
--allow-attach
--allow-admin
```

`--approval-id` 只作为操作员输入证据，不能覆盖策略中的 actor 能力；攻击清单里的 `approval_id` 不会生效。

## 旧格式与新格式

旧格式 `legacy-v1`：

```json
{
  "id": "legacy-maintenance",
  "actor": "app_migrator",
  "requested_by": "build-42",
  "sql": "ALTER TABLE accounts ADD COLUMN last_seen TEXT;\nDROP TABLE audit_log;"
}
```

新格式 `v2`：

```json
{
  "format_version": 2,
  "migration": {
    "id": "orders-v2",
    "actor": "app_migrator",
    "requested_by": "release-2026-11-22",
    "approval_id": "CHG-1042",
    "statements": [
      {"sql": "CREATE TABLE orders (id INTEGER PRIMARY KEY)"},
      {"sql": "CREATE INDEX idx_orders_id ON orders(id)"}
    ]
  }
}
```

同时接受无 JSON 包装的 `legacy-sql`；此时 actor 必须通过 `--actor` 提供，否则策略默认拒绝。两种格式都会归一化为同一 v2 证据对象，但原始字节始终保留，不能用一个格式覆盖另一个格式的审计轨迹。

## 权限模型

默认策略见 `config/policy.json`：

- `reader`：`read`
- `app_writer`：`read`, `write`
- `app_migrator`：`read`, `write`, `schema`
- `admin`：全部能力，但 `destructive` / `attach` / `admin` 仍需操作员开关

解析器按语句归类能力，并保留导致最高风险判定的 token 位置。注释和字符串中的关键字不会误触发；`WITH ... DELETE`、`PRAGMA writable_schema=ON`、`ATTACH DATABASE` 会被提升到相应能力。未知语句按 `admin` 失败关闭（fail closed）。

注意：这是安全优先的词法判定，不是完整 SQL 语法树。对象名恰好等于危险关键字时可能被保守拒绝，需走人工确认，不能通过关闭检查解决。

## 证据与报告

`evidence.sqlite` 有三类关键表：

- `runs`：权限结论、执行状态、触发位置、schema 前后哈希、日志头哈希
- `logs`：`prev_hash` / `entry_hash` 追加链
- `evidence`：原始输入、归一化清单、策略快照、权限判定、schema 快照，每个对象独立记录 SHA-256

`migrationctl verify` 会同时校验日志链、证据内容哈希、run 中的输入字节、策略快照、权限决策和触发位置，不只是看文件是否存在。

报告中的 `## 自动结论` 只陈述工具可确定性验证的内容；`## 人工确认` 保持未签字状态，包含策略批准、攻击语义、特权审批、取消窗口和证据异地保管等检查项。任何 `DENIED`、`CANCELLED`、`FAILED` 或自动检查未通过项，都会在 `## 失败与后续操作` 中生成命令或阻塞动作。

## libFuzzer

真实的 libFuzzer harness 在 `fuzz/libfuzzer/harness.cc`，通过 Go `-buildmode=c-shared` 调用同一解析与权限引擎：

```bash
CLANGXX=/path/to/clang++ RUNS=20000 ./scripts/run_libfuzzer.sh
```

脚本会把 `fuzz/corpus` 复制到构建目录，运行 `-fsanitize=fuzzer`，并把 crash 写到 `build/libfuzzer/artifacts/`。Go 导出层会 recover panic，并把内部不变式失败转成非零码，由 C++ harness `abort()` 形成 libFuzzer crash。导出层还把格式、能力、拒绝原因等语义编码成特征位图；C++ harness 将位图映射为分支桶，为跨语言边界提供语义覆盖反馈。

另有 Go 原生覆盖引导目标用于解析器深挖：

```bash
go test ./fuzz -fuzz=FuzzReview -fuzztime=30s
```

## 验证

```bash
go test ./...
go vet ./...
make fuzz
```

核心测试覆盖：旧/新格式兼容、引用字符串中的分号、注释/字符串绕过、语句级拒绝、危险能力双开关、中途取消回滚、证据哈希链篡改检测、报告自动/人工分栏和失败操作。
