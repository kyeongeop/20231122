# 随机数种子审查

这是一个可复核的随机数种子审查流程。主线固定为“一次恢复后的 libFuzzer 重放”：
恢复清单进入系统，重放保留的 fuzz 产物，提取未知扩展、触发位置、权限判断和日志，
再把所有关键证据写入 SQLite 与内容寻址证据目录。报告明确分开自动结论和人工确认。

仓库中的 `fuzz/seed_target.c` 是审计夹具，不是真实产品漏洞。它稳定产生未知扩展
`hook.v2`、恢复后零种子、权限拒绝和源码触发行，便于端到端验证流程。

## 技术栈

- Go：CLI、清单归一化、重放编排、报告与人工确认。
- libFuzzer：以 `-runs=1` 重放单一 crash/artifact 输入，目标同时启用 ASan/UBSan。
- SQLite：保存会话、重放、扩展、触发点、权限、日志、发现、人工确认和审计事件。

## 快速开始

```bash
make fuzz-build
make demo
make verify
```

手工执行：

```bash
go run ./cmd/seedreview init --db var/demo/audit.db --evidence var/demo/evidence
go run ./cmd/seedreview replay \
  --db var/demo/audit.db --evidence var/demo/evidence \
  --manifest testdata/recovery-v2.json
go run ./cmd/seedreview report \
  --db var/demo/audit.db --evidence var/demo/evidence \
  --run 1 --format markdown
```

旧格式清单可直接重放：

```bash
go run ./cmd/seedreview replay \
  --db var/demo/audit.db --evidence var/demo/evidence \
  --manifest testdata/recovery-v1.json
```

## 主线内容

示例重放固定记录以下证据链：

| 环节 | 示例值 |
|---|---|
| 攻击输入 | `testdata/artifacts/unknown-ext.bin`，内容哈希入库 |
| 未知扩展 | `hook.v2` |
| 触发位置 | `fuzz/seed_target.c:189`，函数 `evaluate_permission` |
| 权限判断 | `guest execute hook.v2`，策略 `unknown-extension-deny`，实际 `deny` |
| 日志证据 | stderr 中 `zero_seed_after_recovery` 与 `unknown_extension_denied` |
| 自动发现 | `UNKNOWN_EXTENSION`、`ZERO_SEED_AFTER_RECOVERY` |

自动结论只能给出“未知扩展被拒绝”和“恢复后种子为零”等机器判断。
人工确认必须独立回答扩展来源、权限策略是否符合预期、日志是否留存，
以及是否由第二人独立重放并比对 trace 哈希。

## 证据保存

每次重放保存六类内容寻址证据：

1. 原始恢复清单。
2. fuzz 目标二进制。
3. 攻击输入。
4. 重放 stdout。
5. 重放 stderr。
6. 结构化 NDJSON trace。

证据写入 `sha256/<前两位>/<完整哈希>`，权限为只读。SQLite 只保存哈希、路径、
大小和关联关系，不依赖可变的原始文件路径。`seedreview verify` 会重新计算每个
证据的 SHA-256 和大小。

## 报告结构

Markdown 报告固定包含：

- `主线：恢复后的一次重放`
- `自动结论`：自动发现、输入到权限/日志的对应关系、证据校验结果
- `人工确认`：待确认项、负责人、备注和确认状态
- `失败后续操作`：仅在重放失败或证据损坏时给出可执行命令
- `复核与兼容性`：输入格式、输出格式和复核命令

JSON 报告使用 `automatic` 和 `manual_confirmation` 两个独立对象，避免把
机器结论误当成人工批准。`--format legacy-json` 另外提供旧版扁平字段。

人工确认示例：

```bash
go run ./cmd/seedreview manual \
  --db var/demo/audit.db --run 1 \
  --check INDEPENDENT_REPLAY --status confirmed \
  --owner reviewer-a --notes "second replay trace hash matched"
```

## 旧格式与新格式

新版清单使用 `schema_version: 2` 和嵌套 `recovery` 对象。旧版清单支持扁平字段，
包括 `time`、`version`、`seed`、`seed_after_recovery`、`rng`、`state_hash`、
`target`、`input` 和 `env`。解析器会归一化为同一内部会话模型，并记录
`legacy-v1` 或 `canonical-v2`。

如果重放失败，命令仍会保存失败运行和已有证据，退出码为非零。报告会给出
`BUILD_TARGET`、`RESTORE_ARTIFACT`、`SYMBOLIZE_CRASH`、`MINIMIZE_INPUT` 等
后续操作。

## 验证

```bash
go test ./...
go run ./cmd/seedreview verify --db var/demo/audit.db --evidence var/demo/evidence
```

测试覆盖旧/新清单、证据防篡改、真实 libFuzzer 未知扩展重放、崩溃处置、
SQLite 映射、自动/人工报告分区和人工状态更新。

更完整的操作步骤见 `docs/review-runbook.md`。
