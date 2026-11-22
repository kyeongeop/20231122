# 随机数种子审查运行手册

## 目标

对一次恢复后的随机数种子状态做可复核审查，并回答四个问题：

1. 哪个攻击输入触发了路径？
2. 路径在何处进入权限判断？
3. 权限结论是否符合预期？
4. 哪条日志可以独立证明上述结论？

本流程只把自动结果当作机器证据。最终结论必须由人工确认项闭合。

## 前置条件

- Go 1.25 或更高版本。
- 支持 `-fsanitize=fuzzer,address,undefined` 的 clang。
- 可写的 SQLite 数据库路径和证据目录。
- 一份恢复清单和对应 libFuzzer 产物。

首次构建：

```bash
make fuzz-build
make test
```

## 步骤 1：初始化审查库

```bash
seedreview init --db var/review/audit.db --evidence var/review/evidence
```

`init` 会应用 SQLite schema，外键开启，日志使用 WAL。证据目录采用内容寻址布局。

## 步骤 2：执行恢复后的单次重放

```bash
seedreview replay \
  --db var/review/audit.db \
  --evidence var/review/evidence \
  --manifest testdata/recovery-v2.json \
  --timeout 15s
```

重放命令执行：

- 归一化旧版或新版恢复清单。
- 保存清单、目标、输入，并计算 SHA-256。
- 用 libFuzzer 的 `-runs=1` 重放单个产物。
- 设置 `SEED_AUDIT_TRACE` 和 `SEED_AUDIT_SINGLE_REPLAY=1`。
- 保存 stdout、stderr 和 NDJSON trace，即使目标崩溃也保留已有数据。

如需覆盖清单中的路径：

```bash
seedreview replay ... --target build/seed_target --artifact path/to/crash
```

## 步骤 3：审阅自动结论

```bash
seedreview report \
  --db var/review/audit.db --evidence var/review/evidence \
  --run <id> --format markdown
```

自动部分必须核对：

- 攻击输入哈希和大小是否与保留产物一致。
- 未知扩展名称是否来自 trace 的 `start` 事件。
- 触发位置的文件、行号、函数是否来自 trace 的 `trigger` 事件。
- `expected` 与 `actual` 是否一致，策略和原因是否合理。
- 日志行哈希是否指向同一 stderr 证据。
- 所有证据是否满足 `hash_ok=true`。

自动结论不能直接关闭审查。即使显示 `unknown_extension_denied`，也必须完成人工确认。

## 步骤 4：完成人工确认

报告会生成以下待确认项：

- `UNKNOWN_EXTENSION_PROVENANCE`：未知扩展是否来自可信发布源。
- `PERMISSION_POLICY_EXPECTATION`：权限预期是否与当前安全策略一致。
- `KEY_LOG_RETENTION`：关键日志是否已进入集中日志并满足保留期限。
- `INDEPENDENT_REPLAY`：第二人是否独立重放并比对 trace 哈希。

确认：

```bash
seedreview manual \
  --db var/review/audit.db --run <id> \
  --check INDEPENDENT_REPLAY \
  --status confirmed \
  --owner reviewer-b \
  --notes "same input and trace hash; trigger line reproduced"
```

拒绝：

```bash
seedreview manual \
  --db var/review/audit.db --run <id> \
  --check PERMISSION_POLICY_EXPECTATION \
  --status rejected \
  --owner security-lead \
  --notes "deny is not the documented policy for this extension"
```

每次确认写入 `audit_events`，报告重新生成后会显示负责人、备注和确认时间。

## 步骤 5：校验证据

```bash
seedreview verify --db var/review/audit.db --evidence var/review/evidence
```

任何哈希或大小不一致都会使命令失败。证据缺失时不得重新生成“通过”报告。

## 失败处置

重放失败时，运行记录仍会写入 SQLite，命令返回非零退出码。按报告中的
`failure.next_actions` 执行：

| 失败代码 | 首选操作 |
|---|---|
| `target_missing` | `make fuzz-build`，修正 `target` 后重放 |
| `target_not_executable` | `chmod +x <target>` 后重放 |
| `artifact_missing` | 恢复保留的 libFuzzer 产物或修正清单 |
| `replay_timeout` | 直接运行目标、提高超时、使用 `-minimize_crash=1` |
| `replay_crash` | 冻结证据、启用符号化、保留原始输入与目标 |
| `trace_missing` / `trace_unreadable` | 修复 `SEED_AUDIT_TRACE` 写入并重新构建 |

失败运行完成处置后应重新重放，形成新的 run，而不是修改旧证据。

## 兼容性

旧版清单示例：

```json
{
  "time": "2026-11-22T08:15:00Z",
  "version": "2023.11.22-hotfix",
  "seed": 0,
  "seed_after_recovery": 0,
  "rng": "splitmix64",
  "state_hash": "...",
  "target": "../build/seed_target",
  "input": "artifacts/unknown-ext.bin"
}
```

新版清单使用 `schema_version: 2` 与嵌套 `recovery.rng`。两种格式进入同一套 SQLite
模型。报告默认输出新版结构，`--format legacy-json` 可给旧消费者使用。
