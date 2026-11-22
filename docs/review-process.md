# 迁移权限复核流程

## 目标

复核结论必须能回答四个问题，并指向同一份输入：

1. 实际输入了什么，是否有攻击载荷？
2. 哪一条语句、哪个 token 触发了权限判断？
3. 权限引擎为什么允许或拒绝？
4. 执行、取消、回滚和日志证据在哪里，是否能发现篡改？

## 处理阶段

### 1. 接收与封存

- 读取原始字节，限制为 4 MiB。
- 计算 SHA-256，原始字节写入证据库 `input/raw`。
- 不修改原始文件；解析失败也必须保留错误与输入。
- 识别 `legacy-v1`、`legacy-sql`、`v2`，记录兼容路径。

### 2. 归一化

- 旧格式和新格式统一转成 v2 清单。
- SQL 按分号拆分，但识别字符串、标识符、行注释和块注释中的分号。
- 每条语句保存相对源位置和 token 偏移。
- 归一化 JSON 写入 `manifest/normalized.json`。

### 3. 权限判定

- 读取 actor 的能力集合。
- 对每条语句计算最高风险能力：`read`、`write`、`schema`、`destructive`、`attach`、`admin`。
- 记录能力对应的 token、行、列。
- `destructive`、`attach`、`admin` 除 actor 能力外，还要求独立操作员开关。
- `destructive` 额外要求操作员提供审批号。
- 任一语句拒绝则整次迁移不执行，但仍保留所有语句的判定结果。

### 4. 执行

- 只在目标 SQLite 上开启一个事务。
- 每条语句执行前写 `statement_start` 日志，执行后写 `statement_executed`。
- 每条语句后检查取消信号。
- 取消或错误：显式 rollback，计算 schema 前后哈希，写 `rollback` 日志。
- 全部完成：检查取消信号后 commit，写 `commit` 日志。

### 5. 中途取消

演示运行 `demo-cancel-midway` 在第 1 条语句后发起取消：

1. `CREATE TABLE cancel_probe` 已在事务内执行。
2. 写 `cancel_requested` 日志。
3. 循环在提交下一条语句前观察到取消。
4. `rollback` 回滚整个事务。
5. `schema_before == schema_after`，`rollback_ok=true`。
6. 目标库中不存在 `cancel_probe`。

自动报告要求同时满足 `CANCELLED`、`rollback_ok` 和前后 schema 哈希一致，缺一不可。

### 6. 证据固化

每次运行写入：

- 原始输入及哈希
- 归一化清单
- 策略快照及哈希
- 完整权限判定
- 关键日志链
- schema 前后快照

日志链公式：

```text
entry_hash = SHA256(canonical(run_id, ts, level, event, detail, prev_hash))
```

`runs.log_head_hash` 固定链头。`migrationctl verify` 会重算每一环，并交叉校验原始输入、策略快照、权限决策和触发位置。

## 报告分栏

### 自动结论

仅包含工具可证明的事实：

- 输入字节和 SHA-256
- 格式与归一化结果
- 触发位置与 token
- 语句级 ALLOW/DENY 与原因
- 执行状态、回滚一致性
- 日志链和证据哈希
- 旧/新格式、取消、攻击拦截的覆盖情况

### 人工确认

必须由授权人填写：

- 策略基线是否已批准
- 攻击载荷的业务语义是否确实危险
- 特权操作审批号是否真实
- 取消时机与重试窗口是否符合规范
- 证据是否已异地保管
- 最终签字或工单

自动检查为 PASS 不能替代人工确认，人工确认未填写时报告保持“未确认”。

## 失败处置

| 情况 | 立即动作 | 后续动作 |
| --- | --- | --- |
| `DENIED` | 不执行、不启用危险开关、保留攻击输入 | 轮换凭据、检查构建链；误报只能通过策略代码评审修正 |
| `CANCELLED` | 核对 `rollback_ok` 和 schema 哈希 | 修复取消原因，在 staging 使用新 run id 重跑 |
| `FAILED` | 停止写入，导出日志与 schema 快照 | 从备份恢复，修复根因后用新证据库重跑 |
| 哈希链失败 | 冻结证据库及 `-wal`/`-shm` | 从备份恢复，禁止用损坏证据放行 |
| 策略哈希不一致 | 停止上线，恢复已批准策略 | 逐字比对策略快照后重新生成报告 |

具体命令由报告中的“失败与后续操作”按 run id 生成，避免只给抽象建议。
