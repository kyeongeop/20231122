# 资源配额绕过处理过程重建（quotabypass）

固定技术栈：**Go + libFuzzer（Go 原生 fuzzing，libFuzzer 移植引擎）+ SQLite**。

## 1. 漏洞模型

攻击输入包含三要素：配额计数 `quota_count`、并发请求 `concurrent_requests`、
拒绝响应模板 `rejection_response`。当拒绝响应缺少必需片段
`rejection_response.fragment` 时，两条处理路径出现分歧：

- **漏洞路径（vulnerable）**：fail-open，权限判断点直接放行全部并发请求，
  配额被绕过（`attack-missing-fragment`，24/24 放行）。
- **修复路径（fixed）**：fail-closed，返回 400 拒绝请求（对照组 0/24 放行）。
- 片段完整时，配额门原子扣减，只放行 `quota_count` 个请求，其余按拒绝模板拒绝。

异常场景由“一个缺失片段”构造：同一份攻击输入分别在两条路径下重放，
形成可对照的绕过/阻断证据。

## 2. 证据链对应关系

每条记录把四类证据固定关联，字段顺序在导出与重载时保持不变：

- **攻击输入**：`attack_input` + `input`（原始字节、SHA-256、字节数、截断标记、缺失字段）。
- **触发位置**：`permission.trigger` 与每个 `attempts[].trigger`，统一指向
  `internal/quota/gate.go:51` 的 `(*Gate).Decide`；空/超大输入指向
  `internal/quota/runner.go:68` 的 `InvalidResult`。
- **权限判断**：`permission.decision/authorized/reason/policy`，
  策略为 `quota.rejection_fragment.required` 与 `quota.concurrent.reserve`。
- **日志证据**：`logs[]` 依次记录 `input_evidence`、`missing_fragments`、
  每次 `attempt_decision`、结尾的 `quota_bypass_detected` 或 `quota_enforced`。

## 3. 六个标准场景

| ordinal | 场景 | 模式 | 放行 | 拒绝 | 绕过 |
|---:|---|---|---:|---:|---|
| 0 | baseline-complete | fixed | 4 | 20 | 否 |
| 1 | attack-missing-fragment | vulnerable | 24 | 0 | 是 |
| 2 | control-missing-fragment | fixed | 0 | 24 | 否 |
| 3 | capacity-pressure | fixed | 3 | 61 | 否 |
| 4 | empty-input | fixed | 0 | 0 | 否 |
| 5 | oversized-input | fixed | 0 | 0 | 否 |

空输入返回 `input is empty`；超大输入（1,048,577 字节）返回
`input exceeds size limit`，哈希仍覆盖完整输入，`raw` 保留前缀并置 `truncated=true`。

## 4. 目录结构

```
cmd/quotabypass/        CLI：rebuild/export/import/verify/query/manifest
internal/model/         证据结构（字段顺序即规范顺序）
internal/quota/         输入解析、配额门、并发重放 runner、fuzz 目标
internal/evidence/      记录指纹、JSON/JSONL 导出导入与字段顺序校验
internal/store/         SQLite 存储（records/attempts/logs/metadata 四表）
fuzz/corpus/.../        fuzz 种子语料（基线、缺失片段、空、超大）
scripts/                rebuild.sh / fuzz.sh / reload_verify.sh
artifacts/              生成产物（evidence.sqlite、evidence.json[l]、manifest.json）
```

## 5. 复现步骤

```bash
go test ./...                                  # 全部单元测试
./scripts/rebuild.sh                           # 重建六场景并写 SQLite + 导出
./artifacts/quotabypass query -db artifacts/evidence.sqlite -ordinal 1
```

## 6. 独立复核（同事视角）

```bash
./scripts/reload_verify.sh                     # JSONL 导入全新库并校验指纹
./artifacts/quotabypass verify -db artifacts/evidence.sqlite
sha256sum artifacts/evidence.json artifacts/evidence.jsonl
```

- 每条记录带 `record_sha256`，哈希覆盖除该字段外的全部字段（紧凑规范 JSON）。
- JSONL 导入时逐行重算哈希并做字节级字段顺序比对，任何篡改或字段漂移均被拒绝。
- SQLite 重载同样重算哈希；篡改 `records` 表中的证据列会导致 verify 失败。
- 重新载入产物时，记录按 `ordinal` 固定排序，字段与顺序保持一致。

## 7. Fuzzing（libFuzzer）

```bash
./scripts/fuzz.sh                              # 默认 30s 覆盖率引导 fuzz
go test -fuzz=FuzzParseAndReplay -fuzztime=60s ./internal/quota
```

Go 原生 fuzzing 的运行时引擎是 libFuzzer 的 Go 移植版，采用相同的覆盖率插桩、
能量调度与语料最小化。fuzz 目标强制以下不变量：

1. 任意输入都必须保留输入哈希证据；
2. 空/超大/畸形输入在解析阶段收敛，不进入权限判定；
3. fixed 路径放行数永不超过配额；
4. 确认绕用时必须同时具备缺失片段日志与 gate 触发位置；
5. 同输入重放指纹完全一致（确定性）。

已验证：30 秒内 1800 万+ 次执行无崩溃、无不变量违反。
