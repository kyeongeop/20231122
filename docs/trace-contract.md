# libFuzzer trace 契约

Go 审查器不解析 sanitizer 的自然语言输出作为主数据源。被审查的 libFuzzer 目标必须
在环境变量 `SEED_AUDIT_TRACE` 指向的文件中追加 NDJSON，每行一个事件。

重放命令还会设置：

- `SEED_AUDIT_SINGLE_REPLAY=1`：libFuzzer 可能对固定输入做初始化执行，
  目标应只记录第一次真实重放。
- `SEED_AUDIT_RECOVERY_SEED`：恢复后的随机数种子。

## 必需事件

### start

```json
{"event":"start","restored_seed":"0","input_seed":"0","effective_seed":"0","extension":"hook.v2","known_extension":false,"principal":"guest","action":"execute"}
```

用于建立本次重放的输入语义、原有种子和有效种子。`known_extension=false`
会在报告中形成未知扩展记录。

### permission

```json
{"event":"permission","extension":"hook.v2","principal":"guest","action":"execute","expected":"deny","actual":"deny","policy":"unknown-extension-deny","reason":"unknown extension is denied by default"}
```

`expected` 与 `actual` 不相等时自动形成 `PERMISSION_MISMATCH` 严重发现。

### trigger

```json
{"event":"trigger","extension":"hook.v2","file":"fuzz/seed_target.c","line":189,"function":"evaluate_permission","kind":"permission_gate"}
```

行号必须由目标在真实权限分支中从 `__LINE__` 取得，不能由审查器猜测。

### log

```json
{"event":"log","source":"seed_target","level":"warn","message":"unknown_extension_denied"}
```

同时应向 stderr 输出以 `[seed-audit]` 开头的可读日志。审查器保存 stderr 整体哈希，
并为每条可读日志记录字节偏移、行哈希和级别。

## 失败要求

- 每个事件写入后立即 `fflush`。
- 崩溃前必须 `fflush(NULL)`，保证 trace 和 stderr 可保留。
- 不允许在 trace 中写未转义的控制字符；扩展名、原因等动态字段必须 JSON 转义。
- 目标退出非零、超时或 signal 结束都视为失败重放，但已有证据必须入库。

## 接入真实目标

1. 在原有 `LLVMFuzzerTestOneInput` 中加入 trace 事件。
2. 保留产品自身的权限判断，不要为了审计另写一套平行逻辑。
3. 在触发分支记录 `__LINE__`、函数名和策略代码。
4. 用恢复清单指定真实 `target` 和 `artifact`。
5. 执行 `seedreview replay`，人工核对 trace 与产品日志是否一致。

审查器只信任「证据哈希 + 结构化事件 + 人工确认」的组合。
