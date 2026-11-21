# 本地文件包含（LFI）证据复核流程

本项目把一次 LFI 事件的取证结果固化为**可复核**的数据流水线：同一起事件在
旧版（v1，扁平 JSON）与新版（v2，带版本号的嵌套信封）两个快照中各有一份记录，
流水线把四类证据对齐后写入 SQLite，供审计人员逐条核对。

## 1. 四类证据的对应关系

每条 `evidence` 记录（见 `internal/model/evidence.go`）都包含以下四组字段，
回答复核时的四个问题：

| 复核问题 | v1 旧格式字段 | v2 新格式字段 | 归一化列 |
| --- | --- | --- | --- |
| 攻击输入是什么 | `payload` | `incident.attack.input` | `attack_input` |
| 在哪里触发 | `trigger_file` / `trigger_line` / `trigger_symbol` | `incident.trigger.*` | `trigger_file` / `trigger_line` / `trigger_symbol` |
| 权限判断结果 | `access_verdict` / `access_rule` | `incident.permission.*` | `permission_decision` / `permission_rule` |
| 日志证据在哪 | `log_file` / `log_line` / `log_evidence` | `incident.log.*` | `log_path` / `log_line` / `log_snippet` |

`correlation_id` 是跨快照的主键，SQLite 视图 `review_pairs` 按它做
`FULL OUTER JOIN`，同一事件的新旧两份记录在同一行左右对照，截断差异一目了然。

## 2. 被截断记录的处理

`snapshots/v1_legacy/LFI-LINC-0003.json` 是一条在 `log_line` 之后被截断的记录
（没有闭合值与花括号）。处理策略：

1. 先做严格 `json.Unmarshal`；返回 `unexpected end of JSON input` /
   `io.ErrUnexpectedEOF` 时判定为**截断**而非普通语法错误。
2. 用基于 `json.Decoder.Token()` 的容错扫描（`tolerantExtract`）按有效前缀
   逐个恢复已出现的键值，嵌套路径用点号展开（如 `incident.trigger.file`）。
3. 记录标记为 `parse_status = 'truncated'`，写入 `parse_error`，并把
   **原始字节**原样存入 `raw_object`，截断点之后的字段保持空值。
4. v2 快照中同一 `correlation_id` 的完整记录照常入库，复核者可在
   `review_pairs` 视图里用完整记录补全被截断的尾部证据。

完全无法解析的对象（如 `LFI-LINC-0009-corrupt.json`）标记为 `malformed`，
计入 `runs.object_failed`，但不会中断其余对象的处理。

## 3. 异常隔离与继续处理

`internal/pipeline` 对每个对象独立执行 `读取 -> 解析 -> 入库`：

- 单个对象读失败、解析失败或入库失败都只生成一条 `ObjectResult`，循环继续。
- `parse.Decode` 内部有 `recover` 兜底，恶意/残缺输入无法使进程崩溃。
- 运行结束写入 `runs` 表，状态为 `completed` 或 `completed_with_errors`。

## 4. 临时状态与清理

- 每次运行创建独立临时工作目录（`os.MkdirTemp`）。
- 未指定 `-db` 时使用临时 SQLite（含 `-wal` / `-shm` 旁路文件），运行结束
  先 `wal_checkpoint(TRUNCATE)` 再关闭，最后删除数据库文件与工作目录，
  删除结果体现在报告的 `cleanup` 段落。
- 指定 `-db` 时数据库保留在原位，仅清理临时工作目录。

## 5. 运行方式

```bash
make review                       # 跑两个快照，输出复核报告，库落在 artifacts/
go run ./cmd/lfi-review -db ""    # 临时库模式，结束即清理
make test                         # 单元测试
make fuzz-go                      # Go 原生 fuzz（解析器截断恢复）
make libfuzzer-run                # clang+libFuzzer 构建并运行（见 fuzz/ 目录）
```

## 6. 复核查询示例

```sql
-- 所有截断记录及其恢复出的前缀证据
SELECT correlation_id, snapshot_version, source_object, parse_error, raw_object
FROM evidence WHERE parse_status = 'truncated';

-- 新旧快照逐条对照
SELECT * FROM review_pairs;

-- 权限放行但日志出现敏感文件读取的高风险项
SELECT correlation_id, attack_input, log_snippet
FROM evidence
WHERE permission_decision = 'permit'
  AND (attack_input LIKE '%/etc/%' OR attack_input LIKE '%proc%');
```
