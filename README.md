# JWT 算法混淆复现（可复核流程）

对 RS256→HS256 算法混淆做可复核复现：围绕未知扩展 `x-ext` 记录 v1/v2
两个版本快照，并把攻击输入、触发位置、权限判断、日志证据关联到同一条
证据记录。技术栈：Go + libFuzzer（Go 原生 fuzz 引擎）+ SQLite。

## 流程

```sh
go run ./cmd/jwtconf            # 复现并落库到 artifacts/evidence/evidence.db
go test ./...                   # 单元测试（格式兼容、续跑、清理）
go test -fuzz=FuzzParse -fuzztime=30s ./internal/jwt   # libFuzzer 模糊解析器
```

## 证据关联

每条 `evidence.Record`（`internal/evidence/record.go`）包含：

- `attack_hash`：攻击输入（token）的 SHA-256
- `trigger`：权限判断点的 `file:line`（`runtime.Caller` 采集）
- `decision`/`reason`：allow / deny / error 及原因
- `logs`：带序号的分级日志证据
- `snaps`：未知扩展 v1（legacy）与 v2（fixed）在判断前后的快照

## 兼容与容错

- 记录格式 v1（旧）与 v2（新）均可写入/读取（`evidence.Marshal/Unmarshal`）
- 单个对象异常（解析失败、panic）记录后继续处理其余对象
- 运行结束自动清理临时目录，关键证据保留在 SQLite
