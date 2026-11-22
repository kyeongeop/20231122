# 跨域策略来源检查

一个可运行的跨域 CORS 策略审计页。每条结论都能回到处理状态、原始输入和不可变 byte 区间；页面突出“首个错误状态”，不输出掩盖顺序的加权总分。

## 已实现

- 截断记录 `TRUNC·7F3A`：采集停在 `Access-Control-Allow-Credentials` 字段值中段，首个错误为 `capture.complete`，后续 5 个状态阻断。
- 恢复重放 `RPLY·9C21`：保留截断前缀，追加恢复块后重新解析。首个确定性错误为 `policy.vary`，不是加权总分。
- 未决边界 `policy.origin`：请求 Origin 为 `[REDACTED:origin]`，系统保留 `undecided`，不把脱敏证据猜成匹配成功。
- 证据链：结论 → 处理步骤 → artifact → byte range → SHA-256，可复制深链接回跳。
- 存储：Go 服务启动时自动建表并写入两份记录；截断原文、完整重放、恢复块均为不可变证据。
- 技术：Go、SQLite（`mattn/go-sqlite3`）、libFuzzer（C++ harness 调用同一 Go 分析器）。

## 运行

需要 Go 1.24+ 和用于 SQLite 驱动的 C 编译器。

```bash
go run ./cmd/server
```

打开 <http://localhost:8080>。默认数据库为 `data/audit.db`，可用环境变量覆盖：

```bash
DB_PATH=/tmp/audit.db PORT=9090 go run ./cmd/server
```

API：

- `GET /api/audits`
- `GET /api/audits/{id}`
- `GET /api/summary`
- `GET /api/health`

## 验证

```bash
go test ./...
```

测试锁定四个关键不变量：截断后不得继续产出通过结论、恢复块必须能重建完整原文、每个结论必须绑定真实步骤与证据、脱敏/`null` origin 必须保持 `undecided`。

libFuzzer 使用同一份 Go 解析逻辑，先构建 c-shared 桥接库，再编译和运行 harness：

```bash
CLANG=/path/to/clang++ CC=/path/to/clang scripts/fuzz.sh -runs=10000
```

`fuzz/corpus/` 包含截断报文和恢复重放两个只读种子；libFuzzer 的新增语料写入 `build/fuzz-corpus/`，脚本生成物不进入版本库。

## 审计约定

- `fail` 和 `truncated` 中按状态顺序取第一个作为 `firstError`。
- `undecided` 单独保留为边界，不转换为 pass/fail，也不计入首个确定性错误。
- 截断记录不修改、不补写；重放仅追加恢复块，并保存接缝偏移与独立哈希。
