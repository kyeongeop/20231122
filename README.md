# tracecheck

日志注入检测的来源检查页。实现固定使用 **Go、libFuzzer、SQLite**：Go 提供服务与处理编排，libFuzzer 负责语料探索和最小复现，SQLite 保存原始输入、每次尝试、处理步骤、证据与审计事件。

## 运行

需要 Go 1.24+。SQLite 由纯 Go 驱动 `modernc.org/sqlite` 提供，不依赖系统 `sqlite3` 命令。

```bash
go run ./cmd/server
```

打开 <http://localhost:8080>。默认数据库为 `data/tracecheck.db`，首次启动会自动写入演示案例 `CHK-1A7F`。

可用环境变量：

- `ADDR`：监听地址，默认 `:8080`
- `TRACE_DB`：SQLite 路径，默认 `data/tracecheck.db`

## 演示案例

- 自动结论与人工确认分开存证：自动规则给出高风险日志注入，安全运营独立确认并关联处置单。
- 两次中途取消：第 1 次由人工取消，第 2 次因上游采集中断取消；原始输入、已完成步骤和部分证据均保留。
- 一次失败恢复：第 3 次尝试在 SQLite 证据写入阶段遇到 `SQLITE_BUSY`，页面展示已保留证据和可执行恢复步骤。
- 一个无法判断的边界：`BOUNDARY-07` 无法判断 U+2028 是否会被上游解析器当作行分隔符，原始字节作为证据保留并由人工补充结论。
- 每个自动 finding 都关联规则、处理步骤与证据 ID；点击证据可查看 SQLite 中的原文、SHA-256、写入时间和来源链。

## 数据模型

`checks → attempts → steps → evidence` 构成主链，`findings` 和 `audits` 分别保存自动结论与追加式审计事件。执行取消不会删除已写入内容，重跑始终引用同一份不可变原始输入。

SQLite 启动时启用 WAL、`busy_timeout=5000` 和外键约束。证据包导出为 ZIP，包含 manifest、原始输入、尝试/步骤、证据和审计轨迹。

## libFuzzer

fuzz target 位于 `fuzz/log_injection_fuzz.cc`，校验换行规范化后的行边界不变量。需要 Clang 20+：

```bash
./scripts/fuzz.sh
```

常用变量：

```bash
CLANG=clang++ FUZZ_SECONDS=60 ./scripts/fuzz.sh
```

将 libFuzzer 产物导入 SQLite，并可选挂到某个检查的证据链：

```bash
go run ./cmd/fuzzimport \
  -db data/tracecheck.db \
  -check CHK-1A7F \
  -artifact fuzz/artifacts/crash-<hash> \
  -minimized
```

导入记录写入 `fuzz_imports`；指定 `-check` 时同时生成 `fuzzer-artifact` 证据。

## 验证

```bash
go test ./...
go vet ./...
```

健康检查：`GET /healthz`。
