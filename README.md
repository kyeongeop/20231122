# 20231122

## 并发账户锁定异常重建

技术栈: Go + libFuzzer 风格 fuzzing (Go 原生 fuzz 引擎) + SQLite (modernc.org/sqlite)。

- `internal/lockout/parse.go` — 原始抓包解析, 每条记录锚定原始偏移; 拒绝空输入/超大输入
- `internal/lockout/service.go` — 并发锁定处理; 重复对象在 `read-modify-write` 窗口确定性复现丢失更新
- `internal/lockout/store.go` — SQLite 证据库 (attempts 审计表 + evidence 表)
- `cmd/reconstruct/` — 重建异常场景并生成 `evidence/report.md`

复现与验收:

```sh
go test ./internal/lockout/                                  # 单元测试(含重复对象异常)
go test ./internal/lockout/ -fuzz=FuzzParseRequests -fuzztime=30s
go run ./cmd/reconstruct                                     # 生成证据与报告
cd evidence && sha256sum -c raw_capture.bin.sha256           # 校验原件未修改
```

验收锚点: `evidence/report.md` 中每条证据行都带 RFC3339Nano UTC 时间戳与
`evidence/raw_capture.bin` 的原始字节偏移; 重复对象 (RequestID
`aa11bb22…`) 的两条 increment 行 (偏移 146 与 192) 记录相同 fail_count=4,
即丢失更新的直接证据。
