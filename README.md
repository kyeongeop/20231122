# 反向代理信任边界：可复核审计流程

技术栈：Go + 原生 fuzz（libFuzzer 式覆盖率引导）+ SQLite（modernc.org/sqlite，纯 Go）。

## 流程

```sh
go build -o artifacts/trustaudit ./cmd/trustaudit
./artifacts/trustaudit all -db artifacts/audit.db -out artifacts/report.json
```

1. **seed**：写入审计日志，混合旧格式 v1（管道分隔文本）与新格式 v2（JSON），
   末尾追加一条**被截断的记录**（模拟写入中途崩溃的撕裂写）。
2. **recover**：逐条校验，第一条无法解码的记录即为**第一个损坏状态**；
   其原始字节与 SHA-256 移入 `evidence` 表永久保留，后续记录标记
   `unreachable`，恢复点本身写入 `recovery` 表。
3. **replay**：对 salvage 出的记录逐条重放信任边界判定，输出关联报告——
   攻击输入（remote/XFF）→ 触发位置（规则 + 源码行）→ 权限判断
   （allow/deny + 理由）→ 日志证据（行号 + 哈希），并**明确指出第一个
   错误状态**（`first_error`），而非只给总分。

## 复现本次样例结论

- 存储层第一个错误：log 5（截断记录，已隔离，证据保留）。
- 判定层第一个错误：log 3，记录为 `allow`，重放判定 `deny`
  （不可信对端伪造 X-Forwarded-For，触发 `R3-xff-spoof`）。

## 测试

```sh
go test ./...
go test -run=NONE -fuzz=FuzzDecode -fuzztime=30s ./internal/record/
go test -run=NONE -fuzz=FuzzDecide -fuzztime=30s ./internal/trust/
```
