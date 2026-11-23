# 20231122

## 密码重置令牌审计 · 来源检查页

Go + SQLite 实现的令牌审计工具：每条结论都可回溯到原始输入与处理步骤。

- 运行审计并生成来源检查页：`go run . -db audit.db -out report.html`
- 单元测试：`go test ./...`
- 模糊测试（Go 内置 libFuzzer 派生引擎）：`go test -fuzz=FuzzParseToken -fuzztime=30s ./internal/audit/`

处理要点：

- 记录两个版本快照（`PRT1`/`PRT2`）与一个未知扩展（`PRTX`）。
- 到期时间恰好等于审计时钟的边界对象判为 `undecidable`，关键证据（审计时钟、到期时间、时钟偏移窗口）入库保留。
- 单个对象异常（含 panic）只记为 `error` 结论，其余对象继续处理。
- 运行期间的临时暂存表在结束时删除并验证，`runs.cleanup_ok` 标记清理结果。
