# Webhook 签名验证 · 来源检查

一个可运行的来源检查台，用原始输入、处理步骤和 SQLite 证据记录回答“这个 Webhook 为什么通过、未决或被隔离”。

## 固定技术栈

- **Go**：HTTP 服务、验签核心、SQLite 访问与嵌入式单页
- **libFuzzer**：通过 `c-archive` 直接调用 Go 验签核心的 C++ fuzz target
- **SQLite**：对象、快照、步骤、证据、结论、fuzz 运行和临时状态的唯一持久化来源

## 本地运行

```bash
make test
make run
```

打开 `http://127.0.0.1:8787`。首次启动会在 `data/inspect.db` 中写入固定案件：

- 1 个未知扩展原始对象：`invoice.paid.whk`
- 2 个版本快照：`v1.8.2`、`v2.0.0-rc1`
- 1 个签名信封异常对象：`refund.failed.whk`

页面聚焦 `v2.0.0-rc1` 的 300 秒边界：签名有效，但接收时间与签名时间恰好相差 `300.000s`，且捕获时钟存在 ±2ms 未观测漂移。源码第 87 行使用严格大于比较，因此该对象保持“无法判断”，不会升级为通过或失败。

## 可追溯约束

每个对象的结论都包含 `evidenceIds`，每条证据都保存原始值、SHA-256、所属快照和写入时间。处理步骤保存输入引用、输出引用和关联证据，因此可以从结论回放到：

1. 原始请求字节与请求头快照
2. 签名信封、解码摘要与 canonical string
3. HMAC-SHA256 重算和恒时比较结果
4. 时间窗边界、隔离原因或内容类型探测
5. 写入 SQLite 的结论记录

未知扩展只作为来源属性显示，不参与签名判定；验签始终使用捕获到的原始字节。

## 异常与清理

- 异常按对象隔离：失败对象保留原因后继续处理后续对象。
- `POST /api/recheck` 会复验全部对象并继续批次。
- `POST /api/cleanup` 只删除登记在 `temp_state` 中、且位于临时根目录下的复验目录；正式证据不删除。
- 服务收到 `SIGINT` / `SIGTERM` 时自动执行同一清理逻辑。

## libFuzzer

```bash
make fuzz
```

`fuzz/export` 将 Go 验签核心构建为 `c-archive`，`fuzz/verify_fuzz.cc` 提供 `LLVMFuzzerTestOneInput`，输入格式为“签名信封行 + `\n` + 原始 body”。语料位于 `fuzz/corpus/`。

已验证结果：`13,494,101` 次执行，`0` 次崩溃。构建依赖 Go 与 clang/libFuzzer。

## API

- `GET /api/case`：完整案件、证据、fuzz 与处理日志
- `POST /api/objects/{id}/verify`：单对象复验
- `POST /api/recheck`：全量复验，异常不阻断
- `POST /api/cleanup`：清理临时状态
- `GET /api/export`：下载带案件的 JSON 证据包
- `GET /healthz`：运行状态
