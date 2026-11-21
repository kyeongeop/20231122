# 崩溃样本自动归因 · 来源检查页

一个可运行的 Go + libFuzzer + SQLite 取证工作台。它记录恢复后的重放、未知
扩展和无法判断的边界，并把自动结论、人工确认、原始输入与处理步骤分开保存。

## 运行

```bash
go test ./...
go run . -addr :8080 -db evidence/forensics.db
```

打开 <http://localhost:8080>。首次启动会自动写入 `C-8842` 样本、9 个证据对象、
7 个处理步骤、2 次重放和 4 条人工确认待办。

## 页面包含什么

- **恢复后的重放**：R-001 因符号化通道不可达失败；job-7fe2 从 journal 恢复后，
  R-002 连续重放 3 次均复现同一崩溃指纹。
- **未知扩展**：样本扩展名为未注册的 `.kz3`，记录内又出现未注册的 `0x7E`。
  12 B 扩展块、其偏移、长度、后继 payload 边界和 SHA-256 均单独保留。
- **无法判断的边界**：规则 `EXT-UNKNOWN` 在 `0x29` 停止，不把扩展块自动归为
  包装层或业务层。置信度 41%，低于自动归属阈值。
- **可追溯结论**：每条自动结论都能打开抽屉，查看原始字节高亮、证据对象、
  哈希、命令和处理步骤。
- **失败后续操作**：失败日志与成功日志并存；页面提供重新执行、查看失败日志、
  查看 journal、导出证据包等操作。
- **报告分栏**：自动结论与人工确认写入不同表、在页面和打印报告中分栏呈现。

## 数据与证据

SQLite 表：

| 表 | 用途 |
|---|---|
| `samples` | 原始样本 BLOB、文件名、扩展名、SHA-256、封存时间 |
| `steps` | 每步命令、状态、时间、输入/输出摘要 |
| `evidence` | 原始字节、失败日志、恢复 journal、ASan 栈、trace、manifest |
| `conclusions` | 仅存自动规则产出的结论 |
| `manual_checks` | 仅存人工签署、审核人、备注和时间 |
| `replay_runs` | 每次重放的状态、退出码、复现次数和证据 ID |
| `unknown_extensions` | 未知标签、偏移、长度、边界和原始 12 B |

原始样本保存在 `evidence/samples/recovered_0x7e.kz3`。SQLite 中保存同一份
84 B BLOB；API 下载与导出都从数据库读取，因此页面结论不会脱离原始输入。

## libFuzzer 复现

`fuzz/kz3_fuzz.c` 使用与 Go 解析器相同的 RZ31 记录边界。安装 clang 后：

```bash
cd fuzz
CC=clang ./build.sh
./kz3_fuzz -runs=200000 corpus/
./kz3_replay corpus/seed.kz3
```

`kz3_replay` 用 ASan/UBSan 复现样本；预期非零退出并输出
`heap-buffer-overflow`。本机实际复现日志在 `evidence/replays/local-asan.log`。
若环境没有 clang，`build.sh` 会给出安装提示，并仍用 `cc` 构建独立重放器。

## API

| 方法 | 路径 | 作用 |
|---|---|---|
| `GET` | `/api/report?sample=C-8842` | 读取完整分栏报告 |
| `POST` | `/api/manual-review` | 写入人工确认，不覆盖自动结论 |
| `POST` | `/api/replay` | 重跑来源解析 3 次并追加步骤、证据和重放记录 |
| `GET` | `/api/evidence/{id}` | 下载原始证据对象 |
| `GET` | `/api/export?sample=C-8842` | 导出含原始字节和全部证据的 JSON |

人工确认示例：

```bash
curl -X POST http://localhost:8080/api/manual-review \
  -H 'Content-Type: application/json' \
  -d '{"check_id":"MC-04","status":"confirmed",
       "reviewer":"owner@example","note":"扩展注册表已补充"}'
```

## 关键文件

- `internal/forensics/`：RZ31 字节结构、未知扩展判定、固定样本
- `internal/store/`：SQLite schema、种子证据、人工确认、导出
- `internal/httpapi/`：报告与证据 API
- `web/`：检查页、追溯抽屉、分栏报告、内置中文字体
- `fuzz/`：libFuzzer target、独立 ASan 重放器、种子语料
