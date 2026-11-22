# wsframefix — WebSocket 帧长度检查局部修正工具

针对 WebSocket 帧(RFC 6455)长度解析的三段锚点做局部修正,每个攻击样本
可单独重跑、比较、导出;全部状态落在 SQLite,支持中途退出与重新进入。

## 三段锚点

| 锚点 | 位置 | 检查内容 |
|------|------|----------|
| `A1-header`  | 原始偏移 `0x0` | 基础头至少 2 字节 |
| `A2-extlen`  | 原始偏移 `0x2` 起 | 16/64 位扩展长度字段在位、64 位长度最高位为 0、掩码键在位 |
| `A3-payload` | 原始偏移 `>= 0x2` | 声明负载不超过剩余缓冲区且 ≤ 16 MiB |

`internal/parser/parser.go` 同时保留两条路径:`parseVulnerable`(未修改的
原始逻辑,越界即 panic)与 `parseFixed`(仅在三个锚点插入检查的局部修正)。

## 技术栈

- **Go**:CLI、解析器、证据收割。
- **libFuzzer**:Go 原生覆盖率制导模糊测试引擎(`go test -fuzz`,libFuzzer
  实现),入口 `internal/parser/fuzz_test.go` 的 `FuzzWSFrame`,含差分不变量
  (原始版 panic 的输入,修复版必须拒绝)。
- **SQLite**(`modernc.org/sqlite`,纯 Go):样本、运行记录、锚点事件、元数据
  全部持久化在 `<dir>/evidence.db`。

## 使用

```sh
go build -o bin/wsframefix ./cmd/wsframefix

./bin/wsframefix init                 # 快照未修改的原始材料(只读 + sha256)
./bin/wsframefix seed                 # 生成 A1/A2/A3 三个基准攻击样本
./bin/wsframefix fuzz -seconds 60     # libFuzzer 引擎;Ctrl-C 可中断,重进续跑
./bin/wsframefix run -id 3            # 单独重跑某样本(原始版+修复版)
./bin/wsframefix compare -id 3        # 逐锚点比较两版行为
./bin/wsframefix export -id 3         # 导出证据包(原始字节 + JSON)
./bin/wsframefix status               # 样本、锚点命中、最近运行时间
```

## 验收落点

- **具体时间点**:每次运行以 UTC RFC3339Nano 落库(`runs.run_at`),导出见
  `evidence.json` 的 `run_at` / `exported_at` / `sample.created_at`。
- **原始偏移**:修复版命中的锚点与字节偏移落库(`runs.anchor`,
  `runs.raw_offset`),如 `A3-payload @ 0x4`。
- **未修改的原始材料**:`init` 把原始解析器快照到
  `.wsframefix/originals/parser.go.orig`(权限 0444),sha256 写入 meta 表并
  随证据包导出;重复 `init` 拒绝覆盖。
- **中途退出/重新进入**:模糊语料缓存于 `.wsframefix/gocache`,样本与运行
  记录全在 SQLite;Ctrl-C 后重跑同一命令即从既有状态继续。

## 测试

```sh
go test ./...                 # 锚点单元测试(锚点 ID + 原始偏移断言)
go test -run=^$ -fuzz=FuzzWSFrame -fuzztime=30s ./internal/parser
```
