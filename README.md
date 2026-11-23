# PathScope · 路径规范化差异来源检查

一个可运行的取证式检查页：围绕一次恢复后的 libFuzzer 重放与一个未知扩展，
把原始字节、处理步骤、自动结论、人工确认和失败处置串成可回查的 SQLite 证据链。

## 技术栈

- **Go 1.26+**：HTTP 服务、重放编排、证据链 API
- **libFuzzer / C**：路径百分号解码与双后端规范化的真实差分目标
- **SQLite（WAL）**：案件、证据、步骤、结论、复核、处置和重放记录
- **原生 HTML/CSS/JS**：无构建步骤，前端资源由 Go `embed` 提供

## 运行

```bash
go mod download
go run .
# http://localhost:8080
```

可用环境变量：

```bash
ADDR=:8080
DB_PATH=data/pathscope.db
CASE_ID=PN-231122-0417
```

首次启动会创建 `data/pathscope.db` 并写入示例案件。数据库已存在时不会覆盖。

## 数据与证据链

页面上的实体分别持久化在：

- `evidence`：原始语料、解码结果、双后端输出、失败日志；SHA-256 与来源路径
- `steps`：S-00 到 S-07 的处理链及后续手动重放步骤
- `findings`：自动规则结论，带置信度和证据引用
- `reviews`：人工确认，只追加，不覆盖自动结论
- `followups`：失败恢复与不可判定边界的可执行后续操作
- `replays`：每次恢复后重放的命令、时间、退出码和输出

页面中的 `S-xx`、`EV-xx`、`AUTO-xx`、`FU-xx`、`REPLAY-xx` 都是可点击引用。
点击后可直接打开对应步骤、证据、处置单或重放输出。

## 不可判定边界

案件故意保留一个无法从现有证据定论的边界：`/srv/www/uploads` 在原始运行时的
符号链接状态没有采集。因此即使 legacy 输出 `/srv/etc/passwd.unk9`，也不能直接
断言真实越界。页面同时呈现 H1/H2 两种解释，并保留原始输入、解码步骤、双输出和
扩展分派作为关键证据。

## libFuzzer 差分目标

目标同时实现单次百分号解码、legacy 词法归一化和 hardened 根界钳制。未知扩展
会导致差分触发：

```bash
# 需要 clang（带 libFuzzer runtime）
./scripts/build_fuzz.sh
./scripts/replay.sh
```

脚本会把 stderr 写入 `artifacts/replays/replay.stderr`，并在检测到
`PATH_CANON_DIVERGENCE` 时输出完整复现链。若 `clang` 不可用，可用 GCC 做语义
自检：

```bash
gcc -std=c11 -DPATHNORM_STANDALONE -o pathnorm_replay fuzz/pathnorm_fuzz.c
base64 --decode fuzz/corpus/minimized-01.b64 > /tmp/minimized-01
./pathnorm_replay /tmp/minimized-01
```

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/case` | 完整案件、证据链与报告 |
| POST | `/api/replay` | 重放恢复语料并追加步骤/重放记录 |
| POST | `/api/reviews` | 追加人工确认 |
| POST | `/api/followups/{id}/status` | 更新处置单状态 |
| GET | `/api/export` | 导出完整证据包 JSON |
| GET | `/api/health` | Go / SQLite 健康检查 |

## 验证

```bash
go test ./...
node --check static/app.js
```
