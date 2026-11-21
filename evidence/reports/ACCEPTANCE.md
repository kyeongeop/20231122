# 解析器整数溢出审计 — 验收报告

技术栈: Go + libFuzzer(clang 18, ASan/UBSan) + SQLite

| 案例 | 锚点 | 原始偏移 | 输入大小 | 权限 | 回绕证据 | hardened 结果 | 时间点 (UTC) |
|------|------|---------:|---------:|------|----------|---------------|--------------|
| CASE-A1 | `A1:count*9` | 4 | 8 | DENY | `0x20000000+0x00000009 -> 0x20000000` | record count exceeds cap | 2026-11-21T16:28:51.231780891Z |
| CASE-A2 | `A2:offset+length` | 13 | 23 | DENY | `0xFFFFFFF0+0x00000020 -> 0x00000010` | integer overflow detected | 2026-11-21T16:28:51.242378793Z |
| CASE-A3 | `A3:cursor+length` | 9 | 22 | DENY | `0x00000008+0xFFFFFFF9 -> 0x00000001` | integer overflow detected | 2026-11-21T16:28:51.257053152Z |
| CASE-EMPTY | `-` | 0 | 0 | DENY | `-` | empty input | 2026-11-21T16:28:51.2778852Z |
| CASE-OVERSIZE | `A3:cursor+length` | 9 | 16777216 | DENY | `0x00000008+0xFFFFFFFF -> 0x00000007` | integer overflow detected | 2026-11-21T16:28:51.288477608Z |

## 证据指针

- 原始输入只读快照: `evidence/original/` (权限 0444)
- 工作语料: `evidence/corpus/`
- 哈希清单: `evidence/reports/SHA256SUMS`
- 结构化日志: `evidence/reports/audit.log`
- SQLite 证据库: `evidence/audit.db`
- libFuzzer 复现: `evidence/crashers/ubsan-vulnerable.log`
- hardened 模糊测试: `evidence/crashers/hardened-fuzz-60s.log`
