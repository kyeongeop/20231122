# 并发账户锁定异常重建报告

- 原始材料: `evidence/raw_capture.bin` (284 字节, 只读 0444)
- 原件 SHA256: `95dd9aa9c99ee394eaba5cd2b7b4c1f7b10aa4569f138327efaa0c2dd38d776a` (运行前后一致, 未修改)
- 策略: 连续失败 5 次锁定 15m0s
- 重复对象 RequestID: `aa11bb22cc33dd44ee55ff6600112233`

## 攻击输入 -> 触发位置 -> 权限判断 -> 日志证据

| 证据行 | 时间戳 (UTC) | 原始偏移 | 阶段 | 判定 | 触发位置/详情 |
|---|---|---|---|---|---|
| #1 (00000000…) | 2026-11-21T20:45:08.00285586Z | 8 | parsed | OK | len=42 ts=1795341600000000000 |
| #2 (00000000…) | 2026-11-21T20:45:08.00401159Z | 54 | parsed | OK | len=42 ts=1795341601000000000 |
| #3 (00000000…) | 2026-11-21T20:45:08.00533532Z | 100 | parsed | OK | len=42 ts=1795341602000000000 |
| #4 (aa11bb22…) | 2026-11-21T20:45:08.006754117Z | 146 | parsed | OK | len=42 ts=1795341603000000000 |
| #5 (aa11bb22…) | 2026-11-21T20:45:08.007969537Z | 192 | parsed | OK | len=42 ts=1795341603000000000 |
| #6 (00000000…) | 2026-11-21T20:45:08.009275331Z | 238 | parsed | OK | len=42 ts=1795341604000000000 |
| #7 (00000000…) | 2026-11-21T20:45:08.010620932Z | 8 | authorize | ALLOW | loc=service.go:authorize locked_until=0 now=1795293908 |
| #8 (00000000…) | 2026-11-21T20:45:08.013322817Z | 8 | increment | COUNTED | loc=service.go:read-modify-write fail_count=1 threshold=5 |
| #9 (00000000…) | 2026-11-21T20:45:08.014821729Z | 54 | authorize | ALLOW | loc=service.go:authorize locked_until=0 now=1795293908 |
| #10 (00000000…) | 2026-11-21T20:45:08.017225104Z | 54 | increment | COUNTED | loc=service.go:read-modify-write fail_count=2 threshold=5 |
| #11 (00000000…) | 2026-11-21T20:45:08.018561421Z | 100 | authorize | ALLOW | loc=service.go:authorize locked_until=0 now=1795293908 |
| #12 (00000000…) | 2026-11-21T20:45:08.021204813Z | 100 | increment | COUNTED | loc=service.go:read-modify-write fail_count=3 threshold=5 |
| #13 (aa11bb22…) | 2026-11-21T20:45:08.022601902Z | 192 | authorize | ALLOW | loc=service.go:authorize locked_until=0 now=1795293908 |
| #14 (aa11bb22…) | 2026-11-21T20:45:08.02288331Z | 146 | authorize | ALLOW | loc=service.go:authorize locked_until=0 now=1795293908 |
| #15 (aa11bb22…) | 2026-11-21T20:45:08.026720579Z | 146 | increment | COUNTED | loc=service.go:read-modify-write fail_count=4 threshold=5 |
| #16 (aa11bb22…) | 2026-11-21T20:45:08.028562466Z | 192 | increment | COUNTED | loc=service.go:read-modify-write fail_count=4 threshold=5 |
| #17 (00000000…) | 2026-11-21T20:45:08.029780321Z | 238 | authorize | ALLOW | loc=service.go:authorize locked_until=0 now=1795293908 |
| #18 (00000000…) | 2026-11-21T20:45:08.031097363Z | 238 | login | SUCCESS | counter reset not implemented in recon |

## 异常结论

- 失败事件共 5 次(3 唯一 + 重复对象 2 副本), 计数器终值仅 4, 阈值 5 未达到, 锁定被绕过。
- 丢失更新直接证据: 重复对象两副本的 increment 行记录相同计数 `loc=service.go:read-modify-write fail_count=4 threshold=5`。
- 攻击收益: 随后持合法凭据的探测登录被权限判断放行 (ALLOW=true), 本应在第 5 次失败后被拒。
- 根因: `service.go:dedup-missing` 缺失按 RequestID 去重, `service.go:read-modify-write` 读-改-写无事务保护, 重复对象两副本并发通过 `service.go:authorize` 门闸后互相覆盖计数(丢失更新)。
- 空输入与超大输入已被拒绝并留证(见 evidence 表 empty_input / oversized_input 行)。
