# cnode 本地日志规范

## 1. 目标

cnode 本地日志对齐 xray-core 的两类日志语义：

- error logger：普通诊断、运行错误和连接阶段错误，受 `loglevel` 控制。
- access logger：访问事实，不带级别，不作为 error loglevel 的一部分。

调用方不能自行添加时间、级别、context ID 或组件前缀；这些由日志层统一生成。每条记录固定为单行 UTF-8 文本，消息中的 CR/LF 会归一化为空格。

## 2. error 格式

无连接上下文：

```text
YYYY/MM/DD HH:MM:SS [Level] component: message
```

带连接上下文：

```text
YYYY/MM/DD HH:MM:SS [Level] [conn_id] component: message
```

示例：

```text
2026/07/19 20:42:06 [Info] [4294967338] app/dispatcher/default_dispatcher: taking detour [direct] for tcp:example.com:443
2026/07/19 20:42:06 [Warning] [4294967338] proxy/freedom/freedom_outbound: dial failed tcp:example.com:443: connection refused
2026/07/19 20:42:07 [Error] infra/access_log_reporter: spool write failed events=1000 bytes=81920
```

级别口径：

- `Debug`：内部状态、握手、路由、relay 生命周期；配置 `trace` 也按 Xray 的 `Debug` 标签输出。
- `Info`：低频正常状态变化。
- `Warning`：单请求失败、拒绝、降级或可恢复异常。
- `Error`：影响进程能力、控制面或全局资源的故障。

`LOG_TRACE` 至 `LOG_ERROR` 写普通 error 日志；`LOG_CONN_*` 写带 context ID 的 error 日志；尚未建立 session 的网络诊断使用 `LOG_NET_*`，同样进入 error logger。

## 3. access 格式

access 对齐 xray-core `AccessMessage`：

```text
YYYY/MM/DD HH:MM:SS from source accepted network:target [inbound -> outbound] email: user
```

示例：

```text
2026/07/19 20:42:06 from 192.0.2.10:52000 accepted tcp:example.com:443 [vless-in -> direct] email: user@example.com
```

access 记录不带 `[Info]`，也不写组件、源码行或 Worker。它只表达访问事实，使用 `LOG_ACCESS` 写入。认证失败、拨号失败和 relay 异常进入 error logger；强类型终态结果由集中日志 `AccessLogSession` 上报，避免在本地 access 中创造第二套终态口径。

## 4. 文件和后端

- error logger 写入 `error_YYYY-MM-DD.log`。
- access logger 写入 `access_YYYY-MM-DD.log`。
- 控制台使用 error 的文本格式。
- Worker 和协议热路径只做级别判断、消息构造和非阻塞入队。
- 后台 writer 负责落盘、刷新、按日轮转、gzip 和保留期清理。
- 队列满时不阻塞 Worker，丢弃数量写入 error logger。

面板控制台日志使用固定的状态行，避免把“配置已加载”误认为“面板已连接”：

```text
panel configured name=jx type=V2board host=https://panel.example.com nodes=[1, 2]
panel status name=jx node=1 state=ready inbound=ready protocol=vmess port=10086 users=120 rules=3 pull=60s push=60s
panel report name=jx node=1 state=ok node_status=ok traffic=ok traffic_users=8 online=ok online_users=5 illegal=idle illegal_events=0
```

`panel status` 的 `connecting / ready / degraded / missing / unavailable` 分别表示正在首次连接、完整同步成功、部分数据沿用旧快照、面板已删除节点、连续重试仍失败。`panel report` 汇总节点状态、流量、在线用户和审计结果的上报状态；没有待上报数据时显示 `idle`。

## 5. 约束

- error 和 access 不得混写。
- access 不增加级别；`loglevel` 只过滤 error logger。
- 不记录密码、UUID 凭据、面板 Key、Bearer Token 或请求正文。
- 不新增协议私有日志队列、直接文件 writer 或跨 Worker 可变日志对象。
