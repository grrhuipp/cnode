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

带连接上下文、尚未认证用户：

```text
YYYY/MM/DD HH:MM:SS [Level] [conn_id] component: message
```

认证成功且用户 ID 为正数时，连接日志同时携带入站标签和用户 ID：

```text
YYYY/MM/DD HH:MM:SS [Level] [conn_id] component: inbound=tag user=id message
```

`component` 对齐 xray-core 包路径，例如 `app/dispatcher`、`proxy/freedom`、`transport/internet/tcp`。`conn_id` 只输出 Worker 本地 32 位序号。日志入队前复制身份字段，后台 writer 不借用 session 或 Worker 内的字符串。未认证连接不输出用户身份字段。失败消息保留 `source -> target via outbound` 和原因。

示例：

```text
2026/07/19 20:42:06 [Debug] [10] proxy/freedom: inbound=vless-in user=123 failed to dial 192.0.2.10 -> example.com:443 via direct > connection refused
2026/07/19 20:42:06 [Warning] [10] app/dispatcher: inbound=vless-in user=123 failed to process outbound traffic 192.0.2.10 -> example.com:443 via direct > outbound connection failed
```

级别口径：

- `Debug`：内部状态、握手、路由、relay 生命周期；配置 `trace` 也按 Xray 的 `Debug` 标签输出。
- `Info`：低频正常状态变化。
- `Warning`：单请求失败、拒绝、降级或可恢复异常。
- `Error`：影响进程能力、控制面或全局资源的故障。

`LOG_TRACE` 至 `LOG_ERROR` 写普通 error 日志；`LOG_CONN_*` 写带 context ID 的 error 日志；尚未建立 session 的网络诊断使用 `LOG_NET_*`，同样进入 error logger。

Freedom 的 TCP / UDP 拨号失败细节使用 `Debug`；Dispatcher 统一输出请求最终失败的 `Warning`，避免同一次失败在两个层级重复告警。

## 3. access 格式

access 以简短的 `from source accepted network:target` 记录访问事实；入站、出口标签相同时只写一次。用户有数字 ID 时优先写 `user:id`，否则写 `user:email`；连接建立后若能取得出站 socket 的实际本地 IP，则写 `sendThrough:IP`，它不是配置中的网段，也不是远端地址。没有已连接的出站 socket 时不伪造该字段。

```text
2026/07/19 20:42:06 from 192.0.2.10:52000 accepted tcp:example.com:443 [vless-in -> ipv6_first] user:714443 sendThrough:2602:2b5:20:111::abcd
```

access 不带 `[Info]`，也不写组件、源码行或 Worker。使用 `LOG_ACCESS` 写入；认证失败、拨号失败和 relay 异常进入 error logger。

## 4. 文件和后端

- error logger 写入 `error_YYYY-MM-DD.log`。
- access logger 写入 `access_YYYY-MM-DD.log`。
- 控制台使用相同的时间与级别，但不写 component：`YYYY/MM/DD HH:MM:SS [Level] message`。
- Worker 和协议热路径只做级别判断、消息构造和非阻塞入队。
- 后台 writer 负责落盘、刷新、按日轮转、gzip 和保留期清理。
- 队列满时不阻塞 Worker，丢弃数量写入 error logger。

面板控制台日志使用固定的状态行，避免把“配置已加载”误认为“面板已连接”：

```text
Panel jx: configured | V2board | nodes [1, 2] | https://panel.example.com
Panel jx/1 status: ready | inbound ready | vmess:10086 | users 120 | rules 3 | pull/push 60s/60s
Panel jx/1 report: ok | node ok | traffic ok/8 | online ok/5 | devices 7 | illegal idle/0
```

`status` 中的 `connecting / ready / degraded / missing / unavailable` 分别表示正在首次连接、完整同步成功、部分数据沿用旧快照、面板已删除节点、本轮拉取失败。`report` 汇总节点状态、流量、在线用户和审计结果的上报状态；没有待上报数据时显示 `idle`。

`panel status` 状态行固定每 60 秒输出一次，不跟随面板下发的 `pull_interval` 或 `push_interval` 改变；即使尚未成功连接面板，也会按固定周期输出 `connecting`、`missing` 或 `unavailable`。节点拉取每到面板下发的 `pull_interval` 只尝试一次，失败后等待下一个拉取周期，不在单次调度内连续重试；首次尚未取得面板配置时使用默认 60 秒拉取周期。节点缺失和同步失败等状态变化仍通过 `panel sync` 日志即时记录。

V2Board 节点卡片和 `runtime.nodes` 的 `online` 沿用 v2node 口径：统计本次 push 周期内产生过流量的不同 UID。即使本周期人数为 0，也会发送空 `/push`，及时清除上一周期的在线人数。`report` 状态行中的 `online` 是当前连接快照中的不同 UID，`devices` 是不同的 `UID + IP` 组合；同一用户同时使用多个 IP 时，前者计 1，后者按 IP 数量统计并上报 `/alive`。

首次启动会立即输出 panel 连接状态，但流量和在线人数要等待一个完整的面板 `push_interval` 后首次上报，避免刚启动、尚未积累流量时打印无意义的 0。

## 5. 约束

- error 和 access 不得混写。
- access 不增加级别；`loglevel` 只过滤 error logger。
- 不记录密码、UUID 凭据、面板 Key、Bearer Token 或请求正文。
- 不新增协议私有日志队列、直接文件 writer 或跨 Worker 可变日志对象。
