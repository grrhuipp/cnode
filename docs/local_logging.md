# cnode 本地日志规范

## 1. 目标

cnode 本地日志分为三个独立语义通道，文本格式与字段示例统一维护在 [README 日志格式](../README.md#日志格式)：

- error logger：普通诊断、运行错误和连接阶段错误，受 `loglevel` 控制。
- access logger：访问事实，不带级别，不作为 error loglevel 的一部分。
- console logger：启动、控制面与资源状态，受 `loglevel` 控制，致命启动失败除外。

调用方不能自行添加时间、级别、context ID 或组件前缀；这些由日志层统一生成。每条记录固定为单行文本，控制字符由日志层统一转义。

## 2. error 语义

`component` 使用包路径，例如 `app/dispatcher`、`proxy/freedom`、`transport/internet/tcp`。连接关联使用完整 64 位 `conn_id`。日志入队前复制身份字段，后台 writer 不借用 session 或 Worker 内的字符串。未认证连接不输出候选用户身份；认证通过后发生语法、flow、准入或重放拒绝，仍保留已验证身份及已解析目标，不倒退为“未知用户认证失败”。

级别口径：

- `Debug`：内部状态、握手、路由、relay 生命周期；配置 `trace` 也按 Xray 的 `Debug` 标签输出。
- `Info`：低频正常状态变化。
- `Warning`：单请求失败、拒绝、降级或可恢复异常。
- `Error`：影响进程能力、控制面或全局资源的故障。

`LOG_TRACE` 至 `LOG_ERROR` 写普通 error 日志；`LOG_CONN_*` 写带 context ID 的 error 日志；尚未建立 session 的网络诊断使用 `LOG_NET_*`，同样进入 error logger。

Freedom 的 TCP / UDP 拨号失败细节使用 `Debug`；Dispatcher 统一输出请求最终失败的 `Warning`，避免同一次失败在两个层级重复告警。

## 3. access 语义

access 只记录真实的接受或拒绝事实，使用 `LOG_ACCESS`，不带日志级别。调用方须在认证完成、目标已解析后建立会话上下文，再执行可能拒绝请求的策略或准入检查；Mux 子流使用自己的目标。格式化函数不能从空上下文猜测身份、目标、出口或本地地址。

正常无数据 EOF、主动取消与停机不伪造拒绝记录；已收到部分握手后的 EOF 是截断，真正的认证拒绝、协议拒绝和超时分别说明原因。访问事实不因 error 通道限级或 DNS 负缓存诊断聚合而被省略。

## 4. 文件和后端

- 文件命名、轮转和格式配置见 [README](../README.md#日志格式)，不在此维护第二套格式。
- Worker 和协议热路径只做级别判断、消息构造和非阻塞入队。控制台与文件各有独立队列及 writer，不把控制台背压传给文件 writer。
- 控制台队列最多 256 条，每条编码后含换行最多 4096 字节；超长、队列满或暂时不可写时丢弃并累计计数，后续输出机会合并报告。管道记录还受实际 `PIPE_BUF` 限制，以整条写入或整条丢弃；不通过无界排队等待消费者。
- Linux 管道与终端使用独立非阻塞描述符；systemd/journald socket 使用逐次非阻塞发送，不修改调用方共享的 descriptor flags。发生部分写入后退役该控制台 sink，避免后续记录拼接到残缺记录；stdout/stderr 指向同一底层 sink 时共享退役状态。独立诊断输出可用时报告部分写入，两个输出均不可用时不能承诺告警可达。
- 控制台重定向至普通文件时共享原描述符的文件偏移，避免后续直接输出或紧急诊断覆盖既有记录；普通文件的内核 I/O 不因 `O_NONBLOCK` 变成可取消操作，独立 writer 只隔离其对业务执行器的影响。
- 文件 writer 负责落盘、刷新、按日轮转、gzip 和保留期清理。access/error 分别检查 write、flush、close 状态；首次故障经独立控制台报告，故障通道累计丢弃数，另一通道继续工作。
- 文件恢复只由后续真实日志触发，每次事件最多尝试一次，冷却从 1 秒退避至最多 30 秒；成功写入并刷新后报告恢复及丢弃数量。不因固定重试次数耗尽而永久停用，不空闲轮询，不向 access 注入合成探测记录。
- 停机先关闭准入，再收束已准入生产者并排空有界队列；控制台停机不等待读者恢复消费，文件停机不等待故障恢复。

面板状态与上报记录使用结构化字段，不把“配置已加载”误认为“面板已连接”；格式示例见 README。

`status` 中的 `connecting / ready / degraded / missing / unavailable` 分别表示正在首次连接、完整同步成功、部分数据沿用旧快照、面板已删除节点、本轮拉取失败。`report` 汇总节点状态、流量、在线用户和审计结果的上报状态；没有待上报数据时显示 `idle`。

`panel status` 状态行固定每 60 秒输出一次，不跟随面板下发的 `pull_interval` 或 `push_interval` 改变；即使尚未成功连接面板，也会按固定周期输出 `connecting`、`missing` 或 `unavailable`。节点拉取每到面板下发的 `pull_interval` 只尝试一次，失败后等待下一个拉取周期，不在单次调度内连续重试；首次尚未取得面板配置时使用默认 60 秒拉取周期。节点缺失和同步失败等状态变化仍通过 `panel sync` 日志即时记录。

V2Board 节点卡片和 `runtime.nodes` 的 `online` 沿用 v2node 口径：统计本次 push 周期内产生过流量的不同 UID。即使本周期人数为 0，也会发送空 `/push`，及时清除上一周期的在线人数。`report` 状态行中的 `online` 是当前连接快照中的不同 UID，`devices` 是不同的 `UID + IP` 组合；同一用户同时使用多个 IP 时，前者计 1，后者按 IP 数量统计并上报 `/alive`。

首次启动会立即输出 panel 连接状态，但流量和在线人数要等待一个完整的面板 `push_interval` 后首次上报，避免刚启动、尚未积累流量时打印无意义的 0。

## 5. 约束

- error 和 access 不得混写。
- access 不增加级别；`loglevel` 过滤普通 error 与控制台诊断，不隐藏访问事实。
- 不记录密码、UUID 凭据、面板 Key、Bearer Token 或请求正文。
- 不新增协议私有日志队列、直接文件 writer 或跨 Worker 可变日志对象。
