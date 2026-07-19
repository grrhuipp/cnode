# cnode 本地日志规范

## 1. 记录模型

控制台、`error` 和 `access` 文件统一输出 UTF-8 JSON Lines。每一行必须是一个完整 JSON 对象，禁止调用方自行添加时间戳、级别、通道前缀或另起一行。

所有记录固定包含：

| 字段 | 类型 | 语义 |
| --- | --- | --- |
| `timestamp` | string | UTC RFC 3339，微秒精度 |
| `level` | string | `trace` / `debug` / `info` / `warn` / `error` |
| `channel` | string | `system` 或 `connection` |
| `component` | string | 从源码路径归一化出的稳定组件名 |
| `event` | string | 稳定的点分事件名；普通诊断为 `diagnostic` |
| `message` | string | 人可读详情；换行和控制字符由日志层转义 |
| `source_line` | integer | 产生日志的源码行 |

带 session 上下文的连接记录额外包含：

| 字段 | 类型 | 语义 |
| --- | --- | --- |
| `conn_id` | integer | Worker 生成的连接 ID |
| `worker_id` | integer | 该连接所属 Worker |
| `inbound` | string | 归一化后的 inbound tag |

示例：

```json
{"timestamp":"2026-07-19T12:00:00.123456Z","level":"info","channel":"connection","component":"proxy.freedom.freedom_outbound","event":"connection.accepted","conn_id":42,"worker_id":1,"inbound":"vless-1","message":"outbound=direct network=tcp target=example.com:443","source_line":359}
```

## 2. 通道边界

- `system`：启动、配置、控制面、资源状态、后台任务和不属于具体连接的故障，写入 `error` 文件。
- `connection`：协议解析、transport、路由、出站、relay 和连接终态的本地诊断，写入 `access` 文件。
- 控制台只用于操作者需要立即看到的启动与状态信息，记录格式与文件一致。
- 集中式 `accesslog::Event` 是强类型终态业务事件，继续由 `AccessLogSession` 唯一提交；它不与本地 JSON 文本记录合并，也不允许从文本反向解析生成。

文件名是存储目标，不是日志语义。调用方只能选择 `system` 或 `connection`，不能直接写文件。

## 3. 调用规则

- 使用 `LOG_TRACE` 至 `LOG_ERROR` 写 system 诊断。
- 有 `session::Context` 时使用 `LOG_CONN_*`，由日志层自动复制 `conn_id`、`worker_id` 和 `inbound`。
- 尚未建立 session 的网络路径使用 `LOG_NET_*`。
- 具有稳定业务语义的连接事件使用 `LOG_CONN_EVENT`，事件名采用小写点分格式，例如 `connection.accepted`。
- `message` 只描述事件详情，不再写 `[Module]`、时间、级别、连接 ID、Worker ID 或 inbound；这些字段属于统一 envelope。
- 字段式详情统一使用 `snake_case=value`。不得记录密码、UUID 凭据、面板 Key、Bearer Token、完整请求正文或其他秘密。

## 4. 级别口径

- `trace`：逐帧、逐包或状态机细节，只用于深度诊断。
- `debug`：连接阶段、路由结果、握手和 relay 生命周期。
- `info`：低频正常状态变化和明确的业务事件。
- `warn`：请求可隔离失败、降级、拒绝或可恢复异常。
- `error`：影响进程能力、控制面持续运行或全局资源的故障。

认证失败、单连接拨号失败等连接级问题不得仅因“失败”写入 system `error`；它们属于 connection `warn`。同一事实只记录一次，终态结果由 `AccessLogSession` 负责。

## 5. 演进约束

- 新增顶层字段必须先更新本规范和格式契约测试。
- `event` 一旦用于监控或查询，不得复用为其他语义。
- 不增加绕过 `Log` 的文件 writer、协议私有日志队列或 Worker 共享可变日志状态。
- 日志后端可调整队列、轮转和压缩实现，但不能改变 Worker 只做非阻塞入队的边界。
