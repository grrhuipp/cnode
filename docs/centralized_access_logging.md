# cnode 集中访问日志设计

状态：cnode 上报端已实现；独立日志服务与 ClickHouse 待实现

更新时间：2026-07-16

## 1. 最终方案

cnode 将结构化访问事件通过网络批量上报给独立日志服务；日志服务完成认证、校验、幂等处理和批量入库，ClickHouse 只由日志服务访问。

```text
cnode Worker
  -> 结构化 AccessEvent
  -> 进程级异步上报器
  -> 本地持久化 spool
  -> HTTPS 批量上报 API
  -> 独立日志服务
  -> ClickHouse
  -> 查询 API / 监控面板 / 用户画像
```

确定的边界：

1. cnode 不直接连接 ClickHouse。
2. Worker 热路径不执行网络请求、压缩、磁盘 I/O 或数据库操作。
3. 日志服务地址、接口和独立认证密钥编译固化在 cnode 中，不接受配置或面板覆盖。
4. 每条日志关联面板 `APIHost`、`NodeType`、`NodeID`、面板名称和用户 ID。
5. 面板身份复用现有 `panels` 配置，不在日志配置中重复填写。
6. 面板 `Key` 不进入日志事件、不写入 spool、不发送给日志服务。
7. ClickHouse 用于明细、聚合和用户画像，不替代现有面板流量上报链路。

## 2. cnode 到日志服务走什么

第一版固定使用：

```text
HTTP/1.1 keep-alive + TLS
POST 批量请求
Protobuf 请求体
zstd 压缩
Bearer Token 认证
应用层 batch_id / sequence ACK
```

建议接口：

```http
POST /v1/access/batches HTTP/1.1
Host: l.bt3.one
Authorization: Bearer <log-service-key>
Content-Type: application/x-protobuf
Content-Encoding: zstd
Connection: keep-alive
X-Cnode-Server-Id: <server-id>
X-Cnode-Schema-Version: 1
```

### 2.1 为什么第一版用 HTTP/1.1 keep-alive

- cnode 已有 Asio + TLS 的 HTTP/1.1 控制面请求实现，技术路径明确。
- 日志按约 250 ms 或 1000 条组成批次，一条长连接即可获得足够吞吐，HTTP/2 多路复用的收益有限。
- 易于接 Nginx、Envoy、负载均衡、鉴权、限流和抓包诊断。
- 服务端可以使用任意语言，不绑定 gRPC 运行时。
- 请求与响应天然对应，方便定义“服务端已可靠接收后才 ACK”的语义。

HTTP 版本不是业务协议的一部分。后续如需要多个并发流，可通过 TLS ALPN 升级为 HTTP/2，保持 URL、认证、Protobuf schema、批次和 ACK 语义不变。

实现时应新建基础设施层日志上报客户端；可以复用底层 Asio/TLS 能力，但不能让上报器调用 V2Board panel client，也不能借用代理协议的 HTTP/2 transport 请求链路。

### 2.2 不选择的方案

| 方案 | 第一版不选原因 |
| --- | --- |
| UDP | 无可靠 ACK，分片、丢包、重放和认证处理复杂 |
| 自定义 TCP 长连接 | 需要自行实现帧、代理兼容、TLS、限流、错误语义和运维工具 |
| WebSocket | 日志是单向批量提交，不需要双向消息会话 |
| gRPC streaming | C++ 依赖和运行时较重，流重连与批次确认仍需自定义语义 |
| HTTP/2 强制模式 | 第一版只有少量长连接和批量请求，多路复用收益不足 |
| Kafka 直连 | 把 broker 地址、协议、认证和背压复杂度下放到所有节点 |
| ClickHouse 直连 | 数据库拓扑、账号和故障会进入 cnode，破坏服务边界 |

## 3. 目标与非目标

目标：

- 集中接收多台 cnode、多个面板和多个节点的访问日志。
- 按面板、节点、用户、时间、目标地址、流量和结果查询。
- 支持亿级及以上明细的压缩存储和聚合分析。
- 日志服务或 ClickHouse 故障不影响代理请求链路。
- 为活跃时段、节点偏好、流量趋势、目标类别和异常行为提供数据基础。

第一阶段非目标：

- 不采集 HTTPS 加密后的完整 URL、正文或响应内容。
- 不采集用户密码、代理协议凭据和面板密钥。
- 不建立绕过 `Inbound -> Dispatcher -> Outbound -> Relay` 的第二条请求链路。
- 不让 Worker、dispatcher、router、relay 理解面板配置。
- 不把集中日志作为计费唯一事实来源。
- 不引入 Kafka；容量或多消费者需求出现后再评估。

## 4. 当前访问日志的缺口

cnode 已有本地异步 error/access 文本日志：error 对齐 Xray 的级别、context ID 和组件格式，access 对齐 Xray 的访问事实格式；relay 结束处另有上下行字节数和关闭原因的 error 诊断信息。

集中分析仍缺少：

- 强类型、可版本化的事件格式。
- 每个 session 唯一的终态事件所有者。
- 开始/结束时间、耗时、上下行字节、最终结果和稳定错误码的统一事件。
- 对 `panel APIHost + NodeType + NodeID` 的稳定关联。
- 断网后的持久化补传和服务端 ACK。

因此不能依靠读取、解析现有文本日志实现集中上报。应新增类型化 `AccessEvent`；文本日志继续用于本地诊断。

## 5. 面板 API 与 NodeID 如何关联

### 5.1 唯一身份

`NodeID` 只在一个面板和节点类型范围内有意义。不同面板或协议可以出现相同 `NodeID`，节点业务唯一身份必须是：

```text
(normalized_panel_api_host, node_type, node_id)
```

面板名称只用于展示，不作为唯一键。日志服务根据规范化后的组合键解析或创建权威 ID：

```text
panel_id  = stable ID of normalized panel APIHost
source_id = stable ID of (panel_id, node_type, node_id)
```

`panel_id` 和 `source_id` 由日志服务管理并写入 ClickHouse，cnode 不需要在启动时向日志服务申请 ID。cnode 控制面只在当前不可变 runtime 内给每个来源分配紧凑 `source_ref`，批次通过来源描述表把 `source_ref` 映射到完整组合键。这样日志服务暂时不可用也不会阻止 cnode 启动或生成可补传事件。

### 5.2 复用现有 panels 配置

现有配置已经包含所需信息：

```json
{
  "panels": [
    {
      "Name": "vmess-panel",
      "Type": "V2board",
      "APIHost": "https://panel.example.com",
      "Key": "panel-api-key",
      "NodeIDs": [1, 2, 3],
      "NodeType": "vmess"
    }
  ]
}
```

约束：

- `Name`、`APIHost`、`NodeType`、`NodeIDs` 仍由 `panels` 管理。
- 日志配置不重复这些字段，避免两套配置漂移。
- `Key` 仅用于面板 API。
- 控制面为每个实际构建的 `(APIHost, NodeType, NodeID)` 创建不可变来源描述和 runtime-local `source_ref`。
- session 创建时绑定准确的紧凑 `source_ref`，不能靠解析 inbound tag 反推。
- Worker 热路径只认识不透明 `source_ref`，不携带或理解面板原始字段。
- 上报器根据不可变快照在批次中附带来源描述，日志服务解析为权威 `panel_id/source_id` 并根据已认证来源登记再次校验。

一个 panel 配置含多个 `NodeID` 时，每个节点必须有独立 `source_ref` 和来源描述；不能只记录 panel 级身份。

### 5.3 APIHost 规范化

日志中的 `panel_api_host` 只保留：

```text
scheme + host + 非默认端口 + 面板基础 path
```

保留用于区分面板部署实例的基础 path；必须移除 query、fragment 和 userinfo，避免把 token 写入日志。

## 6. cnode 固化配置

不增加 `accessLogReport` JSON 配置，也不允许面板下发或运行时覆盖。以下参数编译固化：

| 参数 | 固化值 |
| --- | ---: |
| 服务基址 | `https://l.bt3.one` |
| 批量接口 | `/v1/access/batches` |
| 认证 | 独立 256-bit Bearer Token，代码常量 |
| 未满批次最大等待 | `250 ms` |
| 单批最大事件数 | `1000` |
| 单批 Protobuf 上限 | `1 MiB`，超出自动拆分 |
| 内存队列容量 | `65536` 条事件 |
| spool 最大容量 | `5 GiB` |
| 建连超时 | `3 s` |
| 单次 I/O 超时 | `10 s` |
| 最大重试间隔 | `60 s`，指数退避并加抖动 |

spool 使用现有日志配置的目录，但不新增路径字段：

```text
<Log.LogDir>/access-spool/
```

例如 `Log.LogDir=/opt/cnode/logs` 时，持久化批次位于 `/opt/cnode/logs/access-spool/`。spool 是硬盘持久化，不是内存预分配；正常关机先把内存队列刷入该目录，重启后继续补传。

面板 `Name/APIHost/NodeType/NodeID` 仍来自已有 `panels` 配置，仅远端日志服务参数固化。面板 `Key` 与固化日志密钥相互独立。

## 7. cnode 内部设计

### 7.1 终态事件

每个进入统一 session 的连接最多提交一条规范终态 `AccessEvent`：

- `completed`：正常完成。
- `rejected`：认证或策略拒绝。
- `failed`：路由、拨号、握手或 relay 失败。
- `cancelled`：服务关闭或操作取消。

成功请求照常提交。失败、拒绝或取消的请求在已经识别出非零
`user_id`，并且已经得到单一目标 IP 或域名时也必须提交；认证前噪声、
尚无目标的握手失败以及无法用一个目标表达的容器会话不上传。

事件应在统一 session/dispatcher 生命周期收口，不能由 VMess、Trojan、Shadowsocks、AnyTLS、VLESS、Freedom 等协议各维护一套集中上报逻辑。协议可以继续写本地诊断日志。

### 7.2 热路径

Worker 只允许：

1. 从不可变 runtime/session 读取归一化字段。
2. 构造拥有自身数据的紧凑事件。
3. 非阻塞尝试写入有界队列。

禁止：

- 在 Worker 做 HTTP、TLS、压缩、spool 或 ClickHouse 操作。
- 阻塞等待队列空间。
- 把 `string_view`、Worker 裸指针、handler、stream、allocator 或 buffer provider 交给上报线程。
- 为日志增加跨 Worker 锁。

事件跨线程前必须完成必要复制或所有权转移。上报器只接收值对象和不可变来源快照。

### 7.3 上报器

进程级上报器属于冷路径，负责：

- 消费结构化事件。
- 将 `source_ref` 映射为批次内的不可变来源描述。
- 批量编码和 zstd 压缩。
- 先写 append-only spool，再发送 HTTPS 请求。
- 按 ACK 删除已确认批次。
- 连接复用、超时、重试、退避和指标统计。

上报器不负责路由、协议解析、用户认证或修改 live handler。

## 8. AccessEvent 字段

线上编码使用 Protobuf。字段编号发布后不得复用。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `schema_version` | `uint32` | schema 版本 |
| `event_id` | `bytes[16]` | 全局事件 ID |
| `server_id` | `string` | cnode 实例稳定 ID |
| `boot_id` | `bytes[16]` | 本次进程启动 ID |
| `sequence` | `uint64` | `boot_id` 内单调递增序号 |
| `source_ref` | `uint32` | 当前批次来源描述表的引用 |
| `user_id` | `uint64` | 面板用户 ID，未知时为 0 |
| `conn_id` | `uint64` | cnode 连接 ID |
| `worker_id` | `uint32` | Worker ID |
| `started_at_unix_us` | `int64` | 开始时间，Unix 微秒 |
| `ended_at_unix_us` | `int64` | 结束时间，Unix 微秒 |
| `duration_ms` | `uint64` | 持续时间 |
| `user_email` | `string` | 面板用户邮箱，可选 |
| `inbound_tag` | `string` | 入站 tag |
| `outbound_tag` | `string` | 最终出站 tag |
| `protocol` | `string` | 入站协议 |
| `network` | `enum` | tcp、udp、mux |
| `source_ip` | `string` | 客户端来源 IP |
| `source_port` | `uint32` | 客户端端口 |
| `target_host` | `string` | 请求目标域名或 IP |
| `target_port` | `uint32` | 目标端口 |
| `remote_ip` | `string` | 连接成功后确认的最终目标对端 IP |
| `dial_ip` | `string` | 直连出站最近一次实际尝试拨号的最终目标 IP，失败时仍可用 |
| `local_ip` | `string` | 本地出站 IP，可选 |
| `uplink_bytes` | `uint64` | 上行字节数 |
| `downlink_bytes` | `uint64` | 下行字节数 |
| `result` | `enum` | completed/rejected/failed/cancelled |
| `error_code` | `int32` | cnode 稳定低基数错误码 |
| `close_side` | `enum` | client/remote/local/unknown |
| `dns_state` | `uint32` | none/cache/resolve/failed |
| `sniff_protocol` | `string` | 嗅探协议，可选 |
| `sniff_domain` | `string` | 嗅探域名，可选 |

禁止放入事件：面板 `Key`、日志服务 `Key`、用户密码、UUID 凭据、Trojan 密码、Shadowsocks 密钥、AnyTLS 私有 hash 和任意请求正文。

详细异常文本保留在本地诊断日志；集中事件使用稳定错误码，防止高基数字符串拖累存储和聚合。

## 9. 批次与 ACK

逻辑请求体：

```protobuf
message AccessBatch {
  uint32 schema_version = 1;
  bytes batch_id = 2;
  string server_id = 3;
  bytes boot_id = 4;
  uint64 first_sequence = 5;
  uint64 last_sequence = 6;
  repeated SourceDescriptor sources = 7;
  repeated AccessEvent events = 8;
}

message SourceDescriptor {
  uint32 source_ref = 1;
  string panel_name = 2;
  string panel_api_host = 3;
  string node_type = 4;
  uint64 node_id = 5;
}
```

同一批次中的事件只携带 `source_ref`，面板 API 和节点信息在 `sources` 中只出现一次。日志服务按 `(panel_api_host, node_type, node_id)` 解析权威 `panel_id/source_id`，再把这些字段写入每条 ClickHouse 明细。

成功响应第一版可以使用小型 JSON，便于接收端和运维诊断：

```json
{
  "accepted": true,
  "batch_id": "019f...",
  "acked_through_sequence": 123456
}
```

| HTTP 状态 | 含义 | cnode 行为 |
| --- | --- | --- |
| `200` | 已可靠接收 | 删除已确认 spool 批次 |
| `400` | schema 或字段非法 | 隔离坏批次，不无限重试 |
| `401/403` | 认证或来源无权限 | 停止快速重试并告警 |
| `409` | 批次已处理 | 按成功 ACK 处理 |
| `413` | 批次过大 | 拆小后重试 |
| `429` | 限流 | 按 `Retry-After` 退避 |
| `5xx` | 临时故障 | 指数退避并重试 |

## 10. 可靠性语义

采用“至少一次”交付：

1. 从内存队列组成不可变批次。
2. 批次先写本地 append-only spool。
3. 发送批次。
4. 日志服务完成可靠持久化后返回 ACK。
5. cnode 收到 ACK 后删除 spool 数据。

超时可能发生在服务端已接收但客户端未收到 ACK 的时刻，因此重试会产生重复。`batch_id`、`event_id` 和 `(server_id, boot_id, sequence)` 在重试时必须保持不变；日志服务负责幂等接收或去重。

重试采用指数退避和随机抖动，建议从 500 ms 增长到最多 60 s。认证失败不得高频重试，单个坏批次进入隔离区，不能永久阻塞后续批次。

内存队列满时绝不阻塞 Worker。spool 达到上限后，默认删除最旧批次以保留最近故障证据，同时累计永久丢弃计数并告警。无论日志链路发生什么故障，代理主链路都继续工作。

## 11. 日志服务

写入链路：

```text
HTTPS receiver
  -> token authentication
  -> server/source authorization
  -> size and schema validation
  -> batch idempotency
  -> bounded ingest queue
  -> ClickHouse block writer
  -> durable ACK
```

服务端必须验证：

- 日志密钥是否允许该 `server_id`。
- `server_id` 是否允许上报对应的 `APIHost + NodeType + NodeID`。
- 来源描述规范化后是否匹配已登记来源，并能解析出唯一的 `panel_id/source_id`。
- body 中展示字段不能覆盖服务端登记的权威来源字段。

接收端限制压缩前后大小、事件数、字段长度、时间偏移和枚举值。以上校验、ClickHouse 字段映射和数据库 schema 演进都属于日志服务职责，cnode 只维护带版本号的上报消息格式。ClickHouse 必须按 block 批量写入，不能逐行 INSERT。写入变慢时通过 429/503 施加背压。

## 12. ClickHouse 表

第一阶段使用 `MergeTree`：

```sql
CREATE TABLE access_events
(
    event_time          DateTime64(3, 'UTC'),
    ended_at            DateTime64(3, 'UTC'),
    event_id            UUID,
    schema_version      UInt16,
    server_id           LowCardinality(String),
    boot_id             UUID,
    sequence            UInt64,

    source_id           UInt64,
    panel_id            UInt64,
    panel_name          LowCardinality(String),
    panel_api_host      LowCardinality(String),
    node_type           LowCardinality(String),
    node_id             UInt64,
    user_id             UInt64,

    conn_id             UInt64,
    worker_id           UInt16,
    duration_ms         UInt64,
    inbound_tag         LowCardinality(String),
    outbound_tag        LowCardinality(String),
    protocol            LowCardinality(String),
    network             Enum8('unknown' = 0, 'tcp' = 1, 'udp' = 2, 'mux' = 3),

    source_ip           IPv6,
    source_port         UInt16,
    target_host         String,
    target_port         UInt16,
    remote_ip           IPv6,
    local_ip            IPv6,

    uplink_bytes        UInt64,
    downlink_bytes      UInt64,
    result              Enum8(
                            'unknown' = 0,
                            'completed' = 1,
                            'rejected' = 2,
                            'failed' = 3,
                            'cancelled' = 4
                        ),
    error_code          LowCardinality(String),
    close_side          Enum8(
                            'unknown' = 0,
                            'client' = 1,
                            'remote' = 2,
                            'local' = 3
                        ),
    dns_result          IPv6,
    sniff_protocol      LowCardinality(String),
    ingested_at         DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY
(
    panel_id,
    node_type,
    node_id,
    user_id,
    event_time,
    event_id
)
TTL event_time + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;
```

说明：

- 分区只按月，不按用户、节点或域名制造高基数分区。
- 排序键优先服务面板、节点、用户和时间范围查询。
- IPv4 统一映射为 IPv4-mapped IPv6。
- `target_host` 是高基数字段，保持普通 `String`。
- 明细默认保留 90 天，按磁盘预算和合规要求调整。
- ClickHouse 不提供这里需要的强唯一约束，幂等由接收服务负责。

集群化时可增加本地 `ReplicatedMergeTree` 与对外 `Distributed` 表，cnode API 合同不变。

## 13. 聚合与用户画像

后续建立以下聚合表或物化视图：

- `user_hourly`：连接数、上下行流量、活跃秒数、失败数、活跃节点数。
- `user_daily`：每日流量、活跃时段、目标域名数和节点偏好。
- `node_minute`：节点连接数、流量、错误率、P50/P95 会话时长。
- `domain_hourly`：按面板/节点/用户聚合目标域名，粒度服从隐私策略。

画像 API 优先查聚合表，明细只用于下钻和审计。目标域名分类和异常检测属于日志服务侧异步任务，不能进入 cnode 热路径。

## 14. 安全与隐私

- cnode 到日志服务必须使用 TLS，高安全环境启用 mTLS。
- 日志密钥与面板密钥分离，支持按 `server_id` 轮换和吊销。
- ClickHouse 不直接暴露公网。
- 写入与查询使用不同账号和权限。
- 多面板查询由服务端强制注入租户条件，不能只信客户端的 `panel_id`。
- 明确 IP、域名、明细和聚合数据的保留期。
- 可选对客户端 IP 截断/哈希，只保留注册域，或分类后删除原始域名。

## 15. 可观测性

cnode 至少暴露：

- 队列事件数、spool 字节数和最旧未确认事件年龄。
- 已发送事件/批次数、重试次数和永久丢弃数。
- 被服务端拒绝的批次数、最近 ACK 时间和连接状态。

日志服务至少暴露：

- 请求 QPS、批次大小、认证/来源/schema 失败和限流次数。
- 接收队列深度、ClickHouse 写入延迟、错误率和积压时间。
- 幂等命中数、隔离批次数和 ACK 延迟。

spool 达到 70%/90%、出现永久丢弃、最旧未确认事件持续增长、ClickHouse 写入持续失败或某节点日志量归零时必须告警。

## 16. 实施阶段

### 阶段 1：事件模型

- 定义 `AccessEvent`、错误码和一次性终态提交语义。
- 建立 `(APIHost, NodeType, NodeID) -> source_ref` runtime-local 不可变映射。
- session 绑定准确来源。
- 将分散的协议访问打点收口到统一生命周期。

### 阶段 2：cnode 上报器

- 实现有界队列、Protobuf、zstd 和 HTTP/1.1 TLS keep-alive。
- 实现 spool、ACK、重试、坏批次隔离和容量策略。
- 用 mock 服务测试断网、超时、401、413、429、5xx、重复 ACK 和磁盘满。

### 阶段 3：日志服务与 ClickHouse

- 实现认证、来源注册、批次幂等、校验和写入限流。
- 部署明细表、TTL 和查询 API。

### 阶段 4：聚合与画像

- 建立小时/天聚合表。
- 增加节点质量、用户活跃、流量趋势和目标分类 API。
- 完成查询权限、审计和隐私策略。

### 阶段 5：容量扩展

只有多实例需要共享持久积压、ClickHouse 长时间维护仍需持续接收、峰值超过本地队列/磁盘能力，或多个独立消费者需要同一事件流时，才在日志服务后增加 Kafka。

## 17. 验收标准

1. 每条事件可准确定位 `panel APIHost + NodeType + NodeID + user_id`。
2. 面板密钥、代理凭据和日志服务密钥不出现在事件、spool 和 ClickHouse。
3. 每个连接最多提交一条规范终态事件，重试保持同一 `event_id`。
4. 日志服务不可用时代理主链路无可测退化，事件进入 spool。
5. 服务恢复后自动补传，符合至少一次交付语义。
6. 队列和 spool 都满时代理继续工作，永久丢弃数量可观测。
7. 能按面板、节点、用户和时间查询流量、连接数、失败率和目标地址。
8. Worker 不持有日志 HTTP 客户端、ClickHouse 驱动或面板原始配置。
9. 跨线程事件不引用 Worker-local 对象。
10. 断网、超时、认证失败、限流、重复批次、坏 schema、磁盘满和重启均有自动化测试。

## 18. 后续配套文档

实现前继续补充：

- `access_log.proto` 完整 schema 与字段演进规则。
- 稳定错误码表。
- 日志服务来源注册与密钥轮换协议。
- ClickHouse 日志量、压缩率、磁盘和副本容量测算。
- 日志查询 API 与租户权限模型。
