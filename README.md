# cnode

cnode 是面向 V2Board 面板的高性能代理节点服务端。项目使用 C++23、Asio 协程和 Worker-local 资源模型实现，在保留 xray-core 配置语义的同时，把面板同步、配置归一化、协议处理和流量转发拆成清晰的运行边界。

## 文档分工

- `README.md` 面向使用者和贡献者，说明项目定位、运行架构、配置入口、关键语义和代码组织。
- `AGENTS.md` 面向代码修改和自动化协作者，记录必须遵守的职责边界、禁止项、审查清单和硬性删除规则。
- [`docs/local_logging.md`](docs/local_logging.md) 规定对齐 xray-core 的 error/access 文本格式、通道和级别口径。

如果只是部署、配置或了解项目，从本文件开始；如果要改代码、做重构或接入新协议/面板，先读 `AGENTS.md`。

## 项目定位

- 支持 VMess、VLESS、Trojan、Shadowsocks、AnyTLS、Freedom、Blackhole。
- 支持 TCP、TLS、WebSocket、PROXY protocol、原生 datagram、UDP-over-TCP 和 Mux/子流。
- 支持单进程接入多个 V2Board 面板和多个节点。
- 支持 geoip、geosite、域名、IP、端口、协议、用户等路由条件。
- 默认按多 Worker 运行；每个 Worker 同构，各自拥有全部监听和热路径资源。进程只共享启动后只读的快照、有界日志队列和控制面。
- 部署脚本 `scripts/cnode.sh` 不带参数时更新默认线上二进制及 `geoip.dat`、`geosite.dat`；数据变化后会重启原本运行中的服务以加载新规则，下载失败保留旧数据。`-variant <name>` 可选择 release 变体，`-debug_file true` 会额外下载匹配的 `.debug` 符号文件。

## 架构总览

所有 TCP / UDP 请求最终只能经过一条数据链路：

```text
Inbound Handler::Process
  -> Dispatcher::Dispatch
  -> Outbound Handler::Process
  -> Relay
```

原生 datagram、UDP-over-TCP 和 Mux/子流可以有必要的窄 helper，例如 UDP framer、`DispatchUDP` 或 `DialUDP`。这些 helper 只服务主链路语义：inbound 解析并生成 metadata，dispatcher 做路由，outbound 准备 Worker-local 出站资源，relay 以协议无关方式搬运数据。

运行时主链路：

```text
main
  -> bootstrap
  -> Worker(per-core)
  -> listener / accept
  -> TransportStack(TCP / TLS / WebSocket / PROXY protocol)
  -> InboundHandler(VMess / VLESS / Trojan / Shadowsocks / AnyTLS)
  -> Dispatcher::Dispatch(immutable DispatchPolicy)
       -> sniffing
       -> forced outbound, or Router matched-rule decision
       -> no-match explicit inbound fallback
       -> RequestPolicy allow / block
       -> outbound handler lookup
  -> OutboundHandler(Freedom / VMess / VLESS / Trojan / Shadowsocks / AnyTLS / Blackhole)
  -> Relay(TCP / UDP / Mux)
```

每个 Worker 独立绑定同一组端口（`SO_REUSEPORT`），连接不跨线程迁移。跨线程控制面经有界 mailbox 投递；用户认证、DNS L2 和 Geo 以不可变 snapshot 共享，不共享 live handler、会话或 allocator。

这条边界沿用 xray-core 的关键做法：proxyman / ingress 在冷路径准备 receiver 语义，公开 Dispatcher 只接收请求所需的窄契约；强制出口和未命中回退属于 Dispatcher 编排，Router 只回答“哪条路由规则命中”。每个 receiver 必须在构建时明确选择 `ForceOutbound` 或 `RouteWithFallback`，不存在 Worker 全局默认出口，也不存在可进入热路径的空策略。cnode 使用强类型、只读 `DispatchPolicy`，不把完整 `ReceiverSettings` 或可变配置 context 传入 Dispatcher。面板 `DetectRule` 由 Worker-local 实现通过通用 `RequestPolicy` 接口提供 allow / block 结果，不进入 Router，也不让 Dispatcher 依赖面板规则管理器。

控制面链路：

```text
service/controller
  -> api/*
  -> panel node / user / rule fetch
  -> config normalization
  -> prepared inbound / outbound / routing runtime
  -> atomic Worker runtime snapshot replace
```

用户存储链路：

```text
api/* panel users
  -> api::UserInfo
  -> controller RuntimeUser normalization
  -> proxy/<protocol> user builder registration
  -> proxyman::inbound::UserSet
  -> UserStore immutable RCU snapshot
  -> inbound validator read-only auth
```

DNS 缓存链路：

```text
Worker DNS service
  -> Worker-local L1 cache
  -> GlobalDnsCache sharded immutable RCU snapshot
  -> upstream DNS query
  -> publish DNS result snapshot
```

## 职责速览

| 层级 | 负责 | 不负责 |
| --- | --- | --- |
| inbound | 认证、入站协议解析、用户识别、目标地址解析、session metadata、调用 dispatcher | 路由选择、出站连接、relay 细节、访问 outbound manager 内部结构 |
| dispatcher | 接收只读 DispatchPolicy / session / link；编排 sniff、强制出口、Router 规则、显式 fallback、通用 RequestPolicy；选择 handler 并调用 outbound.Process | 接收完整 ReceiverSettings、依赖具体 DetectRule manager、维护全局默认出口、解析协议、协议特判、执行 relay、读取 panel 字段 |
| router | 通过 `routing::Router` 只读契约查询真实规则命中；具体实现在所属 Worker 冷路径一次构建不可变规则 | 原地重配规则、强制出口、隐式默认出口、未命中 fallback、创建连接、访问 outbound manager / relay / 协议实现 |
| request policy | 基于统一 session context 返回 allow / block；Worker-local 实现可记录策略命中 | 路由选择、outbound handler 查找、协议解析、暴露面板原始字段 |
| outbound | 建立目标连接或下一跳连接，执行出站协议握手和编码，交给 relay | 路由决策、读取 panel 原始配置、绕过 dispatcher |
| relay | TCP / UDP / Mux 数据搬运和流量统计打点 | 解析协议、选择 outbound、访问 panel、暴露 wrapper API |
| Worker | 事件循环、accept 生命周期、运行态组件持有、thread-local allocator / buffer provider | 协议解析、路由、panel 同步、理解具体 validator 或 outbound 类型 |
| control plane | 面板同步、配置归一化、runtime 构建、快照发布、状态与流量上报 | 进入热路径、直接改 live handler、访问 Worker buffer provider |

更完整的边界规则、禁止项和删除标准见 `AGENTS.md`。

## 配置设计

默认主配置文件为 `config.json`。cnode 与 XrayR YAML 配置布局有意不同：cnode 使用 JSON 作为部署配置格式，进程级字段保留在 `config.json`，代理条目使用 xray-core object shapes 放在同目录侧车文件中。

目录模式固定读取：

```text
config.json
inbounds.json
outbounds.json
routing.json
geoip.dat
geosite.dat
```

`inbounds.json` 可以是入站对象数组，也可以是 `{ "inbounds": [...] }`；`outbounds.json` 同理支持 `{ "outbounds": [...] }`；`routing.json` 可以直接是 routing 对象，也可以是 `{ "routing": { ... } }`。不支持的 xray-core 字段可以被忽略，但不能为了支持已有能力再引入第二套 cnode-only schema。

仓库 `config/*.json.example` 只作为样例文件；实际部署和目录模式读取的文件名不带 `.example`，固定为 `config.json`、`inbounds.json`、`outbounds.json`、`routing.json`。

推荐部署目录：

```text
/opt/cnode/
  cnode
  config/
    config.json
    inbounds.json
    outbounds.json
    routing.json
    geoip.dat
    geosite.dat
  log/
    access_YYYY-MM-DD.log
    error_YYYY-MM-DD.log
    access_YYYY-MM-DD.log.gz
    error_YYYY-MM-DD.log.gz
```

启动命令可以显式指定文件或目录：

```sh
./cnode --config-file /opt/cnode/config/config.json
./cnode --config-dir /opt/cnode/config
./cnode -c /opt/cnode/config
```

`-c, --config <path>` 会自动判断路径是文件还是目录；`--config-file` 用于只接受配置文件路径；`-C, --config-dir` 用于只接受配置目录路径。目录模式只读取上述固定文件名，不回退到 YAML 入口，也不读取旧 sidecar path 字段。

## Release 产物

GitHub Release 发布正常 Release 二进制和独立 `.debug` 符号文件。默认兼容资产 `cnode-linux-amd64` 指向 `musl+epoll`；显式资产包括：

```text
cnode-linux-amd64-musl
cnode-linux-amd64-musl-io_uring
cnode-linux-amd64-glibc
cnode-linux-amd64-glibc-io_uring
```

对应符号文件使用同名 `.debug` 后缀。需要 heaptrack、perf 或 core dump 符号时，优先使用 glibc 变体和匹配的 `.debug` 文件；不需要单独 heaptrack release channel。

部署脚本默认仍下载 `cnode-linux-amd64`。如需选择后端或 libc 变体：

```sh
bash scripts/cnode.sh -variant musl-io_uring
bash scripts/cnode.sh -variant glibc -debug_file true
```

配置进入 Worker 前必须完成归一化。Worker 热路径只读取不可变 runtime snapshot；控制面更新时以原子替换快照的方式发布，新旧连接按生命周期自然释放。

## 关键语义

- `ProxyProtocol` 是 cnode 自有三态设置：`"off"`、`"auto"`、`"on"`。省略 `ProxyProtocol` 时默认使用 `"auto"`。
- `SendIP: "auto"` 表示 direct outbound 优先绑定入站连接命中的本地 IP，用于多 IP 服务器源进源出。
- `EnableDNS` 默认值为 `true`。
- 每条 TCP relay 连接的每个方向最多挂起一个 8KB payload Buffer，双向 payload 容量总计 16KB；空闲时先等待可读事件、不持有 payload Buffer，持续流量通过连续读取推进。
- 嗅探只复制至多 4KB 的必要前缀，临时拼接缓冲在嗅探完成后立即释放；仅实际首包 payload 的所有权继续传给出站。
- 首包以 MultiBuffer 按值转交出站，再进入普通上行 relay 循环，与后续数据共用限速、错误分类和统计。VLESS、Trojan、AnyTLS 的握手只写协议控制数据，用户数据由 relay 发送；结果字节数、会话字节数和流量统计保持一致，发送失败不计入成功流量。
- 首包容器只允许移动；单块缓冲通过 BufferGuard 转移所有权。追加、搬移和前缀拆分先完成分配准备再提交；内存不足时保留原有字节和长度，失败的单块插入自动释放交入的缓冲。
- 每个转发方向按 bytes/s 独立限速，初始额度为一秒流量，空闲积累最多两秒；限速等待已经消费对应的未来额度，等待结束不会重复补发。relay 半关闭截止时间和方向失败会取消限速等待，超时后不再发送排队数据；两个方向结束后才释放等待对象和截止回调。
- relay 从控制端点、出站逻辑流和 UDP 请求接收终止事件，同时结束同伴 I/O 与限速等待，并保留超时、取消或资源不足的实际原因。没有客户端控制对象的子流也执行 uplinkOnly/downlinkOnly 的剩余方向预算；父协程退出前等待全部传输和停止任务结束。
- 每个读端都提供通用取消来源，Mux、AnyTLS 和原生 UDP 入站子流沿 Link 传到 relay。取消当前操作与永久关闭分别处理；已取消子流在 relay 开始前就会被识别，排队首包不会在等待结束后继续发送。Link 同时传递 EOF 和写关闭语义，relay 区分 TCP 半关闭与完整逻辑关闭，完整关闭会结束两个方向的 I/O 和限速等待。
- gRPC / HTTP/2 的 END_STREAM 通过读端 EOF 语义关闭目标写方向，并允许反向数据继续传输；协议 TCP reader 保留底层语义。DATA 和控制帧共用所属 Worker 的异步写入门，完整帧写完后才允许下一次写入。VMess 在协议内部编码结束帧，关闭失败沿请求错误路径返回；空响应也先发送响应头。
- gRPC Hunk 的单条未压缩 protobuf 消息正文最多 4 MiB。接收长度头不预分配消息存储，正文按实际收到的字节增长；完整校验后才交付 data，重复字段取最后一个，消费或关闭后释放消息存储。该存储与 relay 的 8KB payload Buffer 分开计量。发送端将较大写入分成多条有界 Hunk，接收端拒绝超限、压缩或畸形消息。
- gRPC、h2 和 XHTTP 的 HTTP/2 服务端共用会话、流准入、HPACK 状态及控制帧处理。每个连接最多接纳 256 个并发流；超过容量以 REFUSED_STREAM 拒绝新流，单流接收队列超过 4 MiB 时以 ENHANCE_YOUR_CALM 重置该流，已有流继续工作。无效 RST_STREAM 属于连接错误，以 GOAWAY 报告并关闭连接。
- V2Board Shadowsocks 2022 节点会自动使用面板下发的 `server_key` 作为 identity PSK，并按 V2Board 规则从用户 UUID 前缀构造用户 PSK；无需把订阅中的两段式密码回填到用户表。
- Shadowsocks 和 AnyTLS inbound 会自动识别 UoT v2（`sp.v2.udp-over-tcp.arpa`）及 v1（`sp.udp-over-tcp.arpa`）。Shadowsocks outbound 可用 `"uot": true` 开启 UoT（默认 v2），以 `"uotVersion": 1` 选择 v1；也接受 `"udp_over_tcp": {"enabled": true, "version": 2}`。
- VMess outbound 的 UUID 和 Shadowsocks outbound 的加密方法、密码会在加载配置时验证。Shadowsocks 省略 `method` 时使用 `aes-256-gcm`；显式的空值、非字符串或未知方法会报错。SS2022 每段 PSK 必须符合所选方法的密钥长度，身份链只支持 AES 方法，不能包含无效或空片段；错误配置不会启动服务。
- VLESS outbound 的 Vision flow 要求 TCP 搭配 TLS 或 Reality；明文 TCP、WebSocket 等组合会在加载配置时被拒绝。VLESS 的 1–30 字节自定义 ID 仍按 UUIDv5 映射，与入站使用同一转换。
- AnyTLS outbound 的 `idleSessionCheckInterval`（默认 30 秒）驱动各 Worker 的周期检查，`idleSessionTimeout`（默认 60 秒）决定空闲到期时间；`minIdleSession`（默认 0）保留该 Worker 最近归还的已建立空闲会话。占用中的会话不参与空闲淘汰，handler 退役时关闭其会话并取消检查。
- AnyTLS 出站请求使用统一的 relay 空闲、写入和半关闭超时；持续接收数据不会延长半关闭的绝对截止时间。取消受阻写入会关闭物理会话；成功请求归还前清除请求超时，空闲连接的寿命随后由会话池控制。
- Freedom 和 Shadowsocks 原生 UDP 出站使用同一套请求级端点和 relay；写入超时包含域名解析等待，取消一个请求不关闭其他请求共享的 UDP socket。上行半关闭后，在 `timeouts.downlinkOnly` 指定的时间内继续接收回包。每个请求最多排队 256 个原始回包、合计 512 KiB，超限会结束该请求并保留资源不足错误；流量只在成功发送后计入。
- 本地日志：`error` 保存受 `loglevel` 控制的诊断与错误，`access` 保存无级别的访问事实。默认启用 `rotateDaily` 和 `gzip`：`access` / `error` 配置作为基础文件名，运行时写入 `access_YYYY-MM-DD.log` / `error_YYYY-MM-DD.log`，历史日志轮转后压缩为 `.gz`，`maxDays` 控制保留天数。不提供集中上传。
- 面板 `DNSType` 会映射到 freedom outbound 的 `settings.domainStrategy`，取值对齐 xray-core freedom outbound。
- 静态 outbound 的顶层 `sendThrough` 可填单个源 IP、`auto`，或按优先级排列的 IP/CIDR 数组；数组只匹配配置加载时本机已分配且与目标同地址族的 IP，不生成网段内新地址。本机地址变更需重新加载配置。CIDR 命中多个地址时由 `sendThroughStrategy` 选择：默认 `hash`（入站源 IP＋源端口），也可设 `random`。每个目标地址族仅选定一个源 IP：绑定或连接失败不更换同族源 IP；若有同族配置但全部不可用，不回退系统默认源 IP；只有完全没有同族配置才由系统选择。`settings.domainStrategy: "UseIPv6v4"` 下 IPv6 目标失败仍可尝试 IPv4 目标，IPv4 单独选源 IP；若目标已由路由预先解析为单个 IP，则不会重新查询另一地址族。UDP 域名逐包解析，建立 socket 前无法获知每包最终地址族；数组绑定依据请求初始目标地址族。原有字符串 `sendThrough` 行为不变。
- 未显式配置 `inboundTag` 的路由规则匹配所有入站；只有显式写出 `inboundTag` 时才限制入站来源。
- 静态 inbound 未指定 `outboundTag` 时参与 routing，未命中回落内置 `direct`；指定 `"outboundTag": "出口标签"` 时强制使用该出口，不经过分流（即使规则可命中）。标签必须指向已配置或内置的静态 outbound；不存在或为空会拒绝启动。旧字段 `routingEnabled` 已移除，原先设置 `false` 的入站如需保持直连，请改为 `"outboundTag": "direct"`。
- 面板创建的 direct outbound 是 routing 未命中时的 fallback，命中规则始终优先生效。
- 出口列表顺序不表达默认出口；动态增删 outbound 不会改变其他 receiver 的选择。明确的 forced / fallback tag 不存在时请求失败，不隐式切换到第一个 outbound。
- AnyTLS 使用 TLS session pool、单物理 session read loop、按 sid demux、共享 session 串行写，以及 `settings.users` 和 `settings.paddingScheme` 配置。

AnyTLS FIN 关闭整个逻辑流：远端 FIN 之前的已接收数据按有界队列排空，同时停止新的反向写入且不回复 FIN；本地关闭只发送一次 FIN。请求的两个方向结束后，完整且正常的物理会话可供新流复用；物理帧写入中断则关闭会话。第四十八轮已通过固定提交官方实现对照、双向直接互通和提前 FIN 检查，验证范围及当前环境限制见[架构审查记录](docs/architecture-review-20260909.md#第四十八轮anytls-完整关闭与-tls-取消传递)。
- REALITY 当前只实现原生 TLS 1.3 + Ed25519 认证握手，不实现未认证连接的 `dest` / `target` 回落、uTLS `fingerprint` 模拟、`spiderX` 爬虫或 ML-DSA-65 证书附加签名/验证；配置这些字段或启用非零 `xver` 会在启动时明确拒绝。

## 运行时状态

面板用户、静态用户和测试用户最终进入同一套认证存储模型。面板客户端只把原始响应解析为 `api::UserInfo`；Controller 只做字段归一化、差量对比和发布触发；协议私有凭据构建由 `proxy/<protocol>` 注册的 user builder 完成，输出统一的 `UserSet`。热路径 validator 只加载 `UserStore` 的不可变视图做认证。

启动时，静态配置和测试模式先合并为同一组普通入站配置，统一校验主标签及监听端点，再通过协议注册入口准备全部 handler 配置和用户。准备阶段不改写用户存储或 Worker；全部准备成功后，一次发布完整的启动用户批次，再启动监听。批次构建失败不会发布部分用户更新。

传输配置归一化返回独立的新值，只有成功后才替换调用者持有的配置；分配失败可由冷路径捕获，不改写输入或终止进程。JSON 解析与传输模式、ALPN 的值转换分开实现。出站协议在注册配置的准备阶段完成归一化，各 Worker 的 handler 直接消费该结果。

`--test` 仍提供 `test-vmess-10086` 入站；未配置面板和静态入站时也会启用该默认测试入站。它与普通静态入站使用相同的准备流程，同名标签或重叠监听会在 Worker 创建之前报错，不能通过追加测试入站覆盖已有配置。

DNS service 不是全局共享对象。每个 Worker 持有绑定自身 `io_context` 的 DNS service、inflight resolve 表、UDP socket、timeout scheduler 和 L1 cache。进程级 `GlobalDnsCache` 只保存 DNS 结果的不可变分片快照，热路径只做 atomic load 和只读查询。

`dns.servers` 中每项可以是裸 IPv4/IPv6（默认 UDP 53），或指定端口的 `127.0.0.1:5353`、`[::1]:5353`。IPv6 带端口时必须使用方括号，端口为 1–65535 的十进制整数；只接受 IP，不使用域名解析 DNS 服务器。配置加载时完成地址与端口拆分并发布完整 endpoint，各 Worker 直接按列表顺序使用；解析、默认值和平台字符串兼容不进入查询路径。

IP 字段必须是完整地址：IPv4 使用四段无前导零的十进制格式，IPv6 可使用数字 scope ID（如 `fe80::1%3`），不接受 `%eth0` 等接口名。`sendThrough` 数组项也可使用规范 CIDR。单独的 host、listen、sendThrough 等字段不接受端口、方括号、空白或 NUL 后缀。方括号仅用于支持 endpoint 或 URL 的入口，且括号内必须是 IPv6；出站服务器字段也可以使用合法 DNS 主机名。旧版在部分平台上接受的地址简写或多余后缀不再兼容。

回调型连接超时由每个 Worker 的 TimeoutScheduler 汇聚到一个在途定时等待。取消事件不会重新分配等待或影响其他事件，取消索引在原存储中整理。限速、Mux 背压和 accept 退避的协程休眠由 AsyncDelay 直接等待可取消定时器，不再通过调度回调和通知 channel 中转；只有所属 Worker 能操作这些对象，销毁前必须收束在途协程。

同一 Worker 的并发同域查询共享一次解析和完成信号，每个调用者独立取得结果。等待者取消不会取消其他请求；缓存写入分配失败也不会丢失已经取得的答案。L1 在完整构建新条目后才淘汰旧条目，从 L2 回填时保留剩余 TTL。

Worker-local 无锁设计的前提是单 Worker 所有权。Worker 私有 manager、handler 表、listener slot、UDP session、stats shard、allocator 和 buffer provider 只能在所属 Worker 线程访问；跨线程控制面必须通过投递、不可变 snapshot 或明确同步的冷路径完成。

控制面批量任务在所有已启动的子任务结束后才返回。取消和部分启动失败遵守同一完成边界，避免子任务继续访问已经销毁的聚合结果或调用者状态。

Dispatcher 通过实际读端的取消来源管理完整请求，覆盖嗅探、路由 DNS、出站连接和握手，以及 relay。已停止的请求不再选择出站；取消后等待请求清理完成，再释放负载计数和记录终态。逻辑子流无需持有物理控制端即可取消自己的请求；正常 relay 收尾不改变已完成结果，嗅探的内存不足及逻辑链路错误保留原分类。

运行状态采样和统计输出是独立的常驻监控循环。每个循环持有自己的上下文，退出或失败时立即记录循环名称及原因，不等待其他监控循环结束。

每个面板的同步与状态输出分别运行独立循环，退出时立即记录面板名称、节点 ID 与循环职责。状态循环启动时输出一次，之后按稳态时钟每 60 秒读取最后提交的节点状态；网络请求的等待不会阻塞心跳，错过的周期不补发日志。同步循环继续按面板下发间隔拉取和推送，首次推送延后一个完整间隔。活动循环持有控制面上下文，控制面通过弱引用记录循环，避免形成循环持有；有限的 Worker 聚合任务继续使用等待全部完成的批量入口。

Mux 和 AnyTLS 的帧处理循环及运行中创建的子请求由同一 Worker 的有限任务组持有，Mux 后台读取也在该任务组内。会话整体退出时终止逻辑读端并取消任务组内的异步操作，覆盖尚未进入 relay 的等待；各协程实际完成后才释放会话数据、transport 和在线会话租约。父任务取消与部分启动失败也遵守这一顺序。正常逻辑 FIN 继续排空已接收数据，任务组仅负责生命周期，子请求仍经过 Dispatcher、outbound 和 relay。

AnyTLS 每个 Session 的新 stream ID 必须严格递增且非零，允许跳号；活动 ID、已经结束的 ID 和回绕后的 ID 均不能重用。非法 SYN 会收到 Alert 并结束该会话，SYN 本身不能携带数据。每条子流独立持有请求上下文，其任务从逻辑字节流解析目标和 UoT 请求，支持地址跨 PSH 以及地址与首包同帧；剩余数据转交统一首包或 UoT reader，保持字节及 UDP 包边界。帧循环仅处理控制和分发，等待数据时保留子流所有权。单条请求的地址无效或不完整只结束该子流。

AnyTLS 出站处理开流写入期间提前到达的 FIN：正常关闭立即交由 Relay 排空已接收数据，并允许后续请求复用健康连接；已经发生的关闭或错误不会重新等待 SYNACK 而误报超时。开流等待的定时器随该次操作回收，错误 SYNACK 文本被截断时保留实际连接关闭原因。

AnyTLS 入站每个 Session 最多同时接纳 128 条未结束子流，包含等待地址的子流和正在转发的请求。这是 cnode 的资源预算，超额新流收到 FIN，v2 同时收到带错误信息的 SYNACK；原有流继续使用，已拒绝 ID 不能重用。子流从 SYN 起使用 `timeouts.handshake`（默认 60 秒）作为绝对握手期限，覆盖目标地址、UoT 初始请求及 SYNACK 写入，心跳或逐字节发送不会续期。正常握手完成后移除该期限，后续请求按 Dispatcher 和 relay 的超时处理。超时通常只结束该子流；若已经开始的物理帧写入被中断，则关闭整个会话以保护帧边界。静态与面板入站使用同一处理规则。

AnyTLS 入站和出站每条子流的接收队列最多保留 65,535 字节有效数据，并合并小片段，使排队数据块的容量不超过 128 KiB。两端满队列时均暂停物理读取，等待消费者释放空间；慢客户端仍可接收完整大响应，取消和超时会终止等待。两端共用私有的字节聚合逻辑，完整大块直接转移所有权，UoT 解码继续负责 UDP 包边界。远端正常 FIN 会排空此前收到的数据，本地主动关闭和错误关闭立即丢弃未读数据。该上限只描述排队数据块，物理帧读取、正在消费的数据及其他会话状态另计。

AnyTLS 入站和出站共用协议私有的 settings 解析，按完整 `v` 字段协商；未声明版本时使用 v1 能力，未来版本只启用本地已支持的功能。v1 会话不发送 SYNACK 或心跳，v2 会话启用 ServerSettings、SYNACK 和心跳；出站收到服务器声明之前保持 v1 行为。重复 settings、非法版本或方向不符的控制帧会结束会话，已建立请求不会被后来的设置改写。客户端标识为 `client=cnode`。

AnyTLS 出站会话池同时管理跨请求存活的物理读取任务。后台异常会关闭该会话并通知逻辑请求，失效会话不能再次借出；池退役会取消物理任务，在途操作继续持有自身状态直到清理完成。物理任务不借用单条请求上下文或 Handler，正常请求完成后仍可继续处理空闲会话的控制帧。

AnyTLS 编解码保留内存不足及逻辑链路错误，由拥有请求或物理会话的边界处理；只有真实系统 I/O 错误才按 socket 原因映射。已开始的物理帧写入异常会关闭会话，后续请求重新连接。子流即使已从会话索引移除，仍通过自己持有的请求上下文记录失败。

AnyTLS 填充方案按实际规则数保存，大报文索引不会创建中间空槽。索引及 `stop` 使用完整的无符号 32 位范围，`stop` 必须大于零，只有小于它的已配置索引生效。默认方案与入站配置在准备后共享只读对象，原始文本及其 MD5 保持一致；出站收到合法更新后替换方案，在途写入继续持有原方案。包序号不会回绕到认证索引 0，达到 `stop` 后停止填充，无效更新保留原方案。入站配置的方案须能装入单个更新帧：字符串或数组归一化后的 UTF-8 文本最多 65,535 字节，数组元素之间的换行也计入长度，超限在准备配置时拒绝。

每个 Worker 的 AnyTLS 出站客户端独立保存服务器下发的填充方案，物理连接断开后，新连接继续使用它。不同出站即使连接相同地址和端口，也独立维护方案。一次新会话的认证、首次 settings 摘要和首次帧写入使用同一份快照，之后的写入消费该客户端当前方案；Handler 被替换后，新客户端从默认方案开始。认证填充按方案长度临时构建，支持完整的 16 位长度，缓冲在认证结束后释放。

认证索引 `0` 独立于会话帧规则，只接受单个长度范围；缺少索引 `0` 或显式 `0=0-0` 时不发送认证填充，`stop=1` 可表示完全不填充的方案。正数范围按 `[较小值, 较大值)` 采样，两端相等时使用固定长度。所有可能的认证长度必须在 0～65,535 之间，例如 `0=65535-65536` 有效；零与非零混合范围、溢出、`c`、多个范围及格式错误会使整个方案无效。认证规则不会作为会话帧规则使用，默认的 30 字节来自显式默认方案，不作为解析失败后的回退。静态配置在准备阶段拒绝无效方案，远端无效更新保留当前方案。

会话填充分段尺寸独立于内部 Buffer 容量，支持 1～65,535 字节，包括跨帧头的小分段和大于 8,192 字节的填充。每个有效范围的全部采样结果都必须满足 16 位 Waste 长度容量；可能超限的范围会使整个方案在编译时失败，不能通过后续重复项或 `c` 标记绕过。纯数据分段直接引用本次数据，Waste 在临时写入缓冲中生成，不使用固定大小的零填充块。分段尺寸表示协议写入策略，TLS 仍可根据记录层限制继续拆分。

每个单节点面板对象在加入控制面前完整构造，直接拥有客户端、只读配置、连接状态、已提交节点快照和统计。用户数从已提交用户快照读取；配置与身份来自同一个归一化入口，不再通过客户端反查或多张关联表补齐。入站、出站和 TLS 构建都要求明确的面板配置。

面板节点的资源标签使用 `panel/{Name}/{NodeID}/{protocol}/{port}`，同一面板下不同节点的用户、handler 和清理目标相互独立。这替换了旧的 `{Name}-{protocol}-{port}` 格式，引用旧入站标签的路由匹配或日志筛选需要同步迁移；不保留旧标签别名。静态入站主 tag 和静态出站 tag 不得使用 `panel/` 前缀。

不同入站不能占用重叠的监听端点。相同端口、相同地址族下，通配地址与具体地址也视为冲突；IPv4 和 v6-only IPv6 可以分开监听，auto 模式保留两个地址族的请求范围。控制面在投递 Worker 前检查其他面板节点，包括更新中和等待清理的旧/候选端点；Worker 另外检查 TCP、UDP 各自的监听归属，防止与静态入站冲突。冲突会使本次节点更新失败，原监听继续服务。

节点变更由私有事务编排，具体 Worker 操作集中在 NodeRuntime。最后提交的快照以共享只读指针持有，运行态另行记录停止、就绪、变更中或需要恢复。候选快照和回滚凭据在变更前准备，全部运行操作成功后才发布。回滚不完整时保留旧节点及候选节点的清理目标；下一轮先完成本地清理，再拉取并重建，避免相同配置被误当作普通刷新，也避免遗留候选资源依赖面板网络恢复才能释放。

面板 HTTP 请求可在连接或 TLS 握手失败时尝试下一个 DNS 地址。开始发送请求后，写入或响应失败直接报告本次失败，不跨地址重发，避免重复提交流量增量。

面板配置的 `RequestTimeout` 以秒为单位，默认 `30`，只接受 `1` 至 `3600` 的整数。每次 HTTP 请求共用一个时限，覆盖 DNS 等待、连接、TLS 握手、发送和响应读取；超时会取消请求并等待资源释放，再报告本次失败。完整收到响应后，TLS 关闭握手最多额外占用剩余请求时间中的 1 秒，关闭失败或取消不会丢弃已经收到的响应。

运行时接管进程后，Worker 的生命周期持续至进程退出。信号立即退出并返回成功码；入站启动失败、事件循环异常或意外停止，会同步向 stderr 输出阶段和原因，以失败码立即退出。退出不等待活动连接或日志上传队列排空。配置解析和运行时接管前的构建错误仍正常返回错误。

## 代码组织

```text
include/acppnode/      公共 API 和窄接口
src/app/              Worker、dispatcher、router、proxyman、stats、bootstrap
src/proxy/            协议实现
src/transport/        传输层实现
src/service/          控制面 controller
src/api/              面板 API client
src/infra/            配置、JSON、日志、校验
src/common/           通用类型、buffer、allocator、session、mux
src/geo/              geoip / geosite 数据读取
src/sniff/            HTTP / TLS sniffing
config/               示例配置
scripts/              部署与更新脚本
```

仓库结构应表达最终职责，而不是表达迁移历史。删除或替换一个协议时，不应影响 dispatcher、router、relay、Worker 的结构；替换面板实现时，不应影响协议热路径；替换路由规则时，不应影响 inbound/outbound 协议实现。

## 开发提示

- 变更前先分析现有代码和配置，再决定修改方式。
- 新代码优先沿用现有目录、命名、RAII、协程和错误处理风格。
- 新增行为要同步考虑静态配置、面板配置、热更新、TCP、UDP、Mux/子流和源进源出语义。
- 涉及架构边界、热路径、用户存储、DNS、Worker-local 状态或配置归一化时，必须按 `AGENTS.md` 的硬约束审查。
