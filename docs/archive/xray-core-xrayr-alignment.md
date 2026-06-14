# cnode 架构重构总纲：对齐 xray-core / XrayR

> Archived migration log. References to removed e2e scripts are historical and
> do not describe the current validation gate.

本文档定义 cnode 全仓库重构的最终目标、职责边界、禁止事项、迁移阶段和验收标准。

本次重构允许破坏性改动，不考虑旧 cnode API、旧类名、旧目录、旧配置和旧内部兼容。不允许为了兼容旧结构保留 adapter、wrapper、compat、legacy 或 manager 万能层。不允许把局部机械重命名当作完成。不允许把临时中间态包装层作为最终设计保留。

最终目标不是逐字翻译 Go 代码，而是以 C++、Asio coroutine、RAII、move-only buffer 和 Worker-local allocator 的方式，对齐 xray-core 和 XrayR 的职责边界、生命周期、请求链路、配置语义、面板同步流程和运行时行为。

## 1. 最高层架构原则

1. 全仓库必须高度统一。
   每种职责只能有一个明确归属层，不允许同一行为散落在协议、Worker、router、relay、panel、proxyman、transport 多处。

2. 请求链路必须唯一。
   所有 TCP / UDP 请求最终只能经过：

   ```text
   inbound.Process
     -> dispatcher.Dispatch
     -> outbound.Process
     -> relay
   ```

   不允许 Worker、协议、router、panel、proxyman 私自绕过该链路。

3. 职责归属必须唯一。
   如果一个模块知道了不属于自己层级的东西，它就是错的。发现职责散落时，直接删除、合并或下沉为私有实现细节。

4. 冷路径可以复杂，热路径必须简单。
   配置解析、面板同步、工厂注册、对象构建、字段兼容归一化都属于冷路径。热路径只读预构建结构，不散落 XrayR 兼容分支、panel 类型判断、legacy 字段判断和协议特殊分支。

5. 允许阶段性迁移，但阶段结束不得留下兼容层。
   每个阶段必须保持可构建、可测试、可验证。不允许把某个协议局部改动当作整体目标完成。

## 2. 统一请求链路

最终请求链路必须收敛为：

```text
Inbound Handler::Process
  -> Dispatcher::Dispatch
  -> Outbound Handler::Process
  -> Relay
```

### 2.1 inbound

inbound 是监听连接后的协议入站处理入口。

inbound 负责：

- 认证。
- 入站协议解析。
- 用户识别。
- 目标地址解析。
- 初始 payload 处理。
- 生成统一 session / context 元信息。
- 调用 dispatcher.Dispatch。

inbound 不负责：

- 路由选择。
- 出站连接。
- relay 细节。
- 直接访问 outbound manager 内部结构。
- 持有协议私有长期大 buffer。

### 2.2 dispatcher

dispatcher 是请求链路的路由分发入口。

dispatcher 负责：

- 接收 inbound 交给它的 session / context / link。
- 调用 router 做路由决策。
- 根据路由结果选择 outbound handler。
- 调用 outbound.Process。

dispatcher 不负责：

- 解析协议。
- 创建协议专属对象。
- 包含 VMess / Trojan / Shadowsocks / AnyTLS 特判。
- 直接执行 relay。
- 读取或理解 panel 配置字段。

### 2.3 router

router 只做路由决策。

router 负责：

- 接收归一化后的 session metadata。
- 输出 outbound tag / route decision。

router 不负责：

- 创建连接。
- 访问 relay。
- 访问协议实现。
- 依赖 proxyman 具体类型。
- 理解 Worker 资源细节。

### 2.4 outbound

outbound 是出站协议处理入口。

outbound 负责：

- 根据 dispatcher 选择执行出站处理。
- 建立目标连接或下一跳连接。
- 执行出站协议握手。
- 执行出站编码。
- 完成出站链路准备后交给 relay。

outbound 不负责：

- 路由决策。
- 读取 panel 原始配置。
- 绕过 dispatcher。
- 保留旧 stream process 入口或协议 wrapper。

### 2.5 relay

relay 只搬运数据。

relay 负责：

- TCP 双向转发。
- UDP 转发。
- Mux 数据搬运。
- 流量统计打点。

relay 不负责：

- 解析 VMess / Trojan / Shadowsocks 协议。
- 选择 outbound。
- 访问 panel。
- 持有连接生命周期级别的大 scratch。
- 暴露 wrapper API。

### 2.6 Worker

Worker 只负责运行时边界。

Worker 负责：

- 事件循环。
- accept 生命周期。
- 运行态组件持有。
- thread-local allocator / buffer provider。

Worker 不负责：

- 理解具体协议 validator。
- 理解具体 outbound 类型。
- 路由。
- 协议解析。
- panel 同步。

## 3. 协议核心重构要求

1. 协议核心必须统一为 Handler::Process 模型。
   VMess、Trojan、Shadowsocks、AnyTLS、Freedom、Blackhole 都必须遵守同一职责边界。

2. 入站协议最终结构：

   ```text
   proxy/<protocol>/inbound/handler
   ```

   入站 handler 负责：

   - Process(connection / link / context)。
   - decode inbound request。
   - authenticate user。
   - produce session metadata。
   - call dispatcher。

3. 出站协议最终结构：

   ```text
   proxy/<protocol>/outbound/handler
   ```

   出站 handler 负责：

   - Process(context / link / dialer)。
   - dial target or next proxy。
   - encode outbound request。
   - hand over to relay。

4. 协议内部允许存在 reader、writer、codec、crypto helper。
   这些只能是私有实现细节，不能成为公开请求链路对象。

5. 以下对象不能作为最终设计保留：

   - SsServerAsyncStream。
   - SsClientAsyncStream。
   - VMess stream wrapper。
   - Trojan stream wrapper。
   - Shadowsocks stream wrapper。
   - protocol-specific public stream object。
   - inbound / outbound wrapper。
   - request carrier。
   - parsed action handoff。
   - session disconnect hook。
   - context accessor shell。
   - transport link helper。
   - relay wrapper API。
   - compat / adapter / legacy 层。

6. 协议不能拥有独立请求链路。
   所有协议必须通过统一的 inbound.Process -> dispatcher.Dispatch -> outbound.Process -> relay。

## 4. 传输层重构要求

1. transport 只负责连接和字节流能力。
   TCP、TLS、WebSocket、Proxy Protocol、transport stack 只能提供 stream、dial、accept、wrap 能力。

2. transport 不知道协议。
   不允许 transport include VMess、Trojan、Shadowsocks、panel、router。

3. transport 不知道 relay 策略。
   transport 只交付可读写 endpoint。

4. transport 内部细节不能泄露到 app 层。
   Worker、dispatcher、router、protocol 不允许直接访问 tcp socket、tls inner stream、ws internal frame state。

5. 传输配置必须在冷路径归一化。
   热路径只消费预构建 transport settings。

## 5. 配置系统重构要求

1. 配置格式、字段语义、默认值和目录行为向 xray-core / XrayR 对齐。
   cnode 的部署配置文件统一使用 JSON，默认主配置文件为 `config.json`。
   代理配置仍按目录侧车加载，文件名固定为 `inbounds.json` / `outbounds.json`
   / `routing.json`；这些侧车文件的内容格式必须尽量对齐 xray-core 的
   inbound / outbound / routing 对象，不支持的选项可以忽略。这是与 XrayR
   YAML 配置布局有意不同的兼容边界，文档、CLI 默认值和主配置解析入口
   不得再回退到 `config.yml` / `config.yaml`。
   例外：`ProxyProtocol` 是 cnode 自有三态语义，不能为了对齐 XrayR
   退回 bool。其合法值为 `"off"` / `"auto"` / `"on"`，默认 `"auto"`；
   旧布尔值仅作为输入兼容解析，`true` 映射为 `"auto"`，`false` 映射为
   `"off"`。`"auto"` 表示连接开始时自动探测 PROXY protocol v1/v2，未检测
   到 header 时继续按普通协议处理。
   例外：`SendIP` 的默认值是 cnode 自有 `"auto"` 语义，不能为了对齐外部
   项目改回空字符串或只支持具体 IP。`SendIP: "auto"` 表示 direct outbound
   出站时优先绑定入站连接命中的本地 IP，实现多 IP 服务器的源进源出；旧配置
   中的空字符串仍作为输入兼容，按自动模式处理。
   例外：面板 `DNSType` 映射到 freedom outbound `settings.domainStrategy`，
   其合法值必须对齐 xray-core freedom outbound，而不是 XrayR 或 xray-core
   routing 的较小值集。当前支持 `"AsIs"`、`"UseIP"`、`"UseIPv6v4"`、
   `"UseIPv6"`、`"UseIPv4v6"`、`"UseIPv4"`、`"ForceIP"`、
   `"ForceIPv6v4"`、`"ForceIPv6"`、`"ForceIPv4v6"`、`"ForceIPv4"`。
   cnode direct outbound 当前不会把域名继续传给后续 sockopt，因此 `Force*`
   与对应 `Use*` 的拨号行为保持一致，但值集和 IPv4/IPv6 优先级必须保留。
   实现方式使用 cnode 的 C++ 类型系统和运行时结构。

2. 配置冷路径必须完成全部归一化：

   - 文件配置。
   - 面板配置。
   - 默认值。
   - XrayR 字段语义。
   - inbound / outbound / routing / dns / policy / panel settings。

   进入 Worker 热路径前，配置必须变成稳定、只读、预构建 runtime config。

3. 热路径禁止出现：

   - legacy key alias 判断。
   - panel 类型判断。
   - V2Board / NewV2board 字段分支。
   - JSON 字段临时读取。
   - stringly-typed protocol dispatch。
   - optional shell 默认行为。

4. 配置热更新必须原子替换运行态对象。
   旧运行态由仍在执行的连接自然释放。不允许 panel sync 直接修改 live handler 内部状态。

## 6. XrayR 面板同步重构要求

1. 面板目录、类名、函数名、对象职责、字段语义和同步流程向 XrayR 对齐。
   不保留 cnode 旧 panel model / old V2Board / newV2board 私有命名。

2. 最终职责边界：

   - Controller：管理节点生命周期和同步流程。
   - Node：节点信息、节点状态、节点级配置。
   - User：用户信息、认证信息、速率和限额相关字段。
   - Traffic：用户和节点流量统计、上报、清零语义。
   - API Client：只负责 HTTP 请求和面板 API 数据转换。
   - Builder：只在冷路径构建 inbound / outbound / rule / runtime config。

3. 面板同步流程统一为：

   - 拉取节点信息。
   - 拉取用户列表。
   - 拉取规则和面板策略。
   - 归一化为 XrayR 语义配置。
   - 构建 inbound / outbound / routing / policy runtime。
   - 原子替换运行态。
   - 按 XrayR 语义上报节点状态和用户流量。

4. Controller 不得直接持有协议实现细节。
   Panel 不得参与热路径。Panel 不得直接访问 Worker buffer provider。Panel 不得直接修改 validator 内部表。

## 7. 统计系统重构要求

1. 统计职责必须集中。
   relay 可以打点流量，但统计聚合、用户维度、节点维度、上报语义必须归属 stats / traffic 层。

2. relay 不知道面板。
   relay 只产生 traffic delta。

3. stats 不知道协议私有细节。
   stats 以统一 user / inbound tag / outbound tag / node id / direction 维度统计。

4. 面板上报只读取统计快照。
   不允许面板扫描连接对象或协议对象。

## 8. Worker-local Buffer / Allocator 模型

1. Worker 是热路径唯一资源边界。
   每个 Worker 拥有自己的 thread-local allocator / buffer provider。

2. Buffer、MultiBuffer、协议 scratch、relay 临时对象、短生命周期容器都必须归属当前 Worker。

3. 所有热路径对象必须按需借、用完即还。
   不允许协议对象、连接对象、relay 对象长期持有 8KB / 16KB / 32KB scratch。

4. 禁止以下设计：

   - 协议私有长期 pool。
   - transport 私有长期 pool。
   - outbound 私有长期 pool。
   - inbound 私有长期 pool。
   - relay 私有长期 pool。
   - panel 私有长期 pool。
   - 跨 Worker 共享 pool。
   - 全局共享 buffer pool。
   - 每连接常驻大 buffer。
   - 长期缓存未使用 capacity。

5. 允许 mimalloc 或项目自有 allocator 在 Worker 内部做多尺寸分档。
   分档属于 Worker-local provider 内部实现，不允许按协议或模块拆多个长期私有池。

6. MultiBuffer / Buffer 所有权必须清晰：

   - MultiBuffer move 即转移所有权。
   - 消费结束必须归还。
   - 禁止无意义拼接大字符串。
   - 禁止整包重复复制。
   - 禁止长期持有未使用 capacity。

7. Worker 退出或配置热更新时，必须保证该 Worker 拥有的 buffer / object 生命周期完整结束后，再回收 allocator 资源。

## 9. 热路径性能要求

1. 热路径优先低成本。
   不新增无必要虚调用、shared_ptr、type-erasure、锁、跨线程同步、重复分配、重复拷贝。

2. 允许冷路径使用：

   - OOP。
   - factory。
   - registry。
   - config normalization。
   - builder。
   - immutable runtime snapshot。

3. 热路径只读预构建结构。
   不允许在热路径解析 JSON、读取 panel 字段、动态构建协议对象图。

4. 协议认证、路由匹配、出站选择、relay 搬运必须保持明确数据流。
   不允许隐式全局查找。不允许全局 user table。不允许 dispatcher 内协议特判。

## 10. 目录与命名要求

1. 文件名、类名、函数名必须表达最终职责，不表达历史来源。
   不允许为了保留旧结构进行机械重命名。

2. 禁止最终结构出现以下公开命名：

   - legacy。
   - compat。
   - adapter。
   - wrapper。
   - old。
   - newV2board。
   - stream helper。
   - request carrier。
   - parsed action。
   - manager 万能职责层。

3. manager 只允许在确实对应 xray-core / XrayR 职责时存在。
   如果 manager 同时负责注册、生命周期、dispatch、构建、状态修改，则必须拆分或删除。

4. 目录组织必须反映职责边界：

   ```text
   app/dispatcher
   app/proxyman/inbound
   app/proxyman/outbound
   app/router
   app/stats
   app/worker
   common/buf
   transport/internet
   proxy/<protocol>/inbound
   proxy/<protocol>/outbound
   proxy/<protocol>/encoding 或 codec
   service/controller
   service/panel 或 api/<panel>
   ```

## 11. 迁移阶段

### 执行顺序和测试登记规则

- 必须按阶段 1 -> 阶段 6 顺序推进。
- 只有当前阶段和已完成阶段可以进入常规构建测试入口。
- `CMakeLists.txt` 只能登记真实存在的 `tests/*.cmake` 脚本。
- 后续阶段的结构测试必须在进入该阶段、实现对应规则时新增；不得提前登记缺失脚本占位。
- 每完成一个阶段性切片，必须把新增约束、删除项和剩余缺口更新回本文档。

### 阶段 1：请求链路收口

- 建立 inbound.Process -> dispatcher.Dispatch -> outbound.Process -> relay 唯一路径。
- 删除 DispatchRequest / request carrier / parsed action handoff。
- Dispatcher 不再 include 具体协议。
- Worker 不再直接访问协议 validator。
- Router 不再耦合 relay / proxyman 具体实现。
- 当前已登记结构门：
  - `no_worker_direct_validator_access`
  - `no_dispatch_request_carrier`
  - `no_parsed_action_handoff`
  - `no_dispatcher_protocol_includes`
  - `no_routing_dispatcher_relay_coupling`
  - `no_relay_wrapper_api`
  - `no_worker_direct_udp_outbound_dispatch`
  - `no_worker_shadowsocks_udp_codec`
  - `no_worker_relay_api`
  - `no_dispatcher_direct_relay_api`
- 本阶段当前进展：
  - TCP 请求链路通过 `dispatcher.Dispatch` 进入 outbound / relay。
  - Dispatcher 不再直接 include 或调用 relay / mux relay API；MUX 分支改由 outbound handler 承接后进入 mux relay。
  - Worker 不再直接持有或访问 VMess / Trojan / Shadowsocks validator。
  - Worker 原生 UDP 首包不再自行 `Route` 后直接调用 outbound UDP；改由 dispatcher 承接 UDP 分发入口。
  - Worker 不再直接 include Shadowsocks UDP codec 或调用协议 UDP 编码函数；UDP 回包编码下沉到 Shadowsocks inbound handler。
  - Worker / proxyman UDP 生命周期入口使用 `proxyman::inbound::UdpHandler` 抽象，不再在 Worker 公共接口暴露具体 Shadowsocks inbound handler 类型。
  - Worker 不再 include relay API；relay 入口只保留在 dispatcher / outbound 链路中。
- 阶段 1 当前门禁已通过；后续请求链路改动必须继续满足上述结构门。

### 阶段 2：协议 Handler 迁移

- VMess 入站/出站改为 Handler::Process。
- Trojan 入站/出站改为 Handler::Process。
- Shadowsocks 入站/出站改为 Handler::Process。
- 删除协议 stream wrapper。
- reader / writer / codec 下沉为协议私有 helper。
- 当前已登记结构门：
  - `no_protocol_stream_wrapper_api`
  - `no_protocol_named_handler_classes`
  - `no_proxyman_inbound_protocol_udp_types`
  - `no_public_shadowsocks_udp_codec_header`
  - `no_public_trojan_codec_header`
  - `no_public_vmess_cipher_header`
  - `no_public_vmess_crypto_header`
  - `no_public_vmess_request_header`
  - `no_public_shadowsocks_aead_cipher_api`
- 本阶段当前进展：
  - VMess / Trojan / Shadowsocks 入站和出站均已暴露 `Handler::Process`。
  - 文档点名的 `SsServerAsyncStream`、`SsClientAsyncStream`、VMess/Trojan/Shadowsocks stream wrapper 公开对象当前不存在，并由结构门防回归。
  - AnyTLS inbound/outbound、Freedom outbound、Blackhole outbound 公开处理器已收敛到协议命名空间下的 `Handler` 类，工厂继续只返回统一 `Inbound` / `Outbound` 接口。
  - Proxyman UDP handler 公共接口不再暴露 Shadowsocks UDP codec 类型；Worker 只持有协议不透明 `UdpResponseContext` 并回传给 handler 编码回包。
  - Shadowsocks UDP codec 头文件已从公共 include 树下沉到 `src/proxy/shadowsocks`，只作为 Shadowsocks 协议私有 helper 使用。
  - Trojan codec 头文件已从公共 include 树下沉到 `src/proxy/trojan`；冷路径用户构建只依赖 `trojan::HashPassword` 的 validator 公共声明，不再 include Trojan 编解码器。
  - VMess cipher 和 crypto helper 头文件已从公共 include 树下沉到 `src/proxy/vmess`；`MemoryAccount` 只公开必要的 `CachedAESKey` 预计算字段声明，KDF/AES/hash 实现保持协议私有。
  - VMess request carrier 已从公共 include 树下沉到 `src/proxy/vmess`；公共 outbound 配置只保留 `proxy/vmess/types.hpp` 中的 `Security` 类型。
  - Shadowsocks 公共 protocol 头不再暴露 `SsAeadCipher`、`DeriveSubkey` 或 OpenSSL EVP 细节；AEAD cipher helper 已下沉到 `src/proxy/shadowsocks/shadowsocks_crypto.hpp`。
- 阶段 2 当前门禁已通过；后续协议改动必须继续保持 Handler::Process 和私有 helper 边界。

### 阶段 3：relay 和 Buffer 统一

- relay 只搬运数据。
- Buffer / MultiBuffer 全部从 Worker-local provider 借还。
- 删除 UDP / Mux / Trojan UDP / protocol scratch 中的常驻大 buffer。
- 明确 MultiBuffer move-only 所有权。
- 当前已登记结构门：
  - `no_relay_protocol_specific_names`
  - `no_trojan_udp_persistent_bytevector`
  - `no_udp_reply_queue_bytevector`
  - `no_mux_reply_queue_bytevector`
  - `no_mux_frame_buffer_bytevector`
  - `no_vmess_request_pending_bytevector`
  - `no_udp_relay_reply_queue_packet`
  - `no_trojan_udp_queue_packet`
  - `no_public_owned_udp_packet_bytevector`
  - `no_public_udp_decode_result_bytevector`
  - `no_tcp_stream_pending_bytevector`
  - `no_trojan_udp_codec_packet_bytevector`
  - `no_initial_payload_bytevector_overflow`
  - `no_mux_codec_return_bytevector`
  - `no_shadowsocks_udp_decode_result_bytevector`
  - `no_protocol_udp_return_bytevector_builders`
  - `no_trojan_request_payload_bytevector`
  - `no_dns_query_return_bytevector`
  - `no_worker_udp_response_bytevector`
  - `no_ws_stream_circular_pending_buffer`
  - `no_common_circular_buffer_header`
- 本阶段当前进展：
  - TCP relay、UDP relay、Mux relay 源码不再出现 VMess / Trojan / Shadowsocks 等协议名或协议 codec 名；relay 层保持协议无关的数据搬运表达。
  - Trojan UDP framed reader 不再持有可增长的 `memory::ByteVector` 作为常驻 scratch；半包缓存改为借用 `buf::Buffer`，消费完或丢弃时归还。
  - UDP inbound 回包队列不再持有 `memory::ByteVector` payload；队列统一转移 `buf::MultiBuffer` 所有权，发送时以 const-buffer sequence 保持单个 UDP datagram 的生命周期。
  - Mux reply queue 不再持有 `memory::ByteVector` payload；TCP/UDP 子会话回包以 `buf::MultiBuffer` 形式排队，只有写回客户端编码帧时才使用短生命周期连续 scratch。
  - Mux read-side frame parser 不再持有连接级 `memory::ByteVector frame_buf`；粘包数据由 `buf::MultiBuffer` 持有，解析前局部 flatten，解析后按字节消费并归还 Buffer。
  - VMess request 不再用 `memory::ByteVector` 保存握手后的 pending first-packet data；剩余首包数据直接从握手 `buf::Buffer` 转移所有权，并由 server body decoder 按 span 消费。
  - UDP relay 回包队列不再排队 `UDPPacket` / `ByteVector` payload；回包以 `buf::MultiBuffer` 持有并在写回 client writer 前标注来源地址。
  - Trojan UDP framed reader 队列不再排队 `UDPPacket` / `ByteVector` payload；解帧成功后立即借用 `buf::Buffer` 持有 payload，并在输出 `MultiBuffer` 时转移所有权。
  - app UDP 公共类型不再暴露 owned `UDPPacket` / `ByteVector` payload；公共回调只暴露同步有效的 `UDPPacketView`，跨协程保存由调用点局部 Buffer/MultiBuffer 类型完成。
  - Proxyman UDP decode 公共结果不再暴露 `memory::ByteVector` payload 或 offset/size 片段；协议私有解码 scratch 在跨 Worker 边界前装箱为 `buf::MultiBuffer` 并通过 UDPSession scatter/gather 发送。
  - TcpStream proxy-protocol 后续 pending data 不再挂接连接级 `memory::ByteVector`；剩余字节改由 `buf::MultiBuffer` 持有，AsyncRead 推进 Buffer 游标后归还，ReadMultiBuffer 直接 move 剩余所有权。
  - Trojan UDP codec 解帧结果不再拥有 `memory::ByteVector` payload；payload 只作为当前 Worker Buffer 中的短生命周期 span，随后立即复制进借来的 `buf::Buffer` 并转移到 framed queue。
  - InitialPayload 大首包溢出不再使用 `memory::ByteVector* overflow_`；小首包保留 inline 快路径，大首包由 `buf::MultiBuffer` 持有，dispatcher sniff 仅在需要连续视图时临时 flatten，outbound 首包交付优先 move Buffer 所有权。
  - Mux codec 公开接口不再提供返回 owned `memory::ByteVector` frame 的便捷 builder；Mux relay 只使用调用方提供的短生命周期 `Encode*To` scratch，避免热路径重新引入整帧 owned vector API。
  - Shadowsocks UDP decode 结果不再返回 `memory::ByteVector` payload 加 offset/size 切片；协议私有解密明文只作局部 scratch，返回边界直接转移 `buf::MultiBuffer` payload 所有权。
  - Trojan / Shadowsocks 协议热路径编码器不再保留返回 owned `memory::ByteVector` 的未使用 builder；请求和 UDP 包编码统一使用调用方提供缓冲区的 `Encode*To` 路径。
  - Trojan 请求解析结果不再保留未使用的 `memory::ByteVector payload` 首包字段；TCP 首包剩余数据由 inbound 侧 `InitialPayload` / Buffer 所有权链路承接。
  - DNS 查询报文 builder 不再返回 owned `memory::ByteVector`；查询协程在调用点持有短生命周期 scratch，并由 `BuildQueryTo` 填充后立即发送。
  - Worker UDP 回包编码不再分配整包 `memory::ByteVector`；回包编码职责下沉到 UDP handler，Worker 只接收并排队 `buf::MultiBuffer` 所有权。
  - WebSocket stream 握手后 pending data 不再由连接级 `CircularBuffer` / `ByteVector` 持有；剩余字节改由 `buf::MultiBuffer` 持有，`ReadFull` 消费 Buffer 游标并及时归还。
  - 未使用的 `common/circular_buffer.hpp` 已删除，避免基于可增长 `memory::ByteVector` 的连接级 pending buffer 旧抽象继续作为可复用入口残留。
- 阶段 3 当前门禁已通过；后续 relay / buffer 改动必须继续保持协议无关搬运、Buffer/MultiBuffer 所有权清晰和无连接级可增长大 scratch。

### 阶段 4：配置和运行态快照

- 配置冷路径统一归一化。
- 构建 immutable runtime snapshot。
- Worker 只持有当前 runtime snapshot。
- 热更新原子替换 snapshot。
- 删除 legacy key aliases 和旧配置布局。
- 当前已登记结构门：
  - `no_runtime_config_xrayr_path_fields`
  - `no_worker_direct_config_runtime`
  - `no_runtime_config_raw_panel_json`
  - `no_static_inbound_setup_raw_json`
  - `no_worker_runtime_outbound_config_json`
  - `no_controller_outbound_builder_raw_json`
  - `no_bootstrap_inbounds_raw_settings`
  - `no_worker_header_infra_config_dependency`
  - `no_worker_runtime_full_config_dependency`
  - `no_hot_path_public_config_header_dependency`
  - `no_hot_path_public_common_umbrella_dependency`
  - `no_config_types_common_umbrella_dependency`
  - `no_stream_settings_tls_stream_dependency`
  - `no_hot_path_cpp_config_class_dependency`
  - `no_inbound_factory_raw_settings_api`
  - `no_static_inbound_runtime_raw_settings`
  - `no_static_inbound_runtime_inbound_config_api`
  - `no_static_inbound_runtime_public_config_types_dependency`
  - `no_static_inbound_prepared_config_full_config_dependency`
  - `no_config_loader_builtin_outbound_raw_settings`
  - `no_config_public_raw_inbounds_api`
  - `no_config_runtime_raw_inbounds_storage`
  - `no_public_raw_inbound_config_type`
  - `no_config_public_raw_outbounds_api`
  - `no_config_runtime_raw_outbounds_storage`
  - `no_public_raw_outbound_config_type`
  - `no_worker_split_timeout_runtime_state`
  - `no_worker_split_pressure_runtime_state`
  - `no_worker_non_atomic_runtime_snapshot`
  - `no_dynamic_outbound_without_snapshot_replace`
  - `no_static_inbounds_outside_runtime_snapshot`
  - `no_public_outbound_source_config_raw_json`
  - `no_public_outbound_factory_source_prepare_api`
  - `no_public_outbound_headers_raw_source_names`
  - `no_rule_manager_in_place_rule_update`
  - `no_config_loader_public_outbound_factory_dependency`
  - `no_controller_outbound_builder_runtime_factory_dependency`
  - `no_dynamic_inbound_users_outside_runtime_snapshot`
  - `no_runtime_inbound_prepared_config_factory_dependency`
  - `no_worker_runtime_static_inbound_builder_dependency`
  - `no_worker_runtime_dns_service_dependency`
  - `no_outbound_prepared_config_dns_service_dependency`
  - `no_inbound_prepared_config_validator_dependency`
  - `no_rule_worker_public_api_dependency`
  - `no_worker_public_dns_service_dependency`
  - `no_bootstrap_setup_public_dns_service_dependency`
  - `no_protocol_outbound_public_dns_service_dependency`
  - `no_inbound_manager_public_validator_storage`
  - `no_inbound_manager_public_factory_dependency`
  - `no_outbound_manager_public_handler_storage`
  - `no_router_public_runtime_storage`
  - `no_worker_router_matcher_construction`
  - `no_worker_router_init_prepared_outbound_dependency`
  - `no_worker_public_udp_worker_dependency`
  - `no_worker_public_geodata_dependency`
  - `no_worker_direct_sniff_config_dependency`
  - `no_worker_public_session_context_dependency`
  - `no_worker_public_buffer_util_dependency`
  - `no_worker_public_udp_reply_buffer_dependency`
  - `no_worker_public_proxy_inbound_dependency`
  - `no_worker_public_stats_storage_dependency`
  - `no_worker_public_listener_config_dependency`
  - `no_worker_public_runtime_config_header_dependency`
  - `no_unregister_listener_without_snapshot_cleanup`
  - `no_public_remove_listener_async_bypass`
  - `no_session_tracking_full_session_dependency`
  - `no_dispatcher_public_rule_manager_dependency`
  - `no_outbound_manager_public_handler_dependency`
  - `no_inbound_manager_public_handler_dependency`
  - `no_public_online_device_tracker_type_dependency`
  - `no_public_inbound_rate_limiter_dependency`
  - `no_worker_public_unused_deque_include`
  - `no_worker_public_rule_manager_dependency`
  - `no_worker_public_router_dependency`
  - `no_worker_public_proxyman_manager_dependency`
  - `no_worker_public_udp_session_manager_dependency`
  - `no_worker_public_dispatcher_dependency`
  - `no_public_session_tracking_storage_dependency`
  - `no_worker_public_listener_storage_dependency`
  - `no_worker_public_common_umbrella_dependency`
  - `no_worker_public_private_transport_coroutines`
  - `no_worker_public_listener_lifecycle_methods`
  - `no_worker_public_runtime_state_storage`
  - `no_worker_public_io_context_escape`
  - `no_bootstrap_public_common_umbrella_dependency`
- 本阶段当前进展：
  - `dnsConfigPath` / `inboundConfigPath` / `outboundConfigPath` / `routeConfigPath` 旧 sidecar 配置路径兼容读取已从 `config_loader` 删除；最终布局只从主配置和标准同目录 `inbounds.json` / `outbounds.json` / `routing.json` 进入冷路径归一化，Worker / runtime 只携带已归一化后的 DNS、inbound、outbound 和 routing 结果。
  - Worker 构造和初始化入口不再接收完整 `Config`；Bootstrap 冷路径先构建 `WorkerRuntimeConfig` 快照，Worker 只读取 DNS、timeouts、limits、routing、outbounds 和 worker 数量这些运行态字段。
  - 面板配置不再以 `json::object` 原样保存在 `Config`；`Config::LoadFromJson` 冷路径直接归一化为 `PanelConfig`，Bootstrap panel setup 只消费归一化后的控制面配置。
  - 静态 inbound 注册流程不再在 Worker 注册循环中直接读取 `inbound.settings` 原始 JSON；Bootstrap 冷路径先构建 `StaticInboundRuntimeEntry`，把 tag、监听参数、receiver settings、cipher method 和静态用户集合归一化后再应用到各 Worker。
  - WorkerRuntimeConfig 不再携带 `std::vector<OutboundConfig>`；Bootstrap 和面板动态 outbound 更新会先调用 proxyman outbound prepare 冷路径，把协议 settings 解析进 `PreparedOutboundConfig`，Worker 只用 prepared entry 构建 per-Worker outbound handler。
  - 面板动态 outbound builder 不再先拼装 `OutboundConfig` / `json::object settings`；Controller 冷路径直接构建 freedom `PreparedOutboundConfig`，再投递给各 Worker 原子替换 outbound handler。
  - 静态 inbound 原始 settings 解析已从 `bootstrap_inbounds.cpp` 移入独立 `static_inbound_runtime` 冷路径 builder；bootstrap 注册流程只消费 prepared static inbound runtime entry。
  - `WorkerRuntimeConfig` 已从 `worker.hpp` 抽出到独立 runtime snapshot 头；Worker 公共头不再直接 include 完整 `infra/config.hpp`，运行态入口继续只暴露预构建 snapshot。
  - Worker 公共头不再 include `app/worker_runtime_config.hpp` 或 prepared/static inbound/runtime config 头；`WorkerRuntimeConfig`、`RoutingConfig`、`BuildRequest`、`UserSet` 和 `PreparedOutboundConfig` 只以前置声明出现在 Worker 边界，完整 snapshot/prepared 定义由 `worker.cpp` 和 bootstrap 冷路径实现文件显式 include。
  - 纯配置数据类型已拆入 `infra/config_types.hpp`，`Config` 类保留在 `infra/config.hpp`；`WorkerRuntimeConfig` 只依赖 config types 边界，不再依赖完整 Config 类头。
  - dispatcher / proxyman / proxy outbound 等热路径公共头已切到 `infra/config_types.hpp`，不再为了 `TimeoutsConfig`、`RelayConfig`、`OutboundConfig` 等纯类型拖入完整 `Config` 类头。
  - dispatcher / proxyman inbound / proxyman outbound 的热路径实现文件已切到 `infra/config_types.hpp`，不再通过 `.cpp` include 完整 `Config` 类头获得运行态纯配置类型。
  - proxyman inbound factory 公共接口不再暴露 `json::object settings` 或 raw settings 参数；静态 inbound 冷路径先把 method / clients 归一化为 `StaticUserConfig`，协议注册项只消费预提取的静态用户输入并构建 Worker 本地用户表。
  - 静态 inbound 用户配置的 method / clients 提取已前移到 `InboundConfig::FromJson`，`static_inbound_runtime` 只读取 typed `StaticUserConfig`，不再直接访问 `InboundConfig::settings` 或 raw JSON 字段。
  - 静态 inbound runtime builder 的输入已从 raw `InboundConfig` 切到 typed `StaticInboundConfig`；`Config` 在加载 inbound 时同步维护 `GetStaticInbounds()`，Bootstrap 注册静态入站只消费不含 raw settings 的运行态来源列表。
  - `config_loader` 不再为内置 direct / blackhole outbound fallback 合成 raw JSON settings；内置 direct 的 sendThrough/domainStrategy 默认值由 freedom outbound prepare 冷路径默认值承接。
  - `Config` 公共 API 不再暴露 raw `GetInbounds()`；静态 inbound 运行态入口统一通过 `GetStaticInbounds()` 读取 typed source，raw `InboundConfig` 仅保留为配置内部解析/验证数据。
  - `Config` runtime 对象不再保留 `std::vector<InboundConfig>` raw inbound 存储；文件加载时只用局部 `InboundConfig` 解析并立即转成 `StaticInboundConfig` 保存到运行态来源列表。
  - 公开配置类型中不再保留 raw `InboundConfig` 临时壳；静态 inbound 配置文件由 `StaticInboundConfig::FromJson` 直接解析为 typed runtime source。
  - `Config` 公共 API 不再暴露 raw `GetOutbounds()`；Bootstrap worker runtime 构建直接读取 `GetPreparedOutbounds()`，不再通过 friend 函数从 `Config` 内部取 raw outbounds。
  - `Config` runtime 对象不再保留 `std::vector<OutboundConfig>` raw outbound 存储；配置加载冷路径把文件 outbounds 和内置 fallback 出站局部解析后立即 prepare 为 `PreparedOutboundConfig`，Worker runtime snapshot 直接拷贝 prepared outbounds。
  - 公开 infra 配置类型中不再保留 raw `OutboundConfig`；outbound 文件源解析移动到 proxyman outbound 冷路径 `OutboundSourceConfig`，协议注册 API 只在 prepare 阶段消费该 source config 并输出 prepared runtime entry。
  - Worker 不再把 `TimeoutsConfig` 从 runtime snapshot 中拆成独立成员；Worker 持有当前 `std::atomic<std::shared_ptr<const WorkerRuntimeConfig>>`，DNS、UDP session、outbound 构建、连接握手和 relay/UDP idle timeout 均通过加载当前 snapshot 读取，为后续整包 snapshot 原子替换收束状态入口。
  - Worker 不再把 pressure threshold / pressure idle timeout 作为独立成员保存；Bootstrap 冷路径基于 limits/timeouts/workers 计算 prepared pressure runtime settings，Worker 热路径只从当前 `WorkerRuntimeConfig` snapshot 读取。
  - Worker runtime snapshot 持有方式已从普通 `shared_ptr` 升级为 atomic shared_ptr；热路径读取通过 `RuntimeSnapshot()` acquire-load 获取稳定局部快照，后续热更新可以用单一 snapshot 指针替换承接。
  - 动态 outbound add/remove 不再只修改 per-Worker outbound manager；Worker 在 handler 安装或移除后会复制当前 `WorkerRuntimeConfig`，更新 prepared outbounds 列表，并通过 `StoreRuntimeSnapshot()` release-store 原子替换当前 runtime snapshot。
  - 静态 inbound prepared runtime entries 已纳入 `WorkerRuntimeConfig`；Bootstrap 冷路径在构建 runtime snapshot 时完成 `StaticInboundRuntimeEntry` 归一化，静态 inbound 注册流程只消费 snapshot 中的 prepared entries，不再绕过 runtime snapshot 从 `Config` 重新构建或 include 完整 `Config` 头。
  - `OutboundSourceConfig` 已从公共 include 树下沉到 proxyman outbound 私有冷路径实现头；公共 outbound factory 头不再直接暴露 raw `json::object settings` source config 细节，协议 prepare 迁移期间的原始 outbound settings 解析只保留在 `src` 冷路径边界内。
  - outbound raw source 注册和 prepare API 已从公共 `factory.hpp` 移入 proxyman outbound 私有冷路径头；公共 outbound factory 边界只暴露 prepared runtime handler 构建和注册协议查询，不再公开 `OutboundSourceConfig` / `RegisterProxy` / `PrepareOutboundConfig` 这类 raw source API。
  - proxyman outbound 公共头不再提及 raw source config 名称；public header 只描述 prepared runtime entry 和 handler 边界，原始 outbound JSON source 语义留在私有冷路径实现中。
  - XrayR detect rule 更新不再原地修改 live `rule::Manager` 规则表；规则表在 `rule::Manager` 私有实现中使用 `shared_ptr<const InboundRule>` immutable snapshot，`UpdateRule` 复制当前规则表、应用 tag 更新后整体替换，热路径 `HasRule` / `Detect` 读取稳定局部快照，检测结果统计继续作为 Worker-local mutable runtime state 独立保存。
  - `config_loader` 不再 include public outbound runtime factory；outbound 文件解析只依赖 proxyman outbound 私有 source prepare 边界，避免配置冷路径反向依赖 runtime handler factory 头。
  - Controller outbound builder 公共头不再 include proxyman outbound runtime factory；面板 outbound 冷路径 builder 只暴露 `PreparedOutboundConfig` 返回边界，避免把 runtime handler factory 依赖传播到 controller builder API。
  - 动态 inbound 用户 Apply/Add/Remove/Clear 不再只修改 Worker-local validator；WorkerRuntimeConfig 已保存 prepared inbound user entries，静态 inbound 初始化和面板用户热更新都会复制当前 runtime snapshot、更新 prepared 用户集合并原子替换，热路径继续只读 Worker-local validator。
  - inbound prepared runtime 数据类型已从 proxyman inbound factory 公共头拆入 `prepared_config.hpp`；`WorkerRuntimeConfig`、静态 inbound runtime source 和 controller inbound builder 只依赖 `BuildRequest` / `UserSet` 数据边界，不再为了 prepared 数据拖入协议 factory 注册 API。
  - 静态 inbound prepared entry 已从 `static_inbound_runtime.hpp` 冷路径 builder 头拆入 `static_inbound_prepared_config.hpp`；`WorkerRuntimeConfig` 只依赖静态 inbound prepared 数据边界，不再 include 构建函数和 `StaticInboundConfig` 输入边界。
  - DNS runtime config 已从 DNS 服务实现头拆入 `app/dns/config.hpp`；`WorkerRuntimeConfig` 只持有 DNS 配置数据，不再 include 完整 DNS 服务、缓存和解析实现头。
  - DNS 服务公共头不再暴露 `DnsCache`、cache shard/LRU、inflight resolve map、wire parser 或 Worker-local allocator 容器；`DNS` 改为不透明 `Impl` 持有，cache 结构拆到 `src/app/dns/cache_internal.hpp` 私有实现边界，公共头只保留 `DnsResult`、DNS config/stats 和服务 API。
  - outbound prepared config 不再 include 完整 DNS 服务头或 Outbound 接口头；prepared creator 只通过公共前置声明边界表达 `DNS&` 和 `unique_ptr<Outbound>`，避免 prepared 数据头拖入协议/服务实现。
  - inbound prepared config 不再 include Trojan / Shadowsocks validator 头；协议 prepared user 数据已拆入 `proxy/trojan/user_info.hpp` 和 `proxy/shadowsocks/user_info.hpp`，`UserSet` 只依赖用户数据结构，不再拖入 validator 存储、在线统计和查找实现。
  - detect rule/result 运行态数据已从 panel API 头拆入 `common/rule_types.hpp`；`rule::Manager` 继续拥有 narrow DTO 边界，`Worker` 公共头只前置声明 detect DTO，不再为了 XrayR detect 规则 include 完整 `api/api.hpp` 或 `common/rule_types.hpp`，API 层继续通过别名保留 `api::DetectRule` / `api::DetectResult` 对外语义。
  - `rule::Manager` 公共头不再 include Worker-local allocator / string hash，也不再暴露 `ThreadLocalVector` / rule map 等运行态存储；规则表 snapshot 和检测结果表已移入 `rule.cpp` 私有实现，`GetDetectResult` 公共返回边界收敛为普通 `std::vector<DetectResult>`。
  - DNS cache stats 已从 DNS 服务实现头拆入 `app/dns/stats.hpp`；`worker_stats.hpp` 作为 Worker runtime stats DTO 边界集中承载 DNS cache stats 和 `StatsSnapshot`，`worker.hpp` / `udp_session.hpp` 不再 include 完整 DNS 服务实现头，也不再直接 include stats 存储定义。
  - Bootstrap 公共环境头不再 include 完整 DNS 服务实现；`BootstrapEnvironment` 通过前置声明持有 panel DNS 服务，并把构造/析构放到 `bootstrap_setup.cpp` 冷路径实现中，避免启动公共边界继续传播 DNS 服务实现依赖。
  - Freedom / VMess outbound 公共头不再 include 完整 DNS 服务实现；协议 outbound handler 只在公共边界表达 `DNS&` 依赖，具体解析调用所需的 DNS 实现头留在各自 `.cpp` 中。
  - Proxyman inbound manager 公共头不再 include 或按值暴露 VMess / Trojan / Shadowsocks validator；协议用户表实现被压入 `manager.cpp` 的私有实现结构，Worker 按值持有 inbound manager 时不再间接传播协议 validator 存储细节。
  - Trojan validator 公共头不再 include Worker-local allocator、string hash 或在线追踪实现头，也不再暴露 `users_by_tag_` / `UserMap` / `UserOnlineTracker` 存储；用户表和在线追踪状态已移入 `validator.cpp` 私有 `Validator::Impl`，公共边界只保留用户更新、认证查找和在线设备查询 API。
  - Shadowsocks validator 公共头不再 include Worker-local allocator、string hash 或在线追踪实现头，也不再暴露 `UserList` / `users_by_tag_` / `UserOnlineTracker` 存储；按 tag 用户查询公共边界从内部 `ThreadLocalVector` 指针改为 `std::span<const SsUserInfo>`，用户列表和在线追踪状态已移入 `validator.cpp` 私有 `Validator::Impl`。
  - VMess validator 公共头不再 include Worker-local allocator、string hash、log 或在线追踪实现头，也不再暴露 `UserMap` / `users_by_tag_` / 热点认证缓存 / `UserOnlineTracker` 存储；用户表、热点 auth cache 和在线追踪状态已移入 `validator.cpp` 私有 `TimedUserValidator::Impl`，公共边界继续只保留用户更新、按 tag AuthID 查找、计数和在线设备查询 API。
  - Proxyman inbound manager 公共头不再 include inbound factory 注册边界；`ProtocolDeps` / `ProxyRegistration` / 注册 API 只在 `manager.cpp` 和协议注册实现中可见，Worker 侧只看到 prepared inbound runtime 数据和 handler 管理 API。
  - Proxyman outbound manager 公共头不再暴露 Worker-local handler map、retired handler list 或默认 handler 指针等存储细节；这些运行态容器已移入 `manager.cpp` 私有实现结构。
  - Router 公共头不再暴露运行态规则列表、默认出站 tag 或 GeoManager 指针存储；这些 runtime 状态已移入 `router.cpp` 私有实现结构，公共边界只保留路由规则构建和查询 API。
  - Router 公共头不再暴露 `DomainTrie`、`DomainMatcher`、`IPMatcher`、`Condition` 或 `CompoundRoutingRule` 等 matcher/runtime 实现类型，也不再 include `common.hpp`、`common/session.hpp`、allocator、regex、variant、vector 或完整 config types；这些路由匹配器、CIDR 解析和规则组合实现均已下沉到 `router.cpp` 私有边界，结构门已扩展防止 Router 头重新泄露 matcher 存储。
  - Worker 不再直接组装 `CompoundRoutingRule`、`DomainMatcher`、`IPMatcher` 等 Router 匹配器内部对象；路由 runtime 构建集中到 `Router::Configure` 冷路径边界，Worker 只交付归一化后的 routing runtime config、默认出站 tag 和 GeoManager，Router 公共头不依赖 proxyman prepared outbound 类型。
  - Worker 的 `InitRouter` 私有入口不再接收 prepared outbound 列表；Worker 在初始化时先从 runtime snapshot 提取默认出站 tag，再把 routing config、默认 tag 和 GeoManager 交给 Router 冷路径构建。
  - Worker 公共头不再 include 完整 `proxyman/inbound/udp_worker.hpp`；UDP worker 的回包队列、socket map 和客户端会话存储细节只在 `worker.cpp` 可见，公共头仅保留前置声明和不透明持有边界。
  - Proxyman inbound `udp_worker.hpp` 不再暴露 Worker-local socket map、retired socket list、reply queue map 或 client session map，也不再在公共头使用 `memory::ThreadLocal*` 容器；这些 UDP 监听运行态容器已移入 `udp_worker.cpp` 私有 `UdpWorker::Impl`，公共边界只保留 opaque UDP reply 发送句柄、send-result DTO、socket 操作和普通 `std::vector<std::string>` socket-key 列表。
  - Proxyman inbound `udp_worker.hpp` 不再暴露 `UdpReplyQueueState`、reply deque、queued bytes、write-in-progress 或 drain shrink 标志；UDP 回包队列状态已收进 `udp_worker.cpp` 私有结构，Worker 侧只通过 `EnqueueReply` / `BeginReplySend` / `CompleteReplySend` 操作边界驱动异步发送。
  - Proxyman inbound `udp_worker.hpp` 不再暴露 `PendingUdpReply` 的 endpoint、payload、send buffer 或 payload size/prepare 方法；reply payload 和 scatter/gather 发送缓冲保留在 `udp_worker.cpp` 私有 `UdpWorker::PendingUdpReply` 定义中，Worker 侧只持有 opaque `PendingUdpReplyPtr` 并通过只读 `ReplySendBuffers` / `ReplyEndpoint` 视图投递 `async_send_to`。
  - Proxyman inbound `udp_worker.hpp` 不再暴露 `UdpClientSessionMap`、`UdpClientSession`、`udp_dial`、`callback_id` 或 `last_active` 等 client session 存储字段；客户端 UDP session 查找、upsert、发送和 idle cleanup 已收进 `udp_worker.cpp`，Worker 侧只通过 `HasClientSession` / `UpsertClientSession` / `SendToClientSession` / `CleanupIdleClientSessions` 操作边界访问 per-socket 会话状态。
  - Proxyman inbound `udp_worker.hpp` 不再暴露 `UdpSocketPtr` 或自定义 socket deleter；UDP socket 的 thread-local 分配、归还和 retired socket ownership 已收进 `udp_worker.cpp`，Worker 侧只通过 `MakeSocket` / `AttachSocket` / `FindSocket` 操作边界完成绑定和收包。
  - Worker 公共头不再 include 完整 GeoData 实现头；Worker 只通过 `geo::GeoManager*` 接收冷路径预加载好的 Geo 管理器，公共边界使用前置声明避免传播 GeoData 存储和加载细节。
  - GeoData 公共头不再 include `common.hpp` umbrella、`common/string_hash.hpp`、unordered map/set 或 shared mutex，也不再暴露 `GeoIPLoader` / `GeoSiteLoader`、CIDR 数据表、radix trie、suffix trie、tag index、loaded data map 等索引和懒加载存储；`GeoManager` 改为 `geodata.cpp` 私有 `GeoManager::Impl` 持有 loader，公共边界只保留初始化、预加载、匹配和统计 API。
  - Worker 公共头不再直接 include `proxy/sniff_config.hpp`；sniffing 配置仍由 inbound receiver / prepared config 边界承载，Worker 不再为未使用的 sniff 细节建立直接公共依赖。
  - Worker 公共头不再 include `common/session.hpp`；连接级 `session::Context` 和 session id 创建只保留在 `worker.cpp` 的连接处理实现中，公共 Worker 边界不传播 per-connection runtime 细节。
  - `common/session.hpp` 不再 include `common.hpp` umbrella、Worker-local allocator 或 sniff 实现头；`session::Inbound` / `Content` / `Context` 的 `source_ip`、`user_email`、`protocol`、`sniff_domain` 和 outbound stack 存储已从 `memory::ThreadLocalString` / `ThreadLocalVector` 收敛为普通 `std::string` / `std::vector` DTO，避免 session 公共元数据边界传播 Worker-local allocator 策略。
  - Worker 公共头不再 include `common/buffer_util.hpp` scratch helper；buffer 释放/回收工具留在实现文件边界内。
  - Worker 公共头不再 include `common/buf/multi_buffer.hpp`，也不再暴露 `buf::MultiBuffer` / `buf::BufferGuard` / `std::span` / UDP reply queue helper 私有签名；UDP 回包缓冲和发送队列操作已收进 `Worker::ListenerState` 的 `.cpp` 私有实现边界。
  - Worker 公共头不再 include 完整 `proxy/inbound.hpp`；`Inbound` 只作为 `unique_ptr` API 边界前置声明，真正构造协议 handler 或调用 `Inbound` 方法的 `worker.cpp`、bootstrap/controller 冷路径实现文件自行 include 完整协议接口。
  - Worker 公共头不再 include `app/stats.hpp` 或 `app/dns/stats.hpp`，也不再内联定义 `MemoryStats` / `RuntimeStatsSnapshot` 存储；统计 DTO 已拆入 `app/worker_stats.hpp`，Worker 侧只保留兼容别名和 `StatsShard` 前置声明。
  - Worker 公共头不再 include `app/port_binding.hpp` 或 `app/proxyman/inbound/receiver_settings.hpp`；listener bind 参数和 receiver settings 只通过前置声明的引用边界进入 Worker，异步注册所需的复制/移动逻辑留在 `worker.cpp`，调用方冷路径继续显式构建完整 listener config。
  - `UnregisterListenerAsync` 注销 inbound 时不再只停监听和移除 handler；Worker 会复制当前 `WorkerRuntimeConfig`，从 `static_inbounds` 和 `inbound_users` 中删除对应 tag 的运行态条目，并通过 `StoreRuntimeSnapshot()` 发布清理后的 snapshot，避免已卸载 inbound 的 prepared runtime 数据残留。
  - Worker 不再暴露只停 socket 的 `RemoveListenerAsync` 公共绕路入口；会改变 inbound 生命周期的移除操作必须走 `UnregisterListenerAsync`，进程关闭时只停 listener 的路径保留为 `ShutdownListenersAsync`。
  - `app/session_tracking.hpp` 不再 include 完整 `common/session.hpp`，也不再 include allocator/string hash 或暴露 `LocalTrafficStore` / `ActiveSessionMap` / `ActiveSession` 存储类型；会话流量表和活跃会话表已移入 `session_tracking.cpp` 私有 `SessionTrackingState::Impl`，公共边界只保留 add/register/unregister/collect 方法和 `session::Traffic` 前置声明，完整 `session::Context` 处理留在 dispatcher / worker 实现文件中。
  - `default_dispatcher.hpp` 不再 include 完整 `common/rule.hpp`；dispatcher 公共边界只前置声明 `rule::Manager`，具体规则表、detect snapshot 和调用细节留在 `default_dispatcher.cpp`。
  - Proxyman outbound manager 公共头不再 include 具体 outbound handler 头；公共边界只继承 outbound feature manager 接口并前置声明 `proxyman::outbound::Handler`，handler map、retired handler 和具体 proxy 绑定细节留在 `manager.cpp`。
  - Proxyman inbound manager 公共头不再 include 具体 inbound `Handler` / `UdpHandler` 头；公共边界只暴露指针和 `unique_ptr` 管理 API，handler 方法调用与具体 UDP decode/encode 接口依赖留在 `manager.cpp` / `worker.cpp` 实现文件中。
  - 在线设备采集结果已从 `UserOnlineTracker::OnlineDevice` 嵌套类型拆成独立 `OnlineDevice` DTO；Worker / proxyman inbound manager / controller 公共边界不再为了在线查询结果依赖完整 sharded user tracker 实现头。
  - `OnlineDevice` 已从 `std::pair<int64_t, std::string>` alias 收敛为带 `user_id` / `ip` 命名字段的独立 DTO；Worker 和 proxyman inbound manager 公共头只前置声明该 DTO，完整定义只由在线追踪构造方、Worker 实现和 controller 上报消费方显式 include。
  - VMess / Trojan / Shadowsocks validator 公共在线设备查询签名也已改为独立 `OnlineDevice` DTO，不再把 `UserOnlineTracker::OnlineDevice` 嵌套实现名作为协议公共 API；对应结构门已覆盖协议 validator 头。
  - `UserOnlineTracker` 公共头不再 include Worker-local allocator / string hash，也不再暴露 `ThreadLocalUnorderedMap`、tag connection map 或 user device map 存储；在线计数和设备 IP 追踪状态已移入 `sharded_user_stats.cpp` 私有 `UserOnlineTracker::Impl`，公共边界只保留在线状态更新、设备限制查询和独立 `OnlineDevice` DTO 返回 API。
  - `ConnectionLimiterPtr` 已从完整 `rate_limiter.hpp` 拆入轻量 `rate_limiter_fwd.hpp`；proxy inbound、proxyman inbound manager/factory 和协议 inbound 公共头只暴露连接限制器指针边界，具体 rate limiter 实现与方法调用保留在 `.cpp` 运行态实现中。
  - `app/relay.hpp` 不再 include `common.hpp` umbrella、Worker-local allocator 或 buffer scratch helper；模板 relay 头显式依赖 relay/session/multibuffer/stats/log 等窄边界，rate-limit timer guard 从手工 `ThreadLocalAllocator` 指针改为局部 `std::optional<net::steady_timer>`，避免 relay 公共热路径暴露 allocator 策略。
  - Worker 公共头不再直接 include 未使用的 `<deque>`；Worker 边界不暴露 deque-based 存储，队列和容器实现细节继续留在具体实现头或 `.cpp` 内。
  - Worker 公共头不再 include 完整 `common/rule.hpp`、`common/rule_types.hpp` 或按值持有 `rule::Manager`；detect rule manager 运行态存储改为 Worker 实现文件私有构造的不透明指针，公共 Worker 边界只保留 detect rule/result 前置声明。
  - Worker 公共头不再 include 完整 `app/router/router.hpp` 或按值持有 `app::router::Router`；路由 matcher、regex、Geo 规则和默认出站等 runtime 结构继续由 Router 私有实现管理，Worker 公共边界只保留不透明 Router 持有和 `InitRouter` 冷路径入口。
  - Worker 公共头不再 include 或按值持有 proxyman inbound/outbound manager；handler map、retired handler、协议 validator 和 outbound handler 生命周期管理继续留在 proxyman manager 实现边界，Worker 公共边界只通过 prepared config / user set 数据和不透明 manager 指针衔接。
  - Worker 公共头不再 include 完整 `app/udp_session.hpp` 或按值持有 `UDPSessionManager`；UDP full-cone 会话表、callback 路由和清理 timer 等运行态实现留在 `worker.cpp` / UDP session 实现边界，Worker 公共头只保留 UDP socket 参数所需的通用网络类型。
  - `UDPSessionManager` 公共头不再暴露 session map、retired session list、cleanup timer、deleter 或 Worker-local session 容器；manager 运行态存储已移入 `udp_session.cpp` 私有 `UDPSessionManager::Impl`，公共边界只保留获取/移除/统计/清理 API。
  - `UDPSession` 公共头不再 include `common.hpp` umbrella、Worker-local allocator/session/stats 或 `UdpEndpointKey` 存储头，也不再暴露 Full Cone callback map、target 反向索引、socket、sender endpoint、活跃时间、剪枝 timer 或统计计数；单个 UDP session 的运行态状态已移入 `udp_session.cpp` 私有 `UDPSession::Impl`，公共边界只保留发送、接收启动、callback 注册、过期判断和统计读取 API。
  - `UdpEndpointKey` / `UdpEndpointKeyHash` 已从完整 `app/udp_session.hpp` 拆入轻量 `app/udp_endpoint_key.hpp`；proxyman inbound `udp_worker.hpp` 只依赖 endpoint key DTO 和前置声明的 `UDPSession*`，完整 UDP session manager / callback / socket 实现只在 `udp_worker.cpp`、`worker.cpp` 和 UDP session 实现文件私有 include。
  - Proxyman inbound `tcp_worker.hpp` 不再 include `common.hpp` umbrella，也不再 include allocator 或暴露 `ThreadLocalUnorderedMap` / acceptor map 存储；TCP listener worker 公共边界只显式依赖 `common/asio_types.hpp` 和普通 listener-key DTO，listener acceptor 容器已移入 `tcp_worker.cpp` 私有 `TcpWorker::Impl`，结构门已覆盖防止该公共头重新拖入全局 common 入口或 Worker-local 容器。
  - Proxyman inbound `tcp_worker.hpp` 不再通过 `AddAcceptor(tcp::acceptor)` 暴露 acceptor ownership 转移；TCP acceptor 构造和 replacement 由 `TcpWorker::CreateAcceptor` 在私有 acceptor map 内完成，Worker 侧只拿原始指针做 bind/listen/accept loop 调度和关闭操作。
  - Worker 公共头不再 include 完整 `app/dispatcher/default_dispatcher.hpp` 或按值持有 `DefaultDispatcher`；dispatcher 的 routing/outbound/rule/session 绑定和热路径 dispatch 细节留在实现边界，Worker 公共头只保留不透明 dispatcher 持有。
  - Worker / DefaultDispatcher 公共头不再 include 完整 `app/session_tracking.hpp` 或暴露 `ActiveSessionMap` / `LocalTrafficStore` 存储类型；公开边界只保留轻量 `UserTraffic` / `UserTrafficSnapshot` DTO 和不透明 `SessionTrackingState` 绑定，活跃会话 map、thread-local 流量表和回收逻辑留在实现文件中。
  - Worker 公共头不再 include `app/traffic_types.hpp`，也不再把流量收集 API 写成裸 `std::unordered_map<int64_t, UserTraffic>`；`GetTrafficTask` / `CollectAndResetTraffic` 通过前置声明的 `UserTrafficSnapshot` 命名快照表达收集边界，真实 map 容器只保留在 `traffic_types.hpp` DTO 定义和 `session_tracking.cpp` 私有运行态实现中。
  - Worker 公共头不再 include `common/allocator.hpp` / `common/string_hash.hpp`，也不再暴露 TCP listener tag map、listener slot map、UDP socket tag map 或 UDP worker map；这些 Worker-local 监听和回包运行态容器已合入 `ListenerState` 并定义在 `worker.cpp` 私有实现边界。
  - Worker 公共头不再 include `common.hpp` umbrella；`net` / `tcp` / `udp` Asio 类型别名拆入窄边界 `common/asio_types.hpp`，`common.hpp` 继续复用该窄边界以保持旧 umbrella 入口，同时 Worker 只依赖自身签名实际需要的 Asio 类型和前置声明。
  - Worker 公共头不再暴露 accept / per-connection / UDP receive private coroutine 名称或 `tcp::socket` / `tcp::acceptor` / `udp::socket` 等 transport socket 签名；这些监听循环实现已下沉为 `worker.cpp` 私有 `Worker::ListenerState` 方法，Worker 头只保留生命周期入口和不透明 listener state 持有。
  - Worker 公共头不再暴露 `StartListening` / `StopListening` / `StartUdpListening` / `StopUdpListening` / `RetireInboundHandler` / retired handler drain 等 listener lifecycle 私有方法；监听启动停止、handler retire 和延迟释放都收进 `worker.cpp` 私有 `Worker::ListenerState` 实现，public async 入口只投递到 Worker io_context。
  - Worker 公共头不再逐项暴露 runtime snapshot、StatsShard、listener state、proxyman manager、session tracking、DNS service、UDP session manager、router、rule manager、dispatcher 或 `io_context` 等运行态成员；这些存储已收进 `worker.cpp` 私有 `Worker::RuntimeState`，Worker 头只保留 `std::unique_ptr<RuntimeState>` 不透明边界和必要 public API，`GetExecutor()` 也改为 `.cpp` 中通过 runtime state 返回 executor 边界。
  - Worker 公共头不再暴露 mutable `GetIoContext()` 或 `net::io_context&` 访问器；跨线程控制和采集入口只通过 `GetExecutor()` 的 executor 边界投递，`io_context` 保持为 Worker runtime 内部资源。
  - Bootstrap 启动公共头不再 include `common.hpp` umbrella、完整 `infra/config.hpp` 或完整 DNS 服务实现头；全部 `bootstrap*.hpp` 只依赖窄 Asio、常量或标准库边界和显式前置声明，`bootstrap_shutdown.hpp` 显式 include signal_set 窄边界，完整 `Config` / DNS 服务使用保留在冷路径 `.cpp` 实现文件中。
  - `infra/config_types.hpp` 不再 include `common.hpp` umbrella；公共配置数据边界只显式依赖 constants、defaults、JSON、sniff/stream settings 和标准库类型，避免热路径公共头通过 config types 间接拖入全局 common 入口。
  - `StreamSettings` 不再 include 完整 TLS stream 实现头；纯 TLS 配置数据已拆入 `transport/internet/tls_config.hpp`，`tls_stream.hpp` 只在 TLS stream / SSL context 实现边界消费该配置数据，避免 runtime config 传输配置间接暴露 OpenSSL stream 实现。
  - WebSocket HTTP headers 容器已拆入 `transport/internet/http_headers.hpp` 的 `HttpHeaders` 命名 DTO 边界；`StreamSettings::ws.headers` 和 `WsClientStream::Handshake` 不再在公共签名里直接拼 `std::unordered_map<std::string, std::string>`，结构门已覆盖防止 stream/ws 公共头重新暴露裸 headers map。
  - `AsyncStream` 公共抽象不再 include `common.hpp` umbrella 或 `common/allocator.hpp`；公共头只显式依赖窄 Asio/error/link 边界和标准库类型，自定义分配策略所需的 allocator include 留在 `async_stream.cpp` 实现文件中。
  - `TimeoutScheduler` 公共头不再 include `common.hpp` umbrella；共享超时调度器 API 只依赖 `common/asio_types.hpp` 和标准库时间/回调边界，timer、Worker-local heap/event map 和分片表实现依赖保留在 `timeout_scheduler.cpp`。
  - `TcpStream` 不再通过 `TimeoutScheduler` 间接获得全局 common/chrono 别名；TCP stream 公共头显式声明自己的 chrono 依赖，避免传输流头依赖 umbrella 副作用。
  - `TcpStream` 公共头不再 include Worker-local allocator 或 timeout scheduler 实现头，也不再暴露 `tcp::socket` 成员、timeout scheduler 指针、pending `MultiBuffer`、deadline token、last I/O 时间、readv 自适应策略、stream label enum 或 flags；这些每连接运行态状态已移入 `tcp_stream.cpp` 私有 `TcpStream::Impl`，公共边界只保留流 API、端点查询、timeout/deadline 控制和静态拨号入口。
  - PROXY protocol 解析公共结果 DTO 不再使用 `memory::ThreadLocalString` 保存来源 IP，也不再 include `common.hpp` 或 allocator；`proxy_protocol.hpp` 只依赖 `common/asio_types.hpp` 和标准库字符串/可选值，避免传输解析 DTO 暴露 Worker-local string 存储策略。
  - Transport dial target 公共 DTO 不再 include `common.hpp` / allocator，也不再暴露 `memory::ThreadLocalVector<OutboundDialCandidate>`；`OutboundTransportTarget` 的候选列表改为普通 `std::vector<OutboundDialCandidate>`，公共头只依赖窄 Asio/defaults 边界和 stream settings。
  - Transport dialer 公共入口不再 include `common.hpp` 或 `transport_stack.hpp`；拨号 API 只暴露 `DialResult`、`OutboundTransportTarget` 和前置声明的 `session::Context`，具体 `BuildOutboundTransport` stack 构建依赖留在 `transport_dialer.cpp` 实现边界。
  - `proxy/inbound.hpp` 公共协议基类不再 include `common.hpp`、完整 `common/session.hpp` 或 `transport/async_stream.hpp`；接口只保留窄 Asio/error/relay/rate-limiter 边界，`AsyncStream` 和 `session::Context` 通过前置声明表达，具体入站实现文件自行 include 完整 stream 类型。
  - `proxy/outbound.hpp` 公共协议基类不再 include `common.hpp`、`app/stats.hpp`、`app/udp_types.hpp`、完整 session 或 full config types；接口只保留 relay/link/error 和 Asio 边界，`StatsShard`、`UDPSession`、`TimeoutsConfig`、`session::Context` 和 `buf::MultiBuffer` 均以前置声明表达，具体协议配置头显式 include 自己需要的 stream settings、constants、target address 等数据头。
  - `sniff/sniffer.hpp` 公共嗅探结果不再 include `common.hpp`、`common/allocator.hpp` 或完整 `TargetAddress`；`SniffResult::domain` 改为普通 `std::string` DTO，`ToTarget()` / `ToString()` 的 target-address/constants 依赖留在 `sniffer.cpp` 实现边界。
  - Proxyman inbound UDP decode 公共结果不再用 `memory::ThreadLocalString` 暴露 `user_email`，也不再直接 include `common/allocator.hpp`；`UdpDecodeResult::user_email` 改为普通 `std::string` DTO，Worker 收到结果后再写入自己的 session storage。
  - DNS 公共解析结果不再暴露 `memory::ThreadLocalVector<net::ip::address>`；`DnsResult::addresses` 和 DNS wire parse 返回边界改为普通 `std::vector<net::ip::address>`，cache / inflight 内部 Worker-local 容器已收进 DNS 私有实现细节。
  - `app/stats.hpp`、`app/udp_types.hpp`、Proxyman inbound `factory.hpp` 和 Shadowsocks `shadowsocks_protocol.hpp` 不再 include `common.hpp` umbrella；UDP 公共回调/relay DTO 只依赖 error/span/标准库和 `TargetAddress` 前置声明，inbound factory 公共注册边界只保留 prepared user/build DTO、rate limiter 指针和协议 validator 前置声明，完整 `UdpHandler`、`Inbound`、`StaticUserConfig`、`session::Context` 等依赖改由实际使用字段或方法的 `.cpp` 显式 include。
  - Mux codec 公共头不再 include `common.hpp` umbrella 或 Worker-local allocator，也不再通过 `memory::ByteVector&` 暴露编码 scratch 策略；`EncodeKeepAliveTo` / `EncodeEndTo` / `EncodeKeepDataTo` / `EncodeKeepUDPTo` 改为调用方提供普通 `std::vector<uint8_t>&` scratch，Mux relay 内部继续按需使用 Worker-local 容器管理子会话表。
  - Mux relay 公共头不再 include `common.hpp` umbrella、完整 `common/session.hpp` 或完整 `transport/async_stream.hpp`；`DoMuxRelay` 声明只依赖窄 Asio、relay/UDP 配置 DTO 和前置声明的 `AsyncStream` / `session::Context` / outbound handler，具体 session 字段访问和 stream 操作留在 `mux_relay.cpp` 实现边界。
  - `MultiBuffer` 公共类型不再用 `memory::ThreadLocalVector<Buffer*>` 暴露 spill 元数据容器；超过 inline buffer 后的指针表改为普通 `std::vector<Buffer*>`，保留 `Buffer::New/Free` 的 Worker-local 数据块分配策略，避免 public buffer 容器元数据继续传播 thread-local allocator 类型。
  - `TargetAddress` 公共目标地址 DTO 不再 include `common.hpp` 或 `common/allocator.hpp`，`host` 字段从 `memory::ThreadLocalString` 收敛为普通 `std::string`；`ip_utils.hpp` 也改为依赖窄 Asio/constants 边界，避免目标地址 DTO 传播全局 common umbrella。
  - `static_inbound_runtime.hpp` 不再 include 完整 `infra/config_types.hpp`；静态 inbound runtime builder 公共声明只前置声明 `StaticInboundConfig` 并返回 prepared runtime entry，完整静态 inbound source 字段消费留在 `static_inbound_runtime.cpp` 冷路径实现中。
  - `static_inbound_prepared_config.hpp` 不再 include 完整 `infra/config_types.hpp`；prepared static inbound runtime entry 只显式依赖 `StreamSettings` 和 `SniffConfig` 的窄数据边界，避免 Worker runtime snapshot 通过 static inbound prepared 数据间接拖入完整配置类型集合。
  - outbound prepared config 公共头不再 include `common.hpp` umbrella；`PreparedOutboundCreator` 只通过 `common/asio_types.hpp` 获取 executor 类型边界，并显式前置声明 `Outbound`、`UDPSessionManager` 和 `app::dns::DNS`，避免 Worker runtime snapshot 的 prepared outbound 数据间接传播全局 common 入口。
  - Freedom outbound 公共头不再通过私有 `ResolveTargets` helper 签名暴露 `memory::ThreadLocalVector<net::ip::address>`；目标地址解析结果使用普通 `std::vector<net::ip::address>` 作为协议私有 helper 边界，避免 Worker-local 容器策略出现在协议公共 API 中。
  - Worker runtime snapshot 所需的 `LimitsConfig` / `TimeoutsConfig` / `RoutingConfig` 已从完整 `infra/config_types.hpp` 拆入 `infra/runtime_config_types.hpp` 窄边界；`WorkerRuntimeConfig` 不再依赖 log/DNS/static inbound 等冷路径配置集合，只持有进入 Worker runtime 的 limits、timeouts、routing 和 prepared runtime entries。
  - `common/error.hpp`、`TargetAddress`、session context DTO、rule manager、Mux codec、Mux relay、`app/relay.hpp`、`app/relay_types.hpp`、DNS service、GeoData、`app/udp_session.hpp`、`transport/link.hpp`、`transport/async_stream.hpp`、TcpStream、timeout scheduler、transport dialer、PROXY protocol、transport dial target、proxy inbound/outbound base、sniffer DTO、DNS result DTO、proxyman inbound UDP handler / UDP worker reply queue、routing dispatcher feature、outbound feature、VMess / Trojan / Shadowsocks validator、UserOnlineTracker 和 proxyman inbound TCP worker 公共头不再 include `common.hpp` umbrella；Asio aliases 和 `IoErrorCode` / `IoSystemError` 已集中到 `common/asio_types.hpp`，outbound feature 只依赖 `runtime_config_types.hpp` 获取 `TimeoutsConfig`，mux codec / mux relay / relay / session / MultiBuffer spill 元数据 / TCP worker / TCP stream / UDP session / GeoData / sharded user stats 公共头也不再传播 Worker-local allocator、timeout scheduler、transparent hash 或懒加载索引容器，避免热路径接口传播完整 common/config/allocator 集合。
- 阶段 4 当前门禁已通过；收尾审计结论：
  - Worker / runtime 公共头中的主要运行态存储泄漏、Worker-local allocator 泄漏和完整 config/common umbrella 依赖已收口；当前结构门覆盖 Worker runtime snapshot、DNS / router / proxyman manager / dispatcher / UDP worker / UDP session / session tracking / GeoData / transport stream / mux / relay / validator 等公共边界，防止重新暴露热路径实现存储。
  - `HttpHeaders` 和 `UserTrafficSnapshot` 作为命名 DTO 边界仍在公共头内拥有标准库 map；这是配置/采集结果数据边界，不属于 Worker-local 运行态存储泄漏。
  - `udp_session.hpp` 中的 callback id API 属于 UDP session callback 注册、发送和注销职责；callback map、target reverse index、last_active、socket 和统计计数等运行态存储仍在 `udp_session.cpp` 私有 `UDPSession::Impl` 中。
  - 阶段 4 不再保留已知可操作缺口；下一阶段进入阶段 5 XrayR 面板同步，重点处理 Controller / API client / Node / User / Traffic / Builder 与旧 V2Board / newV2board 面板模型边界。

### 阶段 5：XrayR 面板同步

- 重构 Controller / Node / User / Traffic / API Client / Builder。
- 面板同步流程对齐 XrayR。
- 删除旧 V2Board / newV2board 公开模型和私有配置。
- 面板只参与冷路径，不进入热路径。
- 当前已登记结构门：
  - `no_controller_public_sync_state_dependency`
  - `no_panel_api_public_common_umbrella_dependency`
  - `no_legacy_panel_layout`
  - `no_legacy_panel_models`
  - `no_legacy_v2board_client_names`
  - `no_legacy_v2board_private_config`
  - `no_v2board_public_http_helpers`
  - `no_public_v2board_client_boundary`
  - `no_panel_client_hot_path_dependency`
- 本阶段当前进展：
  - `Controller` 公共头已收窄为 PImpl API，只暴露面板注册、启动/停止、统计读取和关闭所需 tag 列表；面板 API 全量头、`PanelConfig` 定义、同步协程、Node/User/Traffic 缓存、用户 diff、inbound/outbound builder 私有方法、Worker/limiter 引用和 ban tracking set 已下沉到 `src/service/controller/controller_impl.hpp` 及实现文件。
  - `bootstrap_monitor.cpp` 不再通过 Controller 公共头间接获得 defaults，监控冷路径显式 include `common/defaults.hpp`，避免 Controller 公共边界继续传播 common umbrella 依赖。
  - `api/api.hpp` 不再 include `common.hpp` umbrella，也不再暴露 `json::value Header`；面板 API 公共模型显式依赖 `common/asio_types.hpp`、`common/defaults.hpp`、`common/error.hpp`、`common/rule_types.hpp` 和 `core/constants.hpp`，并通过结构门防止重新依赖 raw JSON、Controller 或 Worker 热路径头。
  - 旧 `newV2board` 路径/命名、legacy panel model、V2Board 私有配置命名和 V2Board HTTP helper 公共暴露检查已登记进 CMake，确保已有 legacy panel 结构门参与 `ctest`。
  - `api/v2board/v2board.hpp` 公共具体面板头已删除；Bootstrap 面板冷路径改为 include `api/panel_factory.hpp` 并通过 `api::CreatePanelClient` 创建通用 `api::API`，V2Board `APIClient` 类声明和 JSON/HTTP 细节留在 `src/api/v2board/v2board.cpp` 私有实现中。
  - 面板 API/client 代码不再依赖 Worker、proxyman 或 live handler API；Controller 面板同步先通过 inbound/outbound/user builder 生成 prepared inbound / outbound / users，再由控制面投递 Worker async 更新，结构门已覆盖防止 panel client 直接进入热路径。
- 阶段 5 当前门禁已通过；不再保留已知可操作缺口。下一阶段进入阶段 6 统计、部署和最终清理。

### 阶段 6：统计、部署和最终清理

- stats / traffic 统一。
- deployment config layout 对齐新配置。
- README、示例配置、脚本和 Docker 行为同步。
- 添加 no_legacy / no_wrapper / no_cross_layer 结构测试。
- 当前已登记结构门：
  - `no_deployment_legacy_config_layout`
  - `no_stats_traffic_cross_layer_dependency`
  - `no_final_legacy_public_artifacts`
  - `no_final_wrapper_cross_layer_regression`
- 本阶段当前进展：
  - 部署脚本 JSON 分支按最终 panel schema 字段 `Name` 去重并覆盖同名 panel，不再使用旧/小写 `.name` 字段判断。
  - `docs/configuration.md` 只描述最终 `ProxyProtocol` 字符串三态 schema，不再宣传旧 boolean 兼容写法；部署文档、示例配置、脚本和 Docker 由结构门防止重新出现旧 XrayR sidecar path 字段或 `newV2board` 命名。
  - `config_loader` 已删除 `dnsConfigPath` / `inboundConfigPath` / `outboundConfigPath` / `routeConfigPath` 旧 sidecar path 兼容读取，默认补充配置只按最终布局扫描 `inbounds.json`、`outbounds.json` 和 `routing.json`。
  - stats / traffic 边界已固化为 app 层 `traffic_types.hpp` DTO、`SessionTrackingState` PImpl 和 `worker_stats.hpp` 运行态 stats DTO；Panel API/client 不依赖 app stats/traffic 热路径类型，Controller control plane 负责从 Worker snapshot 汇总并转换成 `api::UserTraffic` 上报。
  - 最终 no_legacy / no_wrapper / no_cross_layer 汇总结构门已登记，覆盖旧 panel/config 公开残留、公开 V2Board concrete client、relay wrapper / 协议命名泄漏、Dispatcher/Router/Worker 跨层耦合回归。
  - 当前仓库根目录不存在 README 文件；已存在的配置文档、示例配置、部署脚本和 Dockerfile 已由阶段 6 部署结构门覆盖。
- 阶段 6 当前门禁已通过；收尾验收结论：
  - 完整 configure / build / ctest 已通过，当前 `ctest` 共 141 项全部通过。
  - `CMakeLists.txt` 当前登记 141 个真实存在的 `tests/*.cmake` 脚本，缺失测试检查为 0。
  - 阶段 6 不再保留已知可操作缺口；本重构进入最终验收标准满足状态。

### 追加切片：AnyTLS 协议对齐

- 本切片按 Xray-core AnyTLS wire format 补齐，不改变阶段 1 -> 阶段 6 的架构边界。
- mux / multi-stream 语义必须对齐 Xray-core AnyTLS PR #5907 / commit `a6e6ec0` 的设计：
  - client 侧按 `sessions map` + `idleSessions` pool 管理 TLS session，配置字段使用 `idleSessionCheckInterval`、`idleSessionTimeout`、`minIdleSession` 语义。
  - 每条 TLS session 只有一个 read loop 读取物理连接，按 sid demux 到 stream；所有 stream 写入共享 session 时必须串行化，不能多个协程同时读写同一个 TLS stream。
  - SYN / SYNACK、ServerSettings、UpdatePaddingScheme、Heart、Alert、FIN 的方向性和异常处理必须按上游 session / session_client 行为收敛，不允许只做本地“看起来并发”的替代 mux。
  - 协议完成验收必须覆盖所有协议的 inbound / outbound，并分别使用 Xray-core、mihomo 与 sing-box 做端到端连通测试；本地测试二进制分别为 `tools/xray-core/xray.exe`、`tools/mihomo/mihomo-windows-amd64.exe` 和 `tools/sing-box/sing-box.exe`。
  - 全部端到端测试后必须重新执行结构约束检查、缺失 tests 检查、配置/文档 JSON 检查和全量 `ctest`，确认没有违反阶段边界。
- 当前已登记结构门：
  - `anytls_outbound_wire_format`
- 当前进展：
  - AnyTLS inbound/outbound 不再是拒绝占位；已补齐 sha256(password) 认证、7 字节帧头、settings/SYN/SYNACK/PSH/FIN/Alert/Heart/ServerSettings/UpdatePaddingScheme 基础帧处理。
  - Outbound 强制 TLS 承载，按 Xray 默认 padding scheme 生成认证 padding、settings、首包和后续 PSH padding，并可接收服务端 padding scheme 更新。
  - Outbound 已将 `paddingScheme`、`packetIndex`、`nextSID`、`settingsSent`、session read loop 和 sid demux 提升到 AnyTLS client session 生命周期；session pool 已按 Xray-core `sessions map` + `idleSessions` + `idleSessionCheckInterval` / `idleSessionTimeout` / `minIdleSession` 语义收敛。
  - AnyTLS 配置语义按 xray-core 收敛：inbound 静态配置使用 `settings.users` / `settings.paddingScheme`，outbound 使用顶层 `settings.address` / `settings.port` / `settings.password` / `settings.idleSessionCheckInterval` / `settings.idleSessionTimeout` / `settings.minIdleSession`；不得引入非 xray-core 的 AnyTLS `clients` 或 `servers[0]` 兼容入口。
  - Inbound 可验证静态配置和面板同步用户，读取客户端 settings/SYN/PSH 目标地址，回复 ServerSettings/SYNACK，并通过连接级 demux 按 sid 分发多 stream；每个 sid 仍通过协议私有 framed reader/writer 交给 dispatcher，静态配置支持 Xray `settings.paddingScheme`，会按客户端 `padding-md5` 差异下发 `UpdatePaddingScheme`。
  - UDP-over-TCP v2 magic 目标 `sp.v2.udp-over-tcp.arpa` 已接入：outbound 在 UDP 请求上打开 AnyTLS magic stream 并发送 UoT request，后续 PSH payload 以 datagram 边界转发；inbound 识别 magic stream 后解析 UoT request，并通过协议私有 UDP reader/writer 进入 dispatcher 的 UDP 数据面。
  - Controller user builder 已生成 AnyTLS 用户认证数据，示例配置和配置文档已补 AnyTLS panel 示例。
  - 新增 `tests/e2e/external_protocol_matrix.ps1`，可生成 xray-core / mihomo / sing-box 的 VMess、Trojan、Shadowsocks、AnyTLS inbound/outbound 配置矩阵，并保存每项校验日志到 `build/e2e-external-matrix`。
  - 新增 `tests/e2e/external_protocol_traffic.ps1`，使用本地 TCP/HTTP 目标服务模拟真实请求，分别验证 cnode inbound 和 cnode outbound 与 xray-core / mihomo / sing-box 的协议互通。
  - Xray-core release `v26.3.27` 和 `v26.6.1` 均未注册 AnyTLS（`unknown config id: anytls`）；为完成 xray-core AnyTLS 配置矩阵，已从 GitHub PR #5907 拉取 commit `a6e6ec0` 并本地构建 `tools/xray-core-anytls/xray.exe`。该二进制与 cnode AnyTLS 对齐参考来源一致。
  - 当前外部配置矩阵 config-only 校验已通过：xray-core PR 版、mihomo `v1.19.27`、sing-box `1.13.13` 共 17 项配置检查全部通过，覆盖 VMess / Trojan / Shadowsocks / AnyTLS 的 inbound / outbound 配置面。
  - 当前外部真实请求矩阵中，cnode inbound 方向已通过 12/12：xray-core AnyTLS PR 版、mihomo `v1.19.27`、sing-box `1.13.13` 均可通过 VMess / Trojan / Shadowsocks / AnyTLS 访问本地 HTTP 目标。mihomo Trojan inbound 用例采用本地 tunnel + 服务端 greeting 验证下行真实字节，因为 mihomo Trojan 客户端会先单独发送 Trojan 头并等待后续链路。
  - `external_protocol_traffic.ps1` 已修正 sing-box route 默认值后，cnode outbound 方向不再被客户端直连或服务端误路由掩盖；当前本地真实请求矩阵已通过 24/24，覆盖 cnode inbound 12/12 和 cnode outbound 12/12。
  - 真实请求矩阵修复了三个连通性问题：VMess inbound 在设置 pending 首包后才把最终 request 移入 `ServerSession`，避免 xray-core / mihomo 首包丢失；Trojan TCP inbound 交给 dispatcher 的 Link 改为真实 stream reader/writer，避免无 leftover 时无法继续读写；dispatcher 不再在 `first_packet` 为空时阻塞读取 late sniff payload，避免客户端等待链路建立而服务端等待首包的互等。
  - cnode sidecar 加载 smoke 已通过：脚本生成的 `config.json` + `inbounds.json` + `outbounds.json` + `routing.json` 能启动 cnode，日志确认加载 4 个 inbound、5 个 sidecar outbound、1 条 routing rule，并成功进入监听状态。
  - Router routing 规则已对齐 xray-core：规则未显式配置 `inboundTag` 时不再隐式追加 `node` 入站条件，而是匹配所有 inbound；只有配置中写出 `inboundTag` 时才按入站标签限制匹配。新增 `no_router_implicit_inbound_tag` 结构门防止回退。
  - 默认配置入口已改为 JSON 布局：CLI、部署配置文档和阶段 4 对齐约束均明确 `config.json` 是默认主配置文件；`config_loader` 已删除 `.yml` / `.yaml` 主配置解析兼容，并新增 `default_config_json_layout` 防止回退到 XrayR 式 YAML 默认入口或 YAML 解析入口。
  - Trojan inbound 修复后已重新执行本地 Windows 增量构建、远端 Linux x86_64 Release 构建、远端 inbound / outbound 真实请求矩阵和全量 `ctest`：`ctest` 共 141 项全部通过，远端 inbound 真实请求 12/12 通过，远端 outbound 真实请求 12/12 通过。
  - 远端 Linux x86_64 Release 构建已在 `node-02.11.9527app.site` 完成，当前部署二进制为 `/opt/cnode-e2e/bin/cnode`，构建产物为 `/opt/cnode-e2e/build/cnode`；使用远端 Debian 13 / GCC 14.2 / CMake / Ninja / `/root/vcpkg` 构建。构建过程中发现并删除了 `ParseDnsConfigValue`、`FirstBytes`、`DomainMatcher::AddRegex`、`DomainMatcher::Clear`、`DomainTrie::Clear`、`IPMatcher::Clear` 等未使用内部 helper，并修正 `Worker::RuntimeState` 初始化顺序，Linux 增量构建不再产生这些 warning。
  - 新增 `tests/e2e/remote_cnode_inbound_traffic.ps1`，用于把 cnode 部署到远端后，由本机 xray-core AnyTLS PR 版、mihomo `v1.19.27`、sing-box `1.13.13` 作为客户端发起真实请求。远端 cnode 仍按目录加载 `config.json` 主配置和 `inbounds.json` / `outbounds.json` / `routing.json` sidecar 内容。
  - 新增 `tests/e2e/remote_cnode_outbound_traffic.ps1`，用于验证远端 cnode 的 outbound 方向：VPS 上运行 cnode VMess ingress + 被测 outbound，本机运行 xray-core AnyTLS PR 版、mihomo `v1.19.27`、sing-box `1.13.13` 协议服务端和 HTTP 目标服务，并通过 SSH reverse forward 让 VPS outbound 连接这些外部实现。
  - 远端公网 IPv4 高端口 `46201-46204` 在服务器本机 `INPUT ACCEPT`、cnode 已监听 `0.0.0.0` 的情况下从本机不可达，判断为云侧入站策略限制；脚本会自动回退到 SSH local forward，仍由本机三套客户端发起完整协议握手和 HTTP 请求。
  - 远端 inbound 真实请求当前结果：xray-core AnyTLS PR 版 VMess / Trojan / Shadowsocks / AnyTLS 全部通过；mihomo VMess / Trojan / Shadowsocks / AnyTLS 全部通过；sing-box VMess / Trojan / Shadowsocks / AnyTLS 全部通过，合计 12/12。
  - 远端 outbound 真实请求当前结果：远端 cnode outbound 到 xray-core AnyTLS PR 版 VMess / Trojan / Shadowsocks / AnyTLS 全部通过；到 mihomo VMess / Trojan / Shadowsocks / AnyTLS 全部通过；到 sing-box VMess / Trojan / Shadowsocks / AnyTLS 全部通过，合计 12/12。
  - Trojan inbound 已修复 sing-box 头后应用数据卡住的问题：`TlsStream::ReadMultiBuffer()` 不再用 `SSL_pending()==0` 作为先读底层 TCP 的条件，而是始终先调用 `SSL_read()`，只有 OpenSSL 返回 `WANT_READ` 时才从底层 socket 补充密文。这样可正确处理 sing-box 将 Trojan 头和 HTTP 请求拆成相邻 TLS records、第二条 record 已在 BIO 中但尚未解密的情况。
  - 本地 `external_protocol_traffic.ps1` 已区分 sing-box client/server 路由默认值：客户端配置 `route.final=proxy`，服务端配置 `route.final=direct`，避免真实请求矩阵被 sing-box 客户端直连或服务端误路由掩盖。
  - 本地 outbound 方向已修复并验证：Shadowsocks outbound 不再在上传首包前等待服务端响应，避免 HTTP 目标互等；Trojan outbound 按 `streamSettings.tlsSettings` 保留 xray-core 的 `serverName` / `allowInsecure`，且不再抢读并取消 VMess ingress body；AnyTLS outbound 将 `auth + auth padding` 合并为同一次 TLS 写出，兼容 mihomo / sing-box 服务端首读 auth padding 的实现。
  - 最终回归验证已通过：`external_protocol_matrix.ps1` 配置矩阵 17/17 通过；本地 `external_protocol_traffic.ps1 -KeepGoing` 真实请求矩阵 24/24 通过；远端 `remote_cnode_inbound_traffic.ps1 -KeepGoing` 真实请求矩阵 12/12 通过；远端 `remote_cnode_outbound_traffic.ps1 -KeepGoing` 真实请求矩阵 12/12 通过；全量 `ctest` 共 141 项全部通过。

## 12. 验收标准

1. 构建必须通过。
2. 现有结构测试必须通过。
3. 每个阶段新增禁止回归测试。
4. 仓库中不得残留已禁止的公开抽象。
5. 请求链路只能有一条。
6. Worker 不知道协议细节。
7. Dispatcher 不知道协议细节。
8. Router 不知道 relay / outbound 具体实现。
9. Panel 不进入热路径。
10. 协议不拥有私有长期 buffer pool。
11. MultiBuffer 所有权清晰。
12. 配置热路径无 legacy / compat / panel 字段分支。
13. README、配置示例、部署脚本与最终结构一致。

## 13. 硬性删除规则

发现以下情况时，不做兼容，不做转接，直接删除、合并或下沉：

1. 公开 wrapper 层。
2. 公开 compat 层。
3. 协议 stream 对象作为请求链路一部分。
4. Worker 直接调用协议 validator。
5. Dispatcher include 具体协议。
6. Router 调用 relay。
7. Relay 解析协议。
8. Panel 修改 live handler。
9. 出站读取面板原始字段。
10. 热路径解析 JSON。
11. 连接对象常驻大 scratch。
12. 协议私有长期 pool。
13. manager 同时承担多个层级职责。
14. legacy 配置字段进入 runtime。

## 14. 最终判断标准

这个重构完成后，cnode 应该满足：

1. 从请求入口到 relay 的数据流一眼可见。
2. 任意协议都只是 Handler 实现，不拥有独立架构。
3. 任意配置来源都先归一化，再进入 runtime。
4. 任意热路径对象都归属 Worker-local 资源边界。
5. 任意模块都不知道不属于自己层级的东西。
6. 删除一个协议不会影响 dispatcher / router / relay / worker 的结构。
7. 替换一个 panel 不会影响协议热路径。
8. 替换 allocator 不会影响协议职责。
9. 替换 router 规则不会影响 inbound / outbound 实现。
10. 仓库结构表达最终职责，而不是表达迁移历史。
