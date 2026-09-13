# AGENTS

## 本文件职责

本文件是修改 cnode 代码时必须遵守的协作规则和架构红线。它面向 Codex、自动化 agent 和参与重构的维护者。

- `README.md` 负责项目介绍、配置入口、部署方式和架构概览。
- `AGENTS.md` 负责代码修改时的职责边界、禁止项、审查清单和硬性删除规则。
- 如果两份文档都提到同一架构边界，以本文件的硬约束为准。

## 沟通与环境

- 与用户沟通时默认使用中文。
- 需要执行诊断、联调或回归时，优先在当前可用的目标环境中完成。
- 若当前会话无法直连目标环境，应先说明限制，再继续给出可在本地完成的分析结果。
- 变更前先分析现有代码和配置，再决定是否需要修改。

## 项目不变量

- cnode 是 C++23 代理节点服务端，核心请求链路必须保持唯一。
- 控制面负责面板同步、配置归一化和运行时快照发布；热路径只读取不可变 runtime snapshot。
- 默认主配置文件是 `config.json`，目录侧车文件固定为 `inbounds.json`、`outbounds.json`、`routing.json`。
- cnode 与 XrayR YAML 配置布局有意不同，不回退到 YAML 默认入口或旧 sidecar path 字段。
- 任意配置来源都必须先归一化，再进入 runtime。
- 任意热路径对象都必须能明确指出所属 Worker；跨线程访问只能通过投递、快照或冷路径同步完成。
- 集中结构化日志的待发送批次只能驻留在有界进程内存；禁止创建或恢复 `access-spool` / `error-spool` 磁盘队列。
- proxyman receiver 在冷路径构建完整监听语义；进入 Dispatcher 时只能传不可变的窄 `DispatchPolicy`，不能传 `ReceiverSettings`。
- Router 只返回真实规则命中；强制出口和入站显式 fallback 由 Dispatcher 编排，不存在 Worker 全局默认出口。
- Dispatcher 只依赖 `routing::Router` 只读契约；具体 Router 在所属 Worker 冷路径一次构建完整、持有不可变规则，不公开原地配置更新入口。
- 每个 receiver 必须在冷路径明确构造 `ForceOutbound` 或 `RouteWithFallback`；策略不可默认构造，空 tag 不得进入热路径。

## 唯一请求链路

所有 TCP / UDP 请求最终只能经过这一条链路：

```text
Inbound Handler::Process
  -> Dispatcher::Dispatch
  -> Outbound Handler::Process
  -> Relay
```

不允许 Worker、协议实现、router、panel、proxyman、transport 或临时 helper 创建第二条绕过链路。任意协议都只是 Handler 实现，不拥有独立架构。

原生 datagram、UDP-over-TCP 和 Mux/子流可以存在必要的窄 helper，例如 `DispatchUDP`、`DialUDP` 或 UDP framer，但这些 helper 只能服务主链路语义：inbound 解析并生成 metadata，dispatcher 做路由，outbound 准备 Worker-local 出站资源，relay 以协议无关方式搬运数据。helper 不允许承载协议私有架构、路由选择、panel 字段理解、跨层访问或第二条请求链路。

## 层级职责边界

### inbound

inbound 是监听连接后的协议入站处理入口。

负责：

- 认证。
- 入站协议解析。
- 用户识别。
- 目标地址解析。
- 初始 payload 处理。
- 生成统一 session / context 元信息。
- 调用 `dispatcher.Dispatch`。

不负责：

- 路由选择。
- 出站连接。
- relay 细节。
- 直接访问 outbound manager 内部结构。
- 持有协议私有长期大 buffer。

### dispatcher

dispatcher 是请求链路的路由分发入口。

负责：

- 接收 inbound 交给它的不可变 `DispatchPolicy`、session / context / link。
- 按 `forced outbound` 或 `Router matched rule -> explicit inbound fallback` 的互斥策略完成出站选择。
- 通过通用 `RequestPolicy` 接口取得 allow / block 结果。
- 根据选择结果查找 outbound handler。
- 调用 `outbound.Process`。

不负责：

- 解析协议。
- 创建协议专属对象。
- 包含 VMess / Trojan / Shadowsocks / AnyTLS 特判。
- 直接执行 relay。
- 读取或理解 panel 配置字段。
- 接收完整 `proxyman::inbound::ReceiverSettings`。
- 依赖具体 `rule::Manager`、`DetectRule` 或其他面板策略实现。
- 把 forced / fallback 伪装成 Router 规则命中。
- 保存或推导 Worker 全局默认出口，或在策略缺失时选择第一个 outbound。

### router

router 只做路由决策。

负责：

- 接收归一化后的 session metadata。
- 仅在规则真实命中时输出 outbound tag / route decision。

不负责：

- 创建连接。
- 访问 relay。
- 访问协议实现。
- 依赖 proxyman 具体类型。
- 理解 Worker 资源细节。
- 保存或选择 forced outbound、入站 fallback、隐式默认 outbound。
- 依赖 outbound manager 或请求策略实现。

### request policy

request policy 是路由完成后的通用请求准入边界。

负责：

- 接收统一 session context。
- 返回 allow / block 结果。
- Worker-local 实现可以在冷路径发布规则，并在所属 Worker 内记录命中结果。

不负责：

- 路由选择。
- 查找或调用 outbound handler。
- 解析协议。
- 向 Dispatcher 暴露面板原始规则或具体 manager 类型。

### outbound

outbound 是出站协议处理入口。

负责：

- 根据 dispatcher 选择执行出站处理。
- 建立目标连接或下一跳连接。
- 执行出站协议握手。
- 执行出站编码。
- 完成出站链路准备后交给 relay。

不负责：

- 路由决策。
- 读取 panel 原始配置。
- 绕过 dispatcher。
- 保留旧 stream process 入口或协议 wrapper。

### relay

relay 只搬运数据。

负责：

- TCP 双向转发。
- UDP 转发。
- Mux 数据搬运。
- 流量统计打点。

不负责：

- 解析 VMess / Trojan / Shadowsocks / AnyTLS 协议。
- 选择 outbound。
- 访问 panel。
- 持有连接生命周期级别的大 scratch。
- 暴露 wrapper API。

### Worker

Worker 只负责运行时边界。

负责：

- 事件循环。
- accept 生命周期。
- 运行态组件持有。
- thread-local allocator / buffer provider。

不负责：

- 理解具体协议 validator。
- 理解具体 outbound 类型。
- 路由。
- 协议解析。
- panel 同步。

### proxyman

proxyman 只负责 prepared inbound / outbound handler 的构建、持有和按 tag 查找。

负责：

- 管理 inbound / outbound handler 生命周期。
- 将控制面准备好的 runtime 对象发布给 Worker-local handler 表；完整 receiver 内嵌冷路径构建的不可变 `DispatchPolicy`。
- 为 dispatcher 提供 outbound handler 选择结果。

不负责：

- 解析协议或 panel 字段。
- 自己做路由选择。
- 直接进入 relay。
- 暴露跨 Worker 可变 handler 指针或引用。

### transport

transport 只负责连接形态和传输栈。

负责：

- TCP、TLS、WebSocket、PROXY protocol、dialer 和 transport stack。
- 把已经建立或接受的连接交给上层 handler。

不负责：

- 解析代理协议。
- 选择 outbound。
- 理解 panel 配置。
- 持有协议私有长期 buffer pool。

### control plane

`service/controller` 与 `api/*` 只属于控制面。

负责：

- 拉取节点信息。
- 拉取用户列表。
- 拉取规则和面板策略。
- 归一化为运行时配置。
- 构建 inbound / outbound / routing / policy runtime。
- 原子替换运行态。
- 按面板语义上报节点状态和用户流量。

不负责：

- 进入流量热路径。
- 直接访问 Worker buffer provider。
- 直接修改 live handler 内部状态。
- 持有协议实现细节。
- 按具体协议构建认证用户凭据。

## Worker-local 与线程边界

Worker-local 无锁设计只在所属 Worker 线程 / `io_context` 内成立。

允许：

- Worker 私有 manager、handler 表、listener slot、UDP session、stats shard、allocator 和 buffer provider 只在所属 Worker 线程访问。
- 跨线程控制面通过 `Worker::*Async`、`net::post` 或等价投递序列化到目标 Worker 线程。
- 投递协程时，通过值参数或由 `co_spawn` 持有的 callable 保存状态；禁止先调用临时捕获 lambda，再投递依赖已销毁闭包的 awaitable。
- 不可变 runtime snapshot 以 `shared_ptr<const ...>` / 原子替换方式发布，发布后只读。
- DNS service、inflight resolve、UDP socket、timeout scheduler 和 Worker L1 DNS cache 归属当前 Worker；跨 Worker 只允许共享不可变 DNS 结果 snapshot。
- Worker 的回调超时调度器始终只保留一个在途 timer 等待；更早事件唤醒既有等待，由完成回调统一重新调度。取消、令牌析构和堆整理不得分配或重挂 timer，等待启动成功前不能发布在途标志。协程休眠使用拥有实际异步等待的 AsyncDelay，取消不经过第二个 channel；拥有者必须等待在途 WaitFor 完成后才能销毁。
- 需要跨 Worker 聚合的数据先复制、快照化或通过明确同步结构进入冷路径。
- 批量协程在返回或抛出前必须等待已启动的子任务全部结束；父请求取消或部分启动失败不得让子任务继续借用已销毁的调用者状态。
- 常驻监控循环各自持有上下文并独立报告退出；不能把单个循环的失败通知推迟到其他常驻循环全部结束。
- 面板同步和固定 60 秒状态心跳必须使用独立循环；状态循环在控制面所属 executor 只读最后提交的节点状态，不等待网络请求，不持有跨 await 的 map 引用。状态循环失败单独报告，不能改写面板连接状态。
- 进入 RunApplicationRuntime 后，Worker 和运行时持有者存活至进程退出。信号立即以成功码退出；启动失败、事件循环异常或意外返回先同步输出原因，再立即以失败码退出，不能展开持有者或恢复单次 post 后销毁 Worker 的回滚路径。配置解析与冷路径构建失败仍正常返回错误。
- Worker 和 io_context 的集合成员由 bootstrap 冷路径确定；运行时、控制面、入站启动和监控只能借用只读集合，不能增删或替换成员。Worker 内部状态仍通过所属 executor 上的 Task 或快照访问。
- 面板资源标签必须包含面板名称和节点 ID，使用保留的 `panel/` 前缀；静态入站主 tag 和静态出站 tag 不得占用该前缀。不同节点不能因协议、端口相同而共用 handler、用户或清理目标。
- 面板端点准入在控制面所属 executor 完成，使用节点事务的已提交及待清理快照识别占用；无待清理项时，准入检查至事务记录旧/候选快照之间不得挂起。更新中和清理未完成的端点继续保留，不能依靠各 Worker 分别竞争 SO_REUSEPORT 来决定不同节点的所有权。
- TCP、UDP 监听分别在所属 Worker 内检查其他 tag 的端点占用；同地址族中通配地址与具体地址重叠，IPv6 监听固定 v6-only。auto 模式保留完整请求地址范围，不能利用某个候选绑定失败绕过冲突。同一 tag 的同 socket 更新才允许复用，其他 tag 的失败和清理不得影响原监听。

不允许：

- 直接从其他线程或其他 Worker 读写 Worker 私有对象，即使当前实现看似无锁或只有 atomic。
- 把 `AsyncStream`、`UDPSession`、handler、manager、listener、thread-local allocator / buffer provider 的裸指针或引用保存到其他 Worker。
- 将无锁容器、thread-local 缓存、Buffer / MultiBuffer 池作为跨 Worker 共享状态。
- 将 DNS service、inflight resolve、UDP socket、timeout scheduler 或 Worker L1 DNS cache 作为跨 Worker 共享可变对象。
- 发布后原地修改 runtime snapshot，或通过 `const_cast`、缓存内部指针等方式绕过快照不可变性。
- 为了跨线程访问热路径状态临时加锁；需要跨线程协作时应改为投递、复制快照或冷路径同步。

## 地址解析边界

文本 IP 只通过 `iputil::ParseLiteral` 解析完整字面量；端口、URL authority 和 CIDR 前缀由对应入口拆分。各调用层禁止直接调用平台或 Asio 的字符串地址转换，以免静默丢弃端口、方括号或 NUL 后缀。IPv4 使用四段无前导零的十进制格式，IPv6 可携带数字 scope ID；接口名解析不属于纯字面量入口。IP 与 DNS hostname 的判定由各使用层按自身语义组合，通用 IP 解析器不做 DNS 查询，也不决定 IPv4-mapped IPv6 的归一化策略。

## DNS 缓存与解析快照

DNS 解析采用 Worker-local service + 进程级只读结果快照的两级缓存。

DNS 上游配置在冷路径归一化为完整 UDP endpoint；默认端口只在配置入口补齐。Worker service 的不可变 Config 是服务器列表唯一来源，不能另存 IP 列表再在服务中推导端口或重建第二份服务器表。配置解析必须先拆分 host/port，不能把带端口字符串交给可能静默丢弃端口的平台 IP 解析器。

允许：

- 每个 Worker 持有自己的 DNS service、inflight resolve 表、UDP socket、timeout scheduler 和 L1 cache。
- `GlobalDnsCache` 按分片保存 `shared_ptr<const ShardSnapshot>`，读取只 atomic load 不可变结果。
- DNS 真实解析成功或 negative cacheable 后，复制目标分片、合并结果、清理过期项并 CAS 发布。
- `cacheSize` 表示进程级 L2 DNS 结果缓存容量；Worker L1 cache 只能是派生的小型本地缓存。
- L1 插入必须先完成节点和索引构建，再淘汰旧项；分配失败不得破坏已有缓存。L2 回填沿用剩余 TTL，不能重新应用最小 TTL 延长寿命。
- 同一 Worker 的并发同域查询共享待完成结果；完成、异常退出和等待者取消必须清理各自状态，不能依赖逐等待者复制结果才能通知完成。
- 缓存写入是解析成功后的可选优化；缓存分配失败不能丢失已取得的解析结果。

不允许：

- 把 DNS service 本身做成全局单例供多个 Worker 直接调用。
- 在全局 DNS snapshot 上做读命中 LRU 移动、last_access 更新或其他热路径写入。
- 让全局 DNS cache 持有 `io_context`、socket、协程 waiter、Worker-local allocator / buffer provider 或请求生命周期对象。
- 用锁或 atomic 共享当前 Worker 的 DNS L1 cache、inflight resolve 表或 socket。
- 将协程栈上等待者的裸指针保存在 inflight 表，或将缓存写入、结果复制成功作为完成通知的前提。

## 用户存储与认证快照

面板用户、静态用户和测试用户最终必须统一进入同一套认证用户存储模型。

用户同步链路：

```text
api/* 拉取 panel 原始 users
  -> api::UserInfo
  -> controller 归一化为 RuntimeUser
  -> proxy/<protocol> 注册的 build_users / build_static_users
  -> proxyman::inbound::UserSet
  -> UserStore 不可变 RCU snapshot
  -> inbound validator 只读认证
```

统一约束：

- `api/*` 只负责把面板响应解析为 `api::UserInfo`，不构建协议凭据。
- `service/controller` 只负责用户字段归一化、差量对比和发布触发；不能按 VMess / Trojan / Shadowsocks / AnyTLS 分支生成 UUID account、password hash、SS derived key 或 AnyTLS hash。
- 协议用户构建只能位于协议注册项 `build_users` / `build_static_users`，协议私有 hash、key、account 构造必须留在 `src/proxy/<protocol>` 内部。
- `UserSet` 是进入认证存储的唯一协议用户载体；面板用户、静态用户和测试用户都必须通过 `UserStore` 发布。
- `UserStore` 是进程级认证用户 RCU 快照，按 `protocol + tag` 保存不可变容器；冷路径复制构建并原子发布，热路径只加载只读视图。
- 所有启动入站必须先归一化为普通静态入站配置，再对完整集合校验身份和监听端点，最后经同一协议注册入口准备 handler 配置及 UserSet。测试模式只能提供配置，不得另行构建 runtime、绕过校验或发布用户。
- 启动入站准备函数不得修改 UserStore 或 Worker。全部描述和协议载荷准备成功后，bootstrap 通过一次批量 ApplyUsers 发布用户快照；批量发布的分配失败必须保留原快照，不能逐 tag 提前提交。
- inbound validator 只做协议认证、用户查找和 Worker-local 在线设备追踪；公开用户更新接口必须统一为 `ApplyUsers` / `AddUsers` / `RemoveUsers` / `ClearUsers`。
- 在线设备、连接数和限设备检查属于 Worker-local tracker，不进入全局 `UserStore`，也不能跨 Worker 直接共享。

## 配置与热更新

- 传输配置归一化以值转换返回新的 StreamSettings；分配失败必须向冷路径调用者报告，保留输入及调用者已持有的值。不得把会分配的归一化声明为 noexcept，也不得以公开原地 mutator 更新缓存字段和 ALPN。
- JSON 解析留在配置层，传输模式、ALPN 归一化及传输配置查询实现归属 transport。出站归一化在协议注册的冷路径准备回调完成，prepared creator 和 Worker-local handler 构造不得再次归一化同一配置。
- 出站凭据必须在所属协议的准备回调中完整验证并构造，再交给 prepared creator；Worker-local handler 只消费已准备的不可变值。不得接受无效凭据后仅记录错误、暗中替换加密方法、丢弃身份链片段或保留等待首个请求才失败的可空凭据。
- 固定密码摘要和 VLESS encryption 等不可变协议配置只在准备阶段构造；codec 只编码已准备的认证值，不能每次请求重新哈希密码。连接票据、PFS 状态及会话池属于 Worker-local 可变状态，不能随只读凭据一起跨 Worker 共享。能从配置确定的 flow/transport 限制必须在准备阶段拒绝。
- AnyTLS 物理会话由单一 Worker-local 会话池持有，获取后立即标记占用，正常完成才归还；握手、子流注册或转发异常退出必须通过作用域所有权关闭会话。空闲检查由所属 Worker 的定时器执行，不能依赖下一次请求；最小空闲数量在关闭过期会话之前计算。定时回调不得借用 handler，退役必须关闭会话并取消定时器，旧取消回调不能覆盖新一轮调度状态。
- AnyTLS 跨请求存活的物理任务由会话池接纳时启动，必须有显式完成回调持有池状态与物理会话；禁止由 Process 创建 detached 读循环或保存启动标志。完成回调必须处理异常、关闭失效会话并唤醒逻辑请求，不能让已结束的任务仍可复用。退役同时取消物理协程，池门面和索引移除只表示停止接纳，不能冒充 join；在途根任务必须持有全部自身 I/O 状态直到实际完成，不能借用 Handler 或请求 Context。索引删除前保留关闭对象所有权，整体退役先移出索引再广播关闭；有限逻辑请求继续由请求作用域收束。
- AnyTLS 出站请求独占池中物理会话期间，逻辑端点的 relay 控制必须落实到底层 AsyncStream，覆盖后台读循环、写入和半关闭截止时间；取消在途写入时必须关闭整个会话，不能复用可能只写出部分帧的连接。正常完成归还前清除全部请求超时，不能让请求截止时间进入空闲池。
- 原生 UDP 出站统一经 Worker-local UDPChannel 接入 DoRelayLink。协议私有端点只编解码数据报，不持有回包队列、socket 回调或请求定时器；回调注册、队列上限和 idle/read/write/phase 控制由通用端点负责。取消必须覆盖 DNS 和在途发送，并等待被取消操作结束，不能关闭其他请求共享的 UDPSession socket。注销回调必须无分配且可重入，定时回调不得借用已退役端点；禁止用一次 net::post 代替生命周期证明。
- 冷路径秒数转换为 steady_clock duration 前必须检查可表示范围；相对间隔计算绝对截止时间时不得发生有符号溢出。
- 冷路径可以做 JSON 解析、字段兼容和对象构建。
- 热路径只消费预构建 runtime，不解析 JSON、不理解 panel 字段、不重复构建协议凭据。
- 配置热更新只能原子替换 runtime snapshot，不能原地改写正在运行的对象图。
- 默认主配置文件是 `config.json`，目录模式只读取固定侧车文件 `inbounds.json`、`outbounds.json`、`routing.json`。
- 不回退到 YAML 默认入口，不读取旧 sidecar path 字段，不让 legacy 配置字段进入 runtime。

## 协议约束

- 协议核心必须统一为 `Handler::Process` 模型。
- VMess、Trojan、Shadowsocks、AnyTLS、Freedom、Blackhole 都必须遵守同一职责边界。
- 入站协议实现位于 `proxy/<protocol>/inbound`，负责 decode inbound request、authenticate user、produce session metadata、call dispatcher。
- 出站协议实现位于 `proxy/<protocol>/outbound`，负责 dial target or next proxy、encode outbound request、hand over to relay。
- 协议内部允许存在 reader、writer、codec、crypto helper，但这些只能是私有实现细节，不能成为公开请求链路对象。
- AnyTLS codec 只把真实 IoSystemError 转为 I/O ErrorCode，协议拒绝继续使用结果值；bad_alloc、LinkError 和其他异常保留原类型，交给拥有请求或物理任务的边界分类。逻辑端点用通用 LinkError 传递已有原因，禁止伪造 errc::io_error、connection_reset 或 no_buffer_space。通用入站对协议 Process 的异常保留逻辑原因、资源不足和真实 I/O 分类；未知异常由所属请求阶段分类，不能在 codec 中伪装成 socket 故障。
- AnyTLS 已取得物理写入租约的操作在异常退出时必须立即关闭失效会话并保留原因，再向所属任务传播，不能让残缺帧连接回到池中或被后续控制帧继续使用。子请求失败记录使用任务自己持有的 Context，不能依赖仍然存在于可能已被整体取消清空的索引中。
- 协议不能拥有独立请求链路，所有协议必须进入 `inbound.Process -> dispatcher.Dispatch -> outbound.Process -> relay`。
- UDP / Mux helper 不能成为协议私有请求链路；datagram 资源必须归属当前 Worker，路由和出站选择仍由 dispatcher / outbound 负责。

## 开发规范

- 优先沿用现有目录职责、命名风格、协程模型、RAII 和错误处理方式。
- 公共头保持窄接口，避免暴露协议私有 helper、运行态存储、完整配置对象或跨层依赖。
- 公共 helper / method 必须有当前生产或测试调用；不为假设中的未来需求保留未使用的格式化、转换、清空、兼容或 convenience API。
- 协议私有 reader、writer、codec、crypto helper 留在 `src/proxy/<protocol>` 内部。
- 借用会话状态的有限后台读取和动态子请求必须由同一 Worker 的任务组持有，并在释放会话状态前等待每个 co_spawn 完成回调。启动前先取得 join continuation；部分启动失败和父任务取消都要取消已启动子任务并等待完成，不能退出后再补建等待操作。业务 EOF 计数、done 标志和一次 net::post 只能表达业务状态，不能代替 join。任务组只管理协程生命周期，不接管协议解析、路由或 relay。
- 多路复用会话整体结束时，除了终止各逻辑读端，也要取消拥有任务组内的异步操作，覆盖尚未进入 Dispatcher 的协议解析等等待。父作用域必须在 join 后才归还在线会话租约或销毁 transport；子流对父会话的 Worker-local 借用由这一完成边界覆盖，不能以父子 shared_ptr 循环持有代替退出协议。
- AnyTLS 新 stream ID 必须在当前 Session 内严格递增且非零，已退役 ID 不得重用；SYN 只能创建独立的新请求，不能重置活动请求的接收状态或改写其 Context。非法 SYN 发出 Alert 后结束会话，合法 ID 允许跳号。跨 co_await 保留子流的所有权，不保留可能由其他子任务删除的表项迭代器。普通数据帧和 FIN 不能隐式创建缺失的子流。
- AnyTLS FIN 表示整个逻辑流关闭，不能作为 TCP 写半关闭使用。收到 FIN 后不得继续启动该流的 PSH 写入，也不得回复 FIN；本地关闭只发送一次 FIN，关闭后的 PSH 不能恢复流。已接收数据的有界排空不代表反向写端仍开放，正常关闭必须收束两个转发方向并保持物理 Session 可用于新流。Relay 通过通用链路语义区分半关闭与完整关闭，不能包含 AnyTLS 分支；UoT framing 必须传递底层关闭语义。串行写入必须在取得写入租约后再次检查逻辑终态；进入物理写入后的失败仍关闭整个 Session。
- AnyTLS 出站的开流等待必须读取同一逻辑流的 ACK、关闭及首个错误状态，通知只能用于唤醒，不能充当成功结果。开始等待前已经发生的 FIN 必须允许有界排空，已发生的错误不能变成新的等待或超时；ACK 不能覆盖已发生的错误。有限等待自己持有超时令牌，返回、取消或异常退出均同步撤销回调，不能在跨请求存活的逻辑对象上再维护独立的等待/超时标志。错误 SYNACK 的文本读取失败必须保留真实 I/O 原因，不能一律改写成对端协议拒绝。
- 通用 Link 的 ReadEofAction / WriteShutdownClosesLink 必须跨类型擦除保留，读端 EOF、写端关闭和正常写拒绝不能混同为请求故障。WriteClosed 只允许在启动写入之前抛出，relay 保留另一方向已经接收的数据；完整关闭取消并等待同伴 I/O 与限速任务结束后才执行最终关闭。TLS 底层回调包装必须向实际 socket 操作传递关联取消槽，不能让 SSL 内部读写脱离请求任务的取消范围。
- AnyTLS 帧循环只处理会话控制和按 ID 分发；SYN 注册的有限子任务负责从逻辑字节流解析 SOCKS 目标、UoT 请求和子请求 metadata。地址可以跨多个 PSH，解析后剩余数据必须以拥有所有权的 MultiBuffer 转交 InitialPayload 或 UoT reader；禁止按首个 PSH 整帧解释/清空目标地址，禁止恢复 PendingTarget/PendingUotRequest 帧状态机。解析错误只结束对应子流，整个会话退出仍必须取消并 join 所有解析与 dispatch 任务。
- AnyTLS 入站每个 Session 最多接纳 128 条未结束子流，预算同时覆盖待解析和已进入 Dispatcher 的请求；超额在分配子流与任务之前拒绝，只结束新流并退役该 ID。每条子流从接纳 SYN 开始共享一个 `timeouts.handshake` 绝对预算，覆盖 SOCKS 目标、UoT 初始请求及 SYNACK 写入，心跳和零碎数据不能续期；解析子任务及定时器必须结束后才进入 Dispatcher。已到期但尚未执行的定时回调不能让迟到地址进入 Dispatch。等待共享写入门闩的超时只取消该子流；实际物理帧写入开始后发生异常或失败，必须关闭整个 Session，不能继续拼接或复用可能残缺的帧。
- AnyTLS 入站与出站的逻辑输入均按拥有所有权的 MultiBuffer 聚合字节，不能按 PSH 再嵌套逐帧队列或独立维护字节计数。两端共用协议私有的 AppendQueuedPayload，仅负责缓冲聚合；队列预算、唤醒和终止由各自所有者负责。队列有效数据最多 65,535 字节，除尾块外每块至少承载半个 Buffer，实际持有不超过 16 块；追加先保留全部指针槽位，再合并小片段或转移大块。单一物理帧读取可另持有最多 8 块，不能把排队容量当成整个 Session 的内存预算。读取整体转移所有权并唤醒容量等待；两端满队列均暂停物理读取并等待消费者，不得把正常字节流突发当作 RESOURCE_EXHAUSTED。等待必须属于物理读任务并持有当前 payload/逻辑流，关闭同时唤醒容量等待，不能创建 detached 追加任务或无界暂存队列。正常 FIN 排空数据，错误关闭先发布终态、清空未读队列，再通知取消，防止重入覆盖首个错误；取消及真实分配失败必须释放排队和在途缓冲。UoT 包边界由后续 decoder 解释，不能依赖 PSH 边界。删除旧队列时同步移除收缩状态、无调用身份/参数和只为其服务的 include/helper。
- AnyTLS 的客户端/服务器 settings 必须经过协议私有的精确键值解析，完整校验版本数值，不能以子串、截断整数或未知字段推断能力。会话只接收一次对端 settings，协商状态发布后不再改写；未收到版本声明时使用 v1 能力。ServerSettings、SYNACK 和心跳只按双方支持的能力启用，重复设置、错误方向或错误 stream ID 的控制命令必须终止会话。协议实现标识必须声明 cnode，不冒用其他实现名称。
- AnyTLS 填充方案由协议私有 padding 模块解析为只读稀疏索引，存储必须与实际规则数量相关，禁止按远端最大索引 resize。codec 只消费规则及采样尺寸，不持有文本解析、摘要或规则构建逻辑。默认方案、入站 prepared settings、Handler 和 Session 共享 const 方案；出站更新整体替换，在途写入持有原快照。包序号由 Session 递增并在最大值饱和，是否填充由方案判断，不得在 stop 后回退到认证索引 0。入站协议的 prepare_settings 必须在发布前验证归一化原文能装入 UpdatePaddingScheme 帧，按 UTF-8 字节数及统一帧容量检查，不能在热路径握手时才发现可提前拒绝的配置错误。
- AnyTLS 下发方案属于 Worker-local 出站客户端，不能只保存于物理会话，也不能以进程级可变对象在不同出站间共享。Session 的后台任务持有该客户端状态的所有权，不借用 Handler；旧 Handler 退役期间的状态不能流入新 Handler。认证、首次 settings 摘要及首次开流帧必须持有同一不可变方案，即使认证 I/O 挂起期间另一会话发布更新，也不能混用不同版本。首次开流完成后释放该快照，后续写入读取客户端当前方案；禁止重新引入独立 settings_sent 标志或默认方案格式化入口。认证填充缓冲只属于有限握手作用域，不能常驻连接或限制为默认填充长度。
- 冷路径可以做 JSON 解析、字段兼容和对象构建；热路径避免 JSON 解析、panel 字段判断、重复分配、重复拷贝和不必要锁。
- Buffer / MultiBuffer 必须保持清晰所有权，move 后即视为转移，消费结束后及时归还或释放。
- MultiBuffer 接收和交出单块缓冲时使用 BufferGuard，不能先 release 裸指针再执行可能分配的插入。按值接收的 guard 在插入失败时自动释放；容器长度仅在成功接管后更新。追加、整段搬移和前缀拆分必须先准备所有缓冲及目标槽位，再修改字节、游标或源所有权；分配失败时保留原有数据，reserve 的容量保证按未消费的有效槽位计算。InitialPayload 只允许移动，溢出长度从拥有的 MultiBuffer 派生，不保留隐式复制或失败后虚增长度的路径。
- Dispatcher 将首包统一为拥有所有权的 MultiBuffer，并按值移交 outbound；relay 把它作为普通上行循环的第一份数据，首包与后续数据共用限速、错误处理和成功流量统计。出站握手只发送协议控制数据，不能提前发送用户 payload 后补记字节，不能恢复独立首包 relay 入口。首包转换分配失败必须保留尚未转交的数据并报告错误。
- Dispatcher 必须把实际读端的 CancellationSource 连接到完整请求协程的取消范围，覆盖嗅探、路由 DNS、出站拨号/握手和 relay，不得依赖可选 control 或协议特判。有限请求先取得 join continuation，再启动；订阅上下文不得超过所借用任务组的寿命，请求实际结束后才释放负载计数和记录终态。已停止读端不得进入路由/出站；DNS 返回后仍须检查取消再改写 context 和继续路由。逻辑终止原因与嗅探 LinkError/bad_alloc 分类必须保留，relay 已完成结果不能被正常收尾的 Cancel/Close 覆盖。
- TokenBucket 是 Worker-local、不可复制的额度预留状态；等待时间必须先记入已消费的未来额度，保留不足一字节的余额，时间和速率运算必须饱和，不能因乘法上溢或等待结束而额外授予额度。relay 的两个限速等待由收束两个方向的父作用域持有；relay 半关闭截止时间和方向失败必须同时取消实际 I/O 与限速等待，等待恢复后先检查终止状态再写出数据。截止回调及借用状态不得逃出已完成 join 的 relay 作用域，最终错误分类不能被另一方向的伴随取消覆盖。
- MultiBufferReader 必须通过 Worker-local CancellationSource 发布取消，协议 framing reader 委托其数据来源；不能依赖可选 AsyncStream control 才获得终止通知。CancelPending 只取消当前注册操作，Stop 永久保留终止原因；后续订阅同步收到已终止结果，订阅上下文必须先完成初始化。订阅由观察该来源的请求或 relay 作用域持有且一次触发，注册、撤销和通知不得分配、投递或跨线程访问；组合 transport 在临时取消后显式重新订阅，永久终止不得重新开启。源与订阅不可复制或移动，允许回调重入及撤销其他订阅；逻辑子流必须发布自己的取消，不能借用共享物理流的取消来终止其他子流。TCP 各类截止回调统一经 Cancel 通知，不能直接取消 socket 而跳过请求或 relay 的等待。
- relay 是否订阅终止事件不能取决于是否限速；取消既有读取、准备下一次读取及等待恢复后都须检查终止原因，不能把被取消的空读取当作正常 EOF。无控制入站的 uplinkOnly/downlinkOnly 同样约束剩余方向，停止等待任务必须与两个传输方向一起取消并收束；时间换算先饱和，不允许极大秒数溢出为立即超时。
- 新增行为要同步考虑静态配置、面板配置、热更新、TCP、UDP、Mux/子流和源进源出语义。

## 开发约束

- Worker 不直接访问协议 validator、panel 字段或具体 outbound 实现。
- Dispatcher 不 include 具体协议，不绕过 router/outbound/relay。
- Dispatcher 只接收窄 `DispatchPolicy`，不接收 `ReceiverSettings`，不依赖具体面板规则 manager。
- Router 只返回真实规则命中，不持有 forced / fallback / implicit default，不创建连接，不访问 outbound manager 或 relay。
- RequestPolicy 只返回准入结果，不选择路由或 outbound。
- Relay 只搬运数据，不解析协议，不理解面板。
- Panel/client/controller 不进入热路径，不修改 live handler 内部状态。
- 控制面按单节点面板实体直接持有客户端、只读配置、连接状态、已提交节点快照和统计；完整构造后才能加入集合，禁止用客户端裸指针关联多张表来补齐必需配置，也不能依赖客户端反查已归一化的配置。
- 面板节点的候选只读快照及回滚凭据必须在运行变更前完成构建；最终仅在全部运行操作成功后替换共享只读快照持有者，不得因新的分配而中断提交。用户数直接来自已提交用户快照，不另存重复计数。
- 最后提交的节点快照与当前运行态健康必须分离。回滚失败要明确失效运行态并保留旧节点及候选节点的清理目标；未完成清理不得开始新变更，待清理资源的释放不能依赖面板网络恢复。
- 面板 HTTP 候选地址回退只允许发生在连接和 TLS 握手阶段；开始发送 HTTP 请求后，发送或响应错误不得触发换地址重发，避免重复提交已被面板接收的流量增量。
- 面板请求使用冷路径归一化的有限 RequestTimeout；超时取消请求协程并等待其结束，不能以活动 socket 注册表或借用 stream 的定时器回调代替所有权。完整收到的响应不得因 TLS 关闭握手失败或取消而丢失。
- 禁止跨线程或跨 Worker 直接访问无锁热路径对象；无锁的前提是单 Worker 所有权，不是任意线程可访问。
- 禁止把 Worker-local 裸指针、引用、buffer provider、allocator、handler、manager、UDPSession 或 AsyncStream 逃逸到其他 Worker。
- 禁止把 DNS service、inflight resolve、UDP socket、timeout scheduler 或 Worker L1 DNS cache 提升为跨 Worker 共享可变对象。
- 禁止把 legacy、compat、adapter、wrapper、old 或旧面板私有命名作为最终公开设计保留。
- 禁止协议、transport、relay、panel 维护长期私有大 buffer pool。
- 配置热更新只能原子替换 runtime snapshot，不能原地改写正在运行的对象图。
- 禁止在 controller、panel client、dispatcher、router、relay 或 Worker 中按具体协议构建认证用户凭据。
- 禁止绕过 `RuntimeUser -> UserSet -> UserStore` 增加第二套面板用户存储、协议私有公共用户表或热路径用户缓存。

## 硬性删除规则

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
15. 跨线程或跨 Worker 直接访问 Worker-local 无锁对象。
16. Worker-local 裸指针、引用、buffer provider、allocator、handler、manager、UDPSession 或 AsyncStream 逃逸到其他 Worker。
17. 用 lock-free / atomic 共享 live handler、manager、连接对象或 buffer pool 来绕过 Worker 所有权。
18. controller 按协议构建认证用户凭据。
19. 面板用户绕过 `RuntimeUser -> UserSet -> UserStore` 链路进入热路径。
20. DNS service、inflight resolve、socket、timeout scheduler 或 Worker L1 DNS cache 跨 Worker 共享。
21. Dispatcher 公开接口或实现接收、保存 `ReceiverSettings` 或依赖 `proxyman::inbound`。
22. Router 保存或选择 forced outbound、入站 fallback、隐式默认 outbound。
23. Dispatcher 依赖具体 `rule::Manager`、`DetectRule` 或面板策略类型，而不是通用 `RequestPolicy`。
24. Mux / AnyTLS 子流为重新进入 Dispatcher 而保存完整 receiver，而不是窄 `DispatchPolicy`。
25. receiver 的出口策略可以默认构造、接受空 tag，或由 Worker / Dispatcher 回退到第一个 outbound。

## 审查清单

cnode 应满足：

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
11. 任意无锁对象都能明确指出所属 Worker，跨线程访问只能通过投递、快照或冷路径同步完成。
12. Dispatcher 的公开热路径只暴露 `Dispatch`，参数中没有 proxyman receiver 或面板策略实现。
13. Router 的无匹配结果为空，显式 fallback 只能在 Dispatcher 中解析；系统不存在隐式全局默认出口。
14. 面板 DetectRule 通过 RequestPolicy 抽象接入，不污染 Router 或 Dispatcher 类型边界。
15. 未启用 routing 的静态 inbound 使用 `ForceOutbound(direct)`，即使规则可命中也不得进入 Router。
16. 公共头不存在全仓无调用的 helper / method；删除入口时同步删除只为该入口服务的实现、状态和 include。

## 部署约束

- 部署脚本 `scripts/cnode.sh` 不带参数时更新二进制及 `geoip.dat`、`geosite.dat`；geodata 必须先下载到临时目录，下载失败保留旧文件，内容变化后重启原本运行中的服务以加载新规则。更新模式不得改写既有 panel 或 sidecar 配置。
- `scripts/cnode.sh -debug_file true` 可额外下载对应的 `.debug` 符号文件。
- VPS 或线上环境优先拉取发布产物进行诊断，不默认在目标机上临时编译。
