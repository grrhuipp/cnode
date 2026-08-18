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
- proxyman receiver 在冷路径构建完整监听语义；进入 Dispatcher 时只能传不可变的窄 `DispatchPolicy`，不能传 `ReceiverSettings`。
- Router 只返回真实规则命中；强制出口、入站 fallback 和 Worker 默认出口由 Dispatcher 编排。

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
- 按 `forced outbound -> Router matched rule -> inbound fallback -> Worker default` 的优先级完成出站选择。
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
- 把 forced / fallback / default 伪装成 Router 规则命中。

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
- 保存或选择 forced outbound、入站 fallback、Worker 默认 outbound。
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
- 不可变 runtime snapshot 以 `shared_ptr<const ...>` / 原子替换方式发布，发布后只读。
- DNS service、inflight resolve、UDP socket、timeout scheduler 和 Worker L1 DNS cache 归属当前 Worker；跨 Worker 只允许共享不可变 DNS 结果 snapshot。
- 需要跨 Worker 聚合的数据先复制、快照化或通过明确同步结构进入冷路径。

不允许：

- 直接从其他线程或其他 Worker 读写 Worker 私有对象，即使当前实现看似无锁或只有 atomic。
- 把 `AsyncStream`、`UDPSession`、handler、manager、listener、thread-local allocator / buffer provider 的裸指针或引用保存到其他 Worker。
- 将无锁容器、thread-local 缓存、Buffer / MultiBuffer 池作为跨 Worker 共享状态。
- 将 DNS service、inflight resolve、UDP socket、timeout scheduler 或 Worker L1 DNS cache 作为跨 Worker 共享可变对象。
- 发布后原地修改 runtime snapshot，或通过 `const_cast`、缓存内部指针等方式绕过快照不可变性。
- 为了跨线程访问热路径状态临时加锁；需要跨线程协作时应改为投递、复制快照或冷路径同步。

## DNS 缓存与解析快照

DNS 解析采用 Worker-local service + 进程级只读结果快照的两级缓存。

允许：

- 每个 Worker 持有自己的 DNS service、inflight resolve 表、UDP socket、timeout scheduler 和 L1 cache。
- `GlobalDnsCache` 按分片保存 `shared_ptr<const ShardSnapshot>`，读取只 atomic load 不可变结果。
- DNS 真实解析成功或 negative cacheable 后，复制目标分片、合并结果、清理过期项并 CAS 发布。
- `cacheSize` 表示进程级 L2 DNS 结果缓存容量；Worker L1 cache 只能是派生的小型本地缓存。

不允许：

- 把 DNS service 本身做成全局单例供多个 Worker 直接调用。
- 在全局 DNS snapshot 上做读命中 LRU 移动、last_access 更新或其他热路径写入。
- 让全局 DNS cache 持有 `io_context`、socket、协程 waiter、Worker-local allocator / buffer provider 或请求生命周期对象。
- 用锁或 atomic 共享当前 Worker 的 DNS L1 cache、inflight resolve 表或 socket。

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
- inbound validator 只做协议认证、用户查找和 Worker-local 在线设备追踪；公开用户更新接口必须统一为 `ApplyUsers` / `AddUsers` / `RemoveUsers` / `ClearUsers`。
- 在线设备、连接数和限设备检查属于 Worker-local tracker，不进入全局 `UserStore`，也不能跨 Worker 直接共享。

## 配置与热更新

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
- 协议不能拥有独立请求链路，所有协议必须进入 `inbound.Process -> dispatcher.Dispatch -> outbound.Process -> relay`。
- UDP / Mux helper 不能成为协议私有请求链路；datagram 资源必须归属当前 Worker，路由和出站选择仍由 dispatcher / outbound 负责。

## 开发规范

- 优先沿用现有目录职责、命名风格、协程模型、RAII 和错误处理方式。
- 公共头保持窄接口，避免暴露协议私有 helper、运行态存储、完整配置对象或跨层依赖。
- 协议私有 reader、writer、codec、crypto helper 留在 `src/proxy/<protocol>` 内部。
- 冷路径可以做 JSON 解析、字段兼容和对象构建；热路径避免 JSON 解析、panel 字段判断、重复分配、重复拷贝和不必要锁。
- Buffer / MultiBuffer 必须保持清晰所有权，move 后即视为转移，消费结束后及时归还或释放。
- 新增行为要同步考虑静态配置、面板配置、热更新、TCP、UDP、Mux/子流和源进源出语义。

## 开发约束

- Worker 不直接访问协议 validator、panel 字段或具体 outbound 实现。
- Dispatcher 不 include 具体协议，不绕过 router/outbound/relay。
- Dispatcher 只接收窄 `DispatchPolicy`，不接收 `ReceiverSettings`，不依赖具体面板规则 manager。
- Router 只返回真实规则命中，不持有 forced / fallback / default，不创建连接，不访问 outbound manager 或 relay。
- RequestPolicy 只返回准入结果，不选择路由或 outbound。
- Relay 只搬运数据，不解析协议，不理解面板。
- Panel/client/controller 不进入热路径，不修改 live handler 内部状态。
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
22. Router 保存或选择 forced outbound、入站 fallback、Worker 默认 outbound。
23. Dispatcher 依赖具体 `rule::Manager`、`DetectRule` 或面板策略类型，而不是通用 `RequestPolicy`。
24. Mux / AnyTLS 子流为重新进入 Dispatcher 而保存完整 receiver，而不是窄 `DispatchPolicy`。

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
13. Router 的无匹配结果为空，fallback/default 只能在 Dispatcher 中解析。
14. 面板 DetectRule 通过 RequestPolicy 抽象接入，不污染 Router 或 Dispatcher 类型边界。

## 部署约束

- 部署脚本 `scripts/cnode.sh` 不带参数时只更新二进制。
- `scripts/cnode.sh -debug_file true` 可额外下载对应的 `.debug` 符号文件。
- VPS 或线上环境优先拉取发布产物进行诊断，不默认在目标机上临时编译。
