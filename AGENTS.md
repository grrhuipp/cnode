# AGENTS

本文件只记录修改 cnode 时必须遵守的稳定红线。实现细节、迁移历史和逐类型防回归清单由代码与单元测试维护，不在这里逐轮追加。

- `README.md` 面向使用者，说明定位、配置入口、部署和架构概览。
- `AGENTS.md` 面向贡献者和自动化协作者，说明职责边界、禁止项和硬性删除规则。
- 两份文档都提到同一架构边界时，以本文件为准。不要在两个文件中重复同一内部实现。

## 沟通

- 默认中文回复。
- 不要回退、覆盖或整理用户已有改动，除非用户明确要求。
- 需求不清时只问一个必要问题；能从仓库上下文判断时直接执行。
- 变更前先分析现有代码和配置，再决定是否修改。
- 需要诊断或回归时，优先在当前可用的目标环境完成；无法直连时先说明限制，再给出可在本地完成的分析。
- 默认选择长期正确、边界清晰的一等抽象，即使改动面更大；不要为了缩小 diff 把新能力塞进语义不匹配的旧接口或旁路。

## 项目不变量

cnode 是 C++23 代理节点服务端。

- 所有 TCP / UDP 请求只能走唯一热路径：`Inbound Handler::Process -> Dispatcher::Dispatch -> Outbound Handler::Process -> Relay`。任意协议都只是 Handler 实现，不拥有独立架构。
- 原生 datagram、UDP-over-TCP 和 Mux/子流可以有窄 helper（`DispatchUDP`、`DialUDP`、UDP framer），但只能服务主链路：inbound 生成 metadata，dispatcher 路由，outbound 准备 Worker-local 出站资源，relay 搬运数据。helper 不得承载协议私有架构、路由选择、panel 字段或第二条请求链路。
- 控制面负责面板同步、配置归一化和运行时快照发布；热路径只读取不可变 snapshot。
- 任意配置来源都必须先归一化，再进入 runtime。热更新只能原子替换 snapshot，不能原地改写运行中的对象图。
- 默认主配置是 `config.json`，目录侧车固定为 `inbounds.json`、`outbounds.json`、`routing.json`。不回退 YAML 入口，不读取旧 sidecar path，legacy 字段不得进入 runtime。配置键只认 Xray camelCase；snake_case 别名直接拒绝。
- proxyman receiver 在冷路径构建完整监听语义；进入 Dispatcher 时只能传不可变的窄 `DispatchPolicy`。
- Router 只返回真实规则命中。强制出口和入站显式 fallback 由 Dispatcher 编排。不存在 Worker 全局默认出口。
- 每个 receiver 必须在冷路径明确构造 `ForceOutbound` 或 `RouteWithFallback`；策略不可默认构造，空 tag 不得进入热路径。
- 集中结构化日志的待发送批次只能驻留在有界进程内存；禁止磁盘 `access-spool` / `error-spool`。

## 分层与零成本

仓库分层必须一眼可见，上层不得下沉，下层不得理解上层产品语义：

```text
control    service/controller, api/*
runtime    app/worker, dispatcher, proxyman, relay, dns
protocol   proxy/<protocol> 只作为 Handler::Process
transport  TCP / TLS / WebSocket / PROXY / dialer
memory     当前线程的 std::pmr，直接 allocate/deallocate，不设 pool
```

- 热路径目标是 0 抽象成本：启动期可以用注册表、工厂和一次虚函数绑定。
- 请求期不得新增 mutex、rwlock、spinlock、共享原子争用、`std::function` 链、多余 `shared_ptr` 分配或 type-erasure 旁路。
- 协议边界只允许一次虚调用：`Inbound::Process` / `Outbound::Process`。协议内部是私有实现，不得再套 wrapper、adapter 或第二条请求链路。
- 公开配置用可 designated-initialize 的普通聚合；能用字段表达的不要加 factory / builder。

## 内存

- 禁止自建 size-class free-list、Buffer 回收桶、`unsynchronized_pool_resource` 或其他 pool。
- 每个 Worker 线程持有自己的 `memory_resource`，只做 `::operator new` / `delete`，不缓存空闲块。生产可由 mimalloc 接管 global new。
- `std::pmr::set_default_resource` 只是转发到当前线程资源的门面，不是跨 Worker 共享池。
- 拥有型 `string` / `vector` / map / `Buffer` 一律经当前线程 PMR 分配和释放。`string_view` / `span` 只表示借用。
- `Buffer` 是固定 8KB 数据块；`New`/`Free` 直接走当前线程 PMR。
- 分配器必须活到最后一个使用它的对象析构；PMR 容器、allocator 和 `memory_resource` 都不得跨 Worker 移动或共享。

## 层级边界

| 层级 | 负责 | 不负责 |
| --- | --- | --- |
| inbound | 认证、协议解析、用户识别、目标解析、session metadata、调用 `dispatcher.Dispatch` | 路由、出站连接、relay、访问 outbound manager 内部、协议私有长期大 buffer |
| dispatcher | 只读 `DispatchPolicy`；编排 forced outbound 或 `Router 命中 -> 显式 inbound fallback`；通用 `RequestPolicy`；查找并调用 outbound | 解析协议、协议特判、执行 relay、panel 字段、`ReceiverSettings`、具体 `rule::Manager` / `DetectRule`、伪装 Router 命中、隐式默认出口 |
| router | 只在规则真实命中时给出 outbound tag | 连接、relay、协议、proxyman 类型、forced / fallback / 隐式默认出口 |
| request policy | 统一 session 上返回 allow / block；Worker-local 实现可记录命中 | 选路、查找 outbound、解析协议、向 Dispatcher 暴露面板规则类型 |
| outbound | 拨号或下一跳、出站握手和编码、交给 relay | 路由、读取 panel 原始配置、绕过 dispatcher |
| relay | TCP / UDP / Mux 搬运和流量打点 | 解析协议、选 outbound、访问 panel、连接级大 scratch、wrapper API |
| Worker | 事件循环、accept、capability owner、thread-local allocator | 协议 validator、具体 outbound 类型、路由决策、panel 同步 |
| proxyman | 构建并按 tag 持有 prepared handler；receiver 内嵌不可变 `DispatchPolicy` | 解析协议或 panel 字段、自己做路由、直接进入 relay、暴露跨 Worker 可变 handler |
| transport | TCP / TLS / WebSocket / PROXY / dialer | 代理协议解析、选 outbound、panel 配置、协议私有长期 pool |
| control plane | 拉节点/用户/规则、归一化、构建 runtime、原子发布、按面板语义上报 | 进入热路径、改 live handler、访问 Worker buffer provider、按协议构建认证凭据 |

未启用 routing 的静态 inbound 使用 `ForceOutbound(direct)`，即使规则可命中也不得进入 Router。

## Worker 同构与共享边界

每个 Worker 全部相同：同一份 runtime 配置、同一组监听端口、同一套 inbound / outbound / router 契约。没有 leader Worker，listener 数量不得乘增 Worker 或数据资源。

每个 Worker 独立拥有：

- standalone `io_context` 和 `SO_REUSEPORT` acceptor / UDP socket
- inbound / outbound manager 与 handler
- Router、Dispatcher、RequestPolicy 实现
- DNS service、L1 cache、inflight、UDPSession
- 在线设备、连接跟踪、用户流量计数、限速与连接限制
- Worker-local `std::pmr` 资源

连接由接受它的 Worker 终身拥有，不跨线程迁移。Worker 的 live 能力由 `RuntimeState` 统一构造、启动、暴露和关闭，不得散落成相互独立的生命周期字段。这些实例不得跨 Worker 共享。

进程级只允许共享启动后只读的计划或快照，以及明确的有界冷路径对象：

- `UserStore` 认证用户 RCU 快照
- `GlobalDnsCache` L2 不可变分片快照
- `GeoManager` 启动加载后的只读 geo 数据
- 分片统计容器中属于该 Worker 的那一片
- 访问日志 reporter 的有界内存队列（事件按值拷贝，不持有 Worker 指针）
- 控制面 `Controller` 所在的独立 `io_context`

不允许：

- 跨线程或跨 Worker 直接读写 Worker 私有对象，即使看起来无锁或只有 atomic
- 把 handler、manager、listener、`AsyncStream`、`UDPSession`、allocator / buffer provider 的裸指针或引用保存到其他 Worker
- 把 DNS service、L1 cache、inflight、UDP socket 或 timeout scheduler 做成跨 Worker 可变对象
- 在全局 DNS snapshot 上做 LRU 写或热路径 last_access 更新
- 为跨线程访问热路径状态临时加锁
- 用无界 `net::post` 或裸 `co_spawn` 作为进入 Worker 的控制面入口

跨线程只能：

- 经 Worker 有界 mailbox 投递；满则拒绝，不得无界排队
- 投递的 callable 必须自己拥有状态；禁止先调用临时 lambda，再投递依赖已销毁闭包的 awaitable
- 复制或发布不可变 snapshot
- 冷路径同步

控制面批量操作必须等待已启动的子任务全部结束。面板同步和 60 秒状态心跳必须使用独立循环；状态循环只读最后提交的节点状态，失败单独报告。进入 `RunApplicationRuntime` 后 Worker 存活至进程退出。Worker 与 `io_context` 集合由 bootstrap 冷路径确定，运行时不能增删成员。

## 请求链路契约

- Dispatcher 只依赖 `routing::Router` 只读契约；具体 Router 在所属 Worker 冷路径一次构建完整、持有不可变规则，不公开原地更新入口。
- Dispatcher 公开热路径只暴露 `Dispatch`，不 include 具体协议，不接收 `ReceiverSettings`，不依赖面板规则 manager。
- 首包统一为拥有所有权的 `MultiBuffer`，按值移交 outbound，作为普通上行的第一份数据。
- 实际读端的取消必须覆盖嗅探、路由 DNS、出站拨号/握手和 relay。
- 出站凭据在协议准备回调中完整验证并构造；Worker-local handler 只消费已准备的不可变值。
- 协议用户构建只能位于 `proxy/<protocol>` 的 `build_users` / `build_static_users`。
- 协议私有 reader / writer / codec / crypto 留在 `src/proxy/<protocol>`，不能成为公开请求链路对象。
- 公共 helper 必须有当前生产或测试调用；删除入口时同步删除只为它服务的实现、状态和 include。

## 用户与 DNS 快照

用户链路：

```text
api/* UserInfo
  -> controller RuntimeUser
  -> proxy/<protocol> build_users
  -> UserSet
  -> UserStore RCU snapshot
  -> inbound validator 只读认证
```

`UserStore` 是进程级只读快照，按 `protocol + tag` 发布。在线设备、连接数和限设备是 Worker-local tracker。启动入站全部准备成功后，bootstrap 一次批量 `ApplyUsers`；分配失败保留原快照。

DNS 是 Worker-local service + 进程级 L2 只读结果快照。上游配置在冷路径归一化为完整 UDP endpoint。缓存写入是可选优化，失败不能丢失已取得的解析结果。

## 控制面

- 面板资源标签使用保留的 `panel/` 前缀，且必须包含面板名称和节点 ID。
- 端点准入在控制面 executor 完成；不能靠各 Worker 竞争 `SO_REUSEPORT` 决定节点所有权。
- 同 Worker 内 TCP/UDP 监听检查其他 tag 占用；通配与具体地址重叠，IPv6 固定 v6-only。
- 候选只读快照和回滚凭据必须在运行变更前构建完成；未完成清理不得开始新变更。
- 面板 HTTP 地址回退只允许发生在连接和 TLS 握手阶段；开始发送后不得换地址重发。
- 禁止在 controller / panel client / dispatcher / router / relay / Worker 中按协议构建认证凭据。
- 禁止绕过 `RuntimeUser -> UserSet -> UserStore` 增加第二套用户表。

## 硬性删除规则

发现以下情况时，不做兼容，不做转接，直接删除、合并或下沉：

1. 公开 wrapper / compat 层。
2. 协议 stream 对象作为请求链路一部分。
3. Worker 直接调用协议 validator。
4. Dispatcher include 具体协议，或接收 `ReceiverSettings` / 面板策略类型。
5. Router 调用 relay，或保存 forced / fallback / 隐式默认出口。
6. Relay 解析协议。
7. Panel 修改 live handler，或出站读取面板原始字段。
8. 热路径解析 JSON。
9. 连接对象常驻大 scratch、自建 size-class / Buffer 回收池，或协议私有长期 pool。
10. manager 同时承担多个层级职责。
11. legacy 配置字段进入 runtime。
12. 跨线程或跨 Worker 直接访问 Worker-local 无锁对象。
13. Worker-local 裸指针、引用、allocator、handler、manager、`UDPSession` 或 `AsyncStream` 逃逸到其他 Worker。
14. 用 lock-free / atomic 共享 live handler、manager、连接或 buffer pool 来绕过 Worker 所有权。
15. controller 按协议构建认证凭据，或面板用户绕过 `UserStore`。
16. DNS service / inflight / socket / timeout scheduler / L1 cache 跨 Worker 共享。
17. Mux / 子流为重入 Dispatcher 保存完整 receiver，而不是窄 `DispatchPolicy`。
18. receiver 出口策略可默认构造、接受空 tag，或回退到第一个 outbound。
19. 跨线程用无界 `net::post` / 裸 `co_spawn` 进入 Worker。
20. Worker live 能力散落成相互独立的生命周期，而不是 `RuntimeState` 统一持有。

## 审查清单

1. 从请求入口到 relay 的数据流一眼可见。
2. 任意协议都只是 Handler 实现。
3. 任意配置来源都先归一化，再进入 runtime。
4. 每个 Worker 同构；live 状态不共享；进程级共享仅限只读快照、有界日志队列和控制面。
5. 任意热路径对象都能指出所属 Worker。
6. 删除一个协议不影响 dispatcher / router / relay / worker 结构。
7. 替换一个 panel 不影响协议热路径。
8. Dispatcher 公开热路径只有 `Dispatch`，没有 proxyman receiver 或面板策略类型。
9. Router 无匹配结果为空；系统不存在隐式全局默认出口。
10. 公共头不存在全仓无调用的 helper；仓库结构表达最终职责，而不是迁移历史。
11. 热路径没有额外 wrapper / `std::function` / 共享锁；协议只有 `Process` 这一层抽象。
12. Worker 内存是 PMR，没有第二套自建 pool。

## 部署

- `scripts/cnode.sh` 不带参数时更新二进制及 `geoip.dat`、`geosite.dat`；geodata 先下载到临时目录，失败保留旧文件，内容变化后重启原服务。更新模式不得改写既有 panel 或 sidecar 配置。
- `scripts/cnode.sh -debug_file true` 可额外下载 `.debug` 符号文件。
- VPS 或线上环境优先拉取发布产物诊断，不默认在目标机临时编译。
