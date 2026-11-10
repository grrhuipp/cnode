# 持续架构审查记录

目标：持续审查并重构，明确职责边界与抽象层次；每轮验证后继续，直到用户要求停止。本记录是阶段检查点，不表示全项目审查完成。

## 2026-11-05 会话域分配与原生完成边界

- `memory::AllocationDomain` 是不可移动的执行租约根；`ScopedAllocationDomain` 在每个 callback 及其销毁期间取得独占租约并恢复上一域。连接域只拥有 24 字节根和 72 字节轻量路由资源，不含尺寸类表、slab、large-bin、空闲队列或 reclaimer。
- 完整多级 PMR 池只存在于 Worker。域分配经轻量资源进入当前 Worker 池，同一 Worker 的连接按尺寸类共用 slab；每个 live slot 同时记录连接域和来源 Worker chunk，因组迁移在异 Worker 释放时进入来源池的侵入式 remote-free 队列，并由来源 Worker drain，不跨线程修改池元数据。
- `ThreadLocalAllocator` / `RingDeque` 只弱引用已空的轻量域；只要容器仍有 live block，块本身保持域资源寿命。空容器跨到同组新域后若再次分配，会先绑定当前域，不会让已退役物理连接常驻。阶段级 `request_memory` 是借用域资源的 monotonic arena，只用于握手、认证、探测、路由和建连临时值，不承载长连接持续流量。
- 容器移动/交换转移块所有权。Buffer 访问、域分配/释放及 request arena 的内联分配均检查租约；无租约或未合并异域访问立即拒绝。已合并子域仅在共同 Group 独占执行时互借。迁移后的新分配使用当前 Worker，旧块仍归还来源 Worker。
- Asio native operation 内存使用 `ProcessAllocator`，允许原 reactor 交付或销毁完成；它不接触连接域或 Worker slab。UDP 接收和发送均由 reactor 等待 readiness，再由当前 owner 执行非阻塞 payload 系统调用；重等不重置整次操作预算，空 payload 仍发送实际零长 datagram。
- `TimeoutScheduler::ForIoContext` 在会话内选 `ExecutionDomain::Services()`，域外保留 Worker 服务与缓存；定时器完成绑定当前域 executor，定时器操作内存使用 process resource。Scheduler 仅弱持 domain，避免 service/executor 自循环；能力对象收束任务后调用 `AsyncReleaseForIoContext`，取消事件并等到唯一 native timer 完成交付，不能用一次 post 代替 join。每连接任务组保留 `Impl` 内嵌 owner 和独立取消/join 语义，但无子任务时只保存 executor，首次 `Spawn` 才构造 join 状态与自持有组；已启动子任务的小对象仍由 Worker slab 跨连接紧凑装填。

- 验证：全量并行构建与 CTest 178/178 通过。单 Worker、真实 VLESS TCP 持有 2000 条活跃连接 10.5 秒，RSS 从旧版 187248 KiB 降至 94740 KiB，`pool_mapped` 从 85 MB 降至 9 MB；持有窗口 RSS 仅增加 120 KiB，关闭后回落至 19692 KiB。1000 个连接域跨 13 个尺寸类的定向回归中，live stride 4544000 字节、mapped 5033984 字节，未再出现每域每尺寸类至少占一页。
- 后续反碎片验证保留 64 KiB Worker slab 上限和 64 字节最小槽：16/32 KiB slab 将 2000 连接下的 chunk 数从 226 分别增加到 673/462，32 字节最小槽的重复测试只有噪声量级收益且增加尺寸类和 chunk，因此均未采用。惰性驻留任务组在三轮交错测试中将 2000 条活跃连接的最终 RSS 中位数从 94516 KiB 降至 93828 KiB，扣除各轮基线后的连接增量中位数从 81708 KiB 降至 80788 KiB，约减少 471 字节/连接；Worker chunk 从 221 降至 207。


## 工作区与验证环境

- 基线：`804d7e7`。
- 独立 worktree：`D:\cnode-wt-architecture-20260909`。
- 分支：`codex/architecture-review-20260909`。
- 原工作区 `D:\cnode` 的现有 `.codex/` 未改动。
- 本地 Windows、MSVC 19.44、C++23、Release，开启测试，关闭 LTO。
- 依赖源码使用原工作区已下载的 FetchContent 源码，构建产物位于本 worktree 的 `build/`。
- 后续配置固定本地 `BUILD_ID=20260909T131458Z`，避免仅因 CMake 重配置时间变化而重编整个主程序。
- 第五十九轮结束后按用户指令提交并推送累计重构到当前架构分支；本记录中的各轮“未提交、推送”描述对应当轮验证时点。没有执行部署。

## 已验证轮次

| 轮次 | 问题与改动 | 验证 |
| --- | --- | --- |
| 1 | Dispatcher 直接依赖具体 Router，Router 暴露原地 `Configure`。引入只读 `routing::Router` 契约，将 domain strategy 与规则结果归入契约；具体 Router 在所属 Worker 冷路径构造不可变实现，删除默认构造与原地配置入口。合并重复路由结果类型，删除无意义的空 tag 补救，并移除会导致路由分配异常终止进程的 `noexcept`。 | 全量 Release 构建成功；CTest 80/80。新增真实 Router 测试，覆盖规则优先级、TCP/UDP、IPv6、无匹配、配置所有权和构建失败。 |
| 2 | 嗅探拼接缓冲随转发协程保留至连接结束。将其限制在嗅探作用域，完成后释放；移除 Dispatcher 公共头对完整配置、统计实现和具体流头的冗余依赖。 | 全量增量 Release 构建成功；CTest 80/80。 |
| 3 | GeoManager 的字符串 tag 匹配入口无调用者。删除两个旧入口及对应 loader 匹配、枚举和状态查询辅助方法；删除无调用的 GeoManager 移动接口与 Router 私有清空声明。补充架构契约约束。 | 主程序、Router 测试重建成功；CTest 80/80。 |
| 4 | DNS 实际仅发布单个解析结果，却经过公开批量更新载体、中间拷贝和 256 个分组容器。合并为直接发布目标分片，删除批量接口、载体及无读取的分片 generation 字段，保留不可变快照与 CAS 合并。 | 主程序和新增全局 DNS 缓存测试构建成功；CTest 81/81。覆盖结果所有权、正负缓存、忽略临时错误、容量、过期、禁用与同分片并发发布。 |
| 5 | Worker 私有 L1 缓存沿用 256 分片、手工计数和先淘汰后分配，分配失败会丢失旧答案。合并为单个有界缓存，节点拥有域名、索引借用节点；先构建再淘汰，失败回滚。统一正负结果写入，L2 回填保留剩余 TTL，修正负缓存 TTL 回传。 | 主程序与新增 L1 缓存测试构建成功；CTest 82/82。故障注入先复现旧项丢失，再验证正负插入、替换、恢复、容量、过期和回填 TTL。 |
| 6 | inflight 表保存协程栈上等待者的裸指针，并在缓存写入及逐等待者结果复制后才通知。迁移到 Worker 私有 `InflightResolves`：共享待完成结果和 channel 完成信号，作用域清理移除表项并通知全部订阅者，独立处理取消和结果复制失败；缓存分配失败保留已解析答案。 | 全量 Release 构建成功；CTest 83/83。覆盖同域合并、发起者异常、结果复制分配失败、订阅者取消、表项清理后重查，以及实际 DNS 服务在 L1 回填失败后继续返回 L2 答案。 |
| 7 | `ContiguousBufferView` 自有缓冲与 span 被隐式复制后可能指向不同对象。禁止复制及隐式移动，明确局部视图和借用源缓冲的寿命要求；现有调用无需迁移。 | 主程序及 VMess、Shadowsocks datagram 测试重建成功；CTest 83/83。 |
| 8 | allocator 的 `ThreadScope`、`MarkThreadPoolThread` 已为空实现，仍暗示存在作用域切换。删除定义、全部调用和旧注释。同时将监控堆回收协程的 `force` 从临时闭包捕获改为值参数，避免 awaitable 借用已销毁闭包。 | Windows Release 全量构建成功；CTest 83/83；源码无旧 API 引用。glibc 回收路径已核对调用，但未在 Linux 环境执行。 |
| 9 | 批量任务使用 detached 子任务和可取消完成定时器，取消可让父协程先于子任务返回。改为在指定 executor 内持有批量完成回调，启动前准备通知、启动哨兵阻止提前完成、销毁未启动帧后再释放哨兵；独立协程隔离取消，全部结束后向调用者报告取消。删除完成定时器和逐任务转接协程。 | Release 主程序与批量测试重建成功；CTest 83/83。显式等待门先复现取消提前返回；新增取消后等待、启动分配故障逐点注入（包含部分启动）、单任务跨 executor/线程恢复回归。测试禁用协程帧回收以确保注入覆盖，隔离测试等待门自身的初始化分配；Asio 在进入批量实现前的初始化错误只允许发生在没有子任务启动时。旧变量名匹配检查由行为测试替代。 |
| 10 | `RuntimeMonitor::Stop` 无生产或行为测试调用，取消注册、完成定时器和 running 状态只服务该入口。完整移除这组设计，监控公共头仅前置声明 RuntimeContext；启动失败恢复 active 标志，保留协程持有 Impl 的所有权。 | Release 主程序重建成功；CTest 83/83。更新监控边界契约，立即信号退出契约保持通过。 |
| 11 | 两个常驻监控循环共用有限批量任务入口，单个循环失败会等待另一循环结束才报告。改为 app 私有 MonitorLoop：每个循环独立持有工厂上下文、active 状态和退出回调；按循环名立即报告失败或退出。RuntimeMonitor 的 Impl 改为唯一所有权，活动循环由各自的 co_spawn 持有。日志 flush 时间由静态变量改为循环局部状态。 | Release 主程序与新增 monitor_loop 测试构建成功；CTest 84/84。验证一个失败、另一个仍挂起时及时报告，重复启动不重复执行，失败后可再次启动，工厂抛出保留错误，以及 facade 释放后上下文存活至任务结束。 |
| 12 | RuntimeContext 暴露无读者的 work_guards 引用；内存查询用空协程包装同步系统调用，并读取未使用的虚拟内存字段。删除上下文中的引用与多余头依赖，work guard 继续由 WorkerPool 持有；收窄为同步读取 RSS 字节数。 | Release 主程序构建成功；CTest 84/84。本地独立进程烟测运行 6.5 秒，使用临时 loopback 入站并禁用上传，确认持续运行、监控日志已落盘且内存值有效；测试进程已结束。 |
| 13 | 启动失败关闭监听后只 post 一次便销毁 Worker，不能证明挂起连接、子流与 UDP 回调已经结束；线程创建和事件循环异常也缺少统一运行期边界。统一为进程生命周期：运行期成功信号立即退出，失败先同步输出阶段和原因，再以失败码退出，持有者留在异常处理作用域之外。入站 future 改为 void，以异常携带 Worker、tag、端口和阶段；删除两层启动回滚、Worker::ShutdownTask、ListenerState::Shutdown 及 UDPSessionManager::StopAll，析构直接完成原有清理。合并重复的进程测试程序，并更新公共入口契约。 | 全量 Release 构建成功；CTest 84/84（26.30 秒）。实际进程覆盖两 Worker、首个入站成功后第二个端口冲突，经 future 异常进入失败出口并返回 1，诊断包含具体入站；挂起面板请求时信号退出仍返回 0。旧程序验证只确认进入原回滚路径，未复现内存崩溃。主/Worker 事件循环异常和线程创建失败分支经源码审查，尚未单独故障注入；Linux 进程测试未执行。 |
| 14 | 控制面、入站启动和监控仅遍历 Worker，却借用可修改成员的容器。统一改为只读 Worker 集合引用，RuntimeContext 的 io_context 集合也只读；集合成员仍由 bootstrap 冷路径构造。RuntimeContext 公共头将 InboundStartup 改为前置声明，完整入站配置仅在实现中包含。 | 全量 Release 构建成功；CTest 84/84（26.34 秒）。全仓确认不再存在可写 Worker 集合引用；Worker Task 投递与运行时快照访问方式保持原有语义。 |
| 15 | Controller 的 Stop 仅被源码契约要求，没有实际调用；常驻面板循环使用有限批量入口，单个退出被其他循环延迟。将私有 MonitorLoop 移至 src/common，由运行时与面板复用；每个面板独立持有 Controller 上下文，Controller 仅存弱引用，退出立即记录面板和节点并标记 unavailable。完整删除 Stop、generation、完成定时器、取消注册表、API::CancelPending 及 V2Board socket 注册/epoch，移除重复 panel_nodes 集合；有限 Worker 聚合继续使用批量入口。 | 全量 Release 构建成功；CTest 84/84（26.40 秒）。新增弱引用所有权行为测试，验证任务排队后外层释放仍保留上下文、单个失败独立报告、最后退出后无循环持有；既有重复启动、失败重启、工厂异常测试以及真实进程启动失败/挂起面板信号退出回归通过。面板同步、报告和固定 60 秒状态日志调度契约通过；尚未对真实 Controller 注入单面板循环致命异常。 |
| 16 | V2Board HTTP/HTTPS 候选地址的 catch 同时覆盖连接、请求写入和响应读取，已发送的 POST 在 Content-Length 响应截断后会被重发到下一地址。将候选回退限制为 TCP 连接与 TLS 握手；开始发送 HTTP 后的错误直接结束本次请求。新增真实 cnode + loopback DNS/双 HTTP 端点回归，并复用现有进程测试程序。 | 全量 Release 构建成功；CTest 86/86（37.61 秒），无跳过。Python 探针和原生测试均在修复前复现同次空流量 POST 被两个地址收到，原生正向连接回退测试原本通过；修复后响应截断只收到一次 POST 且报告失败，首地址连接拒绝仍经第二地址成功。实际网络回归覆盖 Windows HTTP；HTTPS 对应边界完成源码检查和编译，未做 TLS 端到端故障注入。Unix 上若无法绑定 DNS 53 端口，新增网络测试明确以 77 跳过。 |
| 17 | 面板 HTTP 请求缺少统一时间上限，等待响应和 TLS 关闭握手可长期占住同步循环。新增冷路径归一化的 RequestTimeout（默认 30 秒，整数 1–3600），将请求策略与网络交换分开；Asio cancel_after 取消并等待交换协程结束，保持调用者取消与请求超时的区别，保留已完整收到的响应。TLS 关闭握手另受 1 秒及剩余总时间限制。 | 全量 Release 构建成功；CTest 88/88，41.31 秒。真实挂起 POST 回归先在旧代码失败（只能由停止进程关闭），修复后按配置超时主动关闭，保持仅一次 POST；地址回退及响应截断回归继续通过。新增请求任务测试覆盖提前成功/失败后清理定时器、异常和值形式的取消、调用者取消传播、返回前资源释放以及有效响应保留；实际启动入口拒绝 8 种错误超时配置。 |
| 18 | 固定状态日志与面板网络请求共用调度循环，挂起 POST 会阻塞 60 秒心跳。拆成 panelSyncLoop 与只读 panelStatusLoop，分别保存弱引用并持有自身上下文、独立报告退出。状态循环按稳态时钟输出最后提交状态，跳过错过的周期；同步循环保持单次拉取、pull/push 间隔和首次延后推送。删除同步循环中的状态定时器与独立启动状态格式。 | 全量 Release 构建成功；CTest 89/89，103.28 秒。真实 120 秒请求时限下挂起 POST，旧代码在 62 秒内只有两条启动日志而失败；修复后同一 POST 仍在等待时观察到两条间隔正好 60 秒的状态日志，随后信号退出。超时关闭、POST 不重发、连接地址回退及监控所有权回归继续通过。 |
| 19 | 客户端、配置、连接状态、节点快照和统计分散在四张关联 map，且重复保存用户计数。迁移为地址稳定的 PanelRuntime：客户端及配置只读，单节点实体完整构造后发布，直接持有状态、快照、统计与循环弱引用。用户数改读已提交用户快照，最终快照移动提交增加不抛异常的编译约束。删除 API::Describe、ClientInfo 及全部转接，删除可空配置、重复名称回退、InboundBuilder 的额外名称参数和 OutboundBuilder/addOutbound 的无效节点配置参数链；TLS 策略统一要求明确配置。 | 全量 Release 构建成功；CTest 90/90，169.42 秒。新增原生生命周期回归：拉取失败保留监听、正常刷新、404 删除、默认 60 秒后恢复；最终覆盖同面板下两个节点，确认伴随节点持续可连接。独立心跳、请求超时、POST 不重发、地址回退、TLS 策略与提交顺序契约均通过。 |
| 20 | 旧提交记录中的 inbound_started 只写 true，回滚失败无法使运行态失效；失败候选的清理信息也会丢失。拆分 NodeRuntime 具体 Worker 操作与私有节点事务，网络同步只准备数据和调用事务。提交数据改为共享不可变 NodeSnapshot，健康单列 Stopped/Ready/Updating/RecoveryRequired；变更前准备完整候选及回滚凭据。失败时保留至多旧、候选两个清理目标，下一轮在面板网络请求前先清理，再完整重建；健康未恢复时暂停推送。删除旧控制器变更/回滚分支及可变快照启动标志。 | 全量 Release 构建成功；CTest 91/91，169.44 秒。生产事务的操作层故障注入覆盖 8 个变更阶段前后抛出异常、入站/出站返回失败、刷新补偿失败、回滚再次失败、遗留候选、清理失败阻止新变更、部分移除和取消后恢复。临时撤销失效保护时测试失败，恢复后通过；真实 Windows 心跳、HTTP 请求和双节点生命周期回归继续通过。 |
| 21 | 同一面板不同节点因标签缺少节点 ID，实际运行时会替换同名 handler 并共用监听。面板标签迁移为 panel/{Name}/{NodeID}/{protocol}/{port}，静态入站主 tag 与静态出站禁止保留前缀。控制面利用现有节点事务快照，在首次挂起前检查并保留旧/候选端点；Worker 分别检查 TCP/UDP 其他 tag 的占用。InboundListen 统一精确、通配、双栈地址重叠语义，静态配置同步校验。 | 全量 Release 构建成功；CTest 94/94，169.76 秒。真实进程基线复现两个节点同标签且都 ready；修复后顺序冲突、两 Worker 并发冲突、静态通配监听与面板冲突均拒绝第二个所有者并保留原监听。事务测试覆盖首次挂起前保留、取消后保留与清理后释放；配置测试覆盖保留命名空间与通配重叠。 |
| 22 | 测试模式在静态校验后独立构建 runtime 并发布用户，同名入站被错误替换，端点冲突延迟到 Worker 启动后失败。将测试模式归一化为普通 StaticInboundConfig，完整集合先校验、再经同一协议注册入口准备；准备阶段不改写 UserStore/Worker，bootstrap 一次批量发布用户快照。删除 BuildTestModeInbound、旧公开构建入口、无调用的启动 tags 列表及测试专用启动参数。 | 全量 Release 构建成功；CTest 100/100，170.01 秒。真实旧程序复现同 tag 两次 ready；新回归覆盖同名和端点冲突在 Worker 创建前失败，以及显式共存与隐式测试模式成功。准备行为测试验证统一入口和无用户发布副作用；用户快照经过 32 个真实分配失败点均保持旧值。逐 tag 发布的变异实现在第 21 个分配边界被测试捕获，恢复后全量通过。 |
| 23 | StreamSettings 的 noexcept 原地归一化会在 ALPN 分配失败时 terminate；多个协议在配置注册、prepared creator 和 handler 构造中重复归一化。将传输查询和归一化移出 JSON 解析实现，删除 RecomputeModes，改为返回独立值的 NormalizeStreamSettings/NormalizeOutboundStreamSettings。所有出站在协议冷路径准备回调中归一化，移除 Worker 构造及 Freedom 默认值的重复处理；AnyTLS 归一化移到 creator 捕获之前。 | 全量 Release 构建成功；CTest 101/101，169.86 秒。独立生产实现基线捕获 terminate；新测试覆盖网络/安全模式别名、ALPN、TLS 默认值、幂等性、查询和 noexcept move 提交。通用与出站各 11 个分配故障点均保持源配置及调用者原值。架构契约检查归一化只在协议冷路径准备执行。 |
| 24 | VMess 无效 UUID 在 Worker 构造中只记录错误，Shadowsocks 未知方法静默回退、SS2022 身份链跳过坏片段；六种错误配置的旧二进制均启动。VMess 冷路径构造完整 MemoryAccount，删除运行态可空账户及重复 UUID 字段。Shadowsocks 以协议私有 Credentials 完整准备方法和密钥链，拒绝未知或显式无效方法、错误密钥、空链节及不受支持的 ChaCha 身份链；删除构造期派生、回退、链片段过滤和重复传输配置。两者的目标字面地址也在注册准备回调中解析。 | 全量 Release 构建成功；CTest 102/102，178.21 秒。密钥单测验证四种普通方法/别名及三种 SS2022 方法的字节、长度、顺序、复制所有权和错误拒绝。真实配置回归新增扁平与嵌套格式共 16 个拒绝及 8 个启动检查，有效配置使用两个 Worker。架构契约禁止 handler 再构造凭据或解析目标字面地址。 |
| 25 | VLESS 在 Worker 构造中重复解析 UUID、flow 和 encryption，并把 Vision 的固定传输限制留到拨号成功后检查。改为协议准备回调一次解析及校验，只读 encryption 配置可共享，连接票据仍逐 Worker 构造；删除 config_valid_ 和原始重复字段。Trojan、AnyTLS 将固定认证摘要移到协议私有 credentials 模块，删除运行态原始密码、codec 内哈希及 validator 的冷路径转换。Trojan 编码仅接受固定 56 字节摘要；VLESS 标准 UUID 和 1–30 字节自定义 ID 保持同一转换。AnyTLS 配置只读，移除重复字段和可空 DNS 状态。 | 全量 Release 构建成功；CTest 104/104，186.36 秒。旧 Trojan 编码器在禁止 C++ new 分配时抛出 bad_alloc；新测试覆盖 SHA224 向量、TCP/UDP 的 IPv4/IPv6/域名报文字节、短缓冲区不改写和无分配编码。AnyTLS SHA256 向量、VLESS UUIDv5/长度/含零字节输入通过。真实配置新增两种格式的有效 ID、加密配置和 Vision 启动，以及无效 ID、flow、encryption、Vision 传输组合拒绝；有效用例配置两个 Worker。 |
| 26 | AnyTLS 空闲检查没有定时驱动，两份会话列表又在最小保留数计算前关闭过期会话。新增协议私有 Worker-local SessionPool，以单一 Entry 存储所有权和空闲时间；物理会话 Lease 在获取或接收后立即占用，正常逻辑流完成才归还，其他退出自动关闭。周期回调只持有 weak State，不借用 handler；退役关闭会话并取消检查，generation 防止旧取消回调覆盖新调度。清理按最近归还顺序保护最小数量，一次整理，无分配，池空时释放存储。补充秒数到 steady_clock 的范围校验和绝对截止时间饱和计算。 | 全量 Release 构建成功；CTest 105/105，186.76 秒。生产池模板使用真实 Asio 定时器测试周期淘汰、最小数量、占用保护、异常归还、取消代次、带在途 Lease 的退役、两个 Worker 线程及最大正间隔。真实 VLESS -> cnode -> AnyTLS/TLS 链路校验摘要和响应：min=0 从 1 条空闲连接回收到 0；min=1 从 2 条保留 1 条且下一请求复用，总建连数仍为 2。 |
| 27 | AnyTLS 出站忽略 relay 超时参数，逻辑端点用空方法冒充超时控制，Cancel 只唤醒逻辑读端。利用请求对池中物理会话的独占所有权，将控制委托给 AsyncStream，使后台读循环、写入及半关闭遵守同一预算；传播真实超时信号，写失败保留取消分类。取消状态拒绝后续写入，在途写操作由作用域计数覆盖写门等待、数据帧和 FIN，取消时关闭整个物理会话；正常完成清除请求超时后才归还池。 | 全量 Release 构建成功；CTest 105/105，186.67 秒。另有 8 个真实 VLESS -> AnyTLS/TLS 场景全部通过：不回复 FIN、持续下行但不 FIN、半关闭时写入受阻、普通写入超时、逻辑 Alert 取消受阻写入，以及清理请求截止时间后的复用和两项原空闲池回归。撤销在途写关闭的变异实现约 2.03 秒才结束，被测试拒绝；恢复后约 0.63 秒结束。 |
| 28 | Freedom 与 Shadowsocks 原生 UDP 分别维护 relay、接收队列和取消状态，SS 的 idle/write 控制为空，DNS 等待不受写预算限制。新增 Worker-local UDPChannel，统一有界原始包队列、回调登记、超时和取消；SS 仅保留协议编解码。删除独立 DoUDPRelayLink、UDPRelayConfig、裸指针 SendTo 和单次 post 清理，所有出站进入 DoRelayLink。取消会结束并等待本请求的 DNS/发送子操作，不关闭共享 socket；写半关闭保留读端至下行预算结束。通用 LinkError 保留错误分类，无控制入站也执行限速并仅统计成功写入。注销不再构建延迟列表或尝试缩容，回调内注销在最外层分发结束后无分配移除。 | 全量 Release 构建成功；CTest 106/106，196.56 秒。新增 UDPChannel 实际 socket 单测覆盖所有权、20 KiB 数据、取消、队列上限、idle/read/phase、旧定时回调、最大间隔和限速；注销测试禁止分配。另有 7 个真实 VLESS -> UDP 场景通过，SS/Freedom DNS 黑洞约 1 秒取消，共享 socket 上另一请求继续传送 20 KiB，覆盖回显、无效 SS 回复及半关闭后延迟回复；8 个 AnyTLS/TLS 回归通过。 |
| 29 | TimeoutScheduler 取消最早事件或插入更早事件时，会先取消旧等待，再分配新等待；失败后留下虚假的在途标志，令牌析构还会吞掉异常，使其他事件失去调度。改为只保留一个在途等待，更早截止时间仅唤醒它，由完成回调统一重挂；等待启动成功后才发布标志。取消与析构不重挂、不分配，堆索引原地整理，删除取消重挂的异常吞并和多代等待状态。ScheduledSleep 的 channel 唤醒也会在 noexcept Cancel 中分配；删除该类及 RateTimerGuard，迁移为直接拥有实际等待的 AsyncDelay，统一限速、Mux 和 accept 退避。共享调度器与协程延时均对最大相对间隔计算饱和截止时间。 | 全量 Release 构建成功；CTest 106/106，196.75 秒。Asio 实际对齐分配故障先复现普通取消、析构和提前插入后剩余事件不触发，修复后无取消分配且事件正常完成。覆盖首次等待失败后恢复、4,096 个取消、连续替换在途等待、显式休眠取消、父协程取消与复用、最大时长、并发等待拒绝及原回调批次公平性；7 个 UDP 和 8 个 TLS 原生回归通过。 |
| 30 | 首包由三条辅助函数提前发送，再经八个专用重载补记字节，绕过正常限速，结果与会话字节数不一致，LinkError 被降为通用写失败。Dispatcher 统一首包为拥有所有权的 MultiBuffer，Outbound::Process 改为按值接收，所有协议将其移入普通上行循环。删除全部首包辅助函数、专用重载及未使用的双完整端点 relay 实现；VLESS、Trojan、AnyTLS 只在握手发送协议控制数据，删除用户数据预写入和补记统计。首包与后续数据共用同一限速器、错误分类和成功统计；分配失败标记为本地错误并释放缓冲。InitialPayload 转换失败保留尚未转交的数据并抛出分配错误，由 Dispatcher 现有边界分类。 | 全量 Release 构建成功；CTest 107/107，199.63 秒。基线五个用例先复现结果 12/会话 5、错误降级及 2,000 字节首包无限速；修复后统计一致、保留分类，并在 1,000 B/s 配置下约 1 秒开始写入。新增测试覆盖有/无控制入站、首包与后续字节顺序、共同限速额度、错误/超时/分配失败、缓冲释放和转换失败恢复；撤销转换检查后测试失败。27 个原生场景通过，包括 12 个首包链路、7 个 UDP 与 8 个 AnyTLS/TLS 回归。 |
| 31 | 首包追加忽略分配失败、赋值先清空旧值，MultiBuffer 在扩容前增加长度并接收已 release 的裸指针，失败还会部分改写尾块或丢失源槽位。统一单块接收/交出为 BufferGuard，按值插入失败自动释放，成功接管后才更新计数；追加、搬移和前缀拆分先准备全部缓冲与目标槽位，再提交字节及所有权。reserve 按有效槽位计算，修复已消费 spill 前缀后的容量保证。InitialPayload 改为只移动、span 输入和事务赋值，溢出长度直接来自 MultiBuffer；删除隐式复制、无调用 data/clear/insert 及手写 VLESS 槽位搬移，迁移全部协议、transport 与测试调用。 | 全量 Release 构建成功；CTest 108/108，199.85 秒。四项旧实现故障全部复现，修复后通过；新增分配矩阵覆盖 36 个失败点和 8 条成功路径，核对原字节、长度、重试、UDP 元数据与全部分配回收。另验证内联/溢出自追加、自赋值、有效槽位容量、无分配前缀合并、源长度不足和空槽位；27 个真实网络回归通过。 |
| 32 | TokenBucket 在等待后重复补发用于本次消费的额度，极大消费返回负等待。改为不可复制的 Worker-local 未来额度预留，保留千分之一字节余额，通过商余运算避免宽乘法上溢，时间与容量饱和；支持显式单调时间以验证精确行为。两个方向的限速器和实际等待统一由已收束任务的父作用域持有，方向失败和 relay 半关闭截止事件同时取消 I/O 与等待，恢复后检查终止状态再写数据。半关闭时间使用有界 time_point，回调由作用域内 token 持有；删除 NoopRate 包装及重复限速状态。最终错误明细采用实际结果，伴随取消不再覆盖原错。 | 全量 Release 构建成功；CTest 109/109，203.87 秒。基线复现第二批 1,000 字节等待为零及最大消费等待 -1,999 ms；修复后连续消费按额度等待，22,800 组输入与独立 Python 大整数模型一致。基线三个取消场景约 3 秒退出，其中一项超时后仍写 4,000 字节并返回成功；修复后半关闭约 1 秒结束、后续写入为零，对端错误立即结束，另覆盖双向半关闭及零预算。27 个原生回归通过；修复 TLS 测试对端的子任务关闭竞态。 |
| 33 | transport 取消未通知 relay 限速等待，无控制入站缺少目标 EOF 后的 uplinkOnly 预算。新增 Worker-local、无分配、一次触发的取消事件与作用域订阅；TCP、UDP 和具体出站端点传递终止原因，gRPC/XHTTP 服务端会话通知其逻辑端点。有控制 relay 无论是否限速均订阅两端，取消同伴 I/O 并在读取前后及限速恢复后检查终止状态；无控制 relay 用共同收束的停止任务取消两方向，统一双向半关闭预算。TCP 所有读/写/idle/phase 截止均经过 Cancel，phase 秒数换算饱和；删除重复 relay phase 截止与无调用的 TcpStream 移动实现。 | 全量 Release 构建成功；CTest 110/110，219.61 秒。基线五个场景约 3 秒才结束，其中无控制目标 EOF 后仍发送 4,000 字节；新回归覆盖 12 个限速终止场景、10 个阻塞读取场景、18 个真实 loopback TCP 场景及原 13 个首包行为。真实 UDP 新增外部取消和 phase 超时，两者均在限速数据发送前结束。取消事件测试覆盖无分配、重入、自身/同伴撤销和事件源先销毁。27 个原生网络回归全部通过。 |
| 34 | 只有 AsyncStream 提供取消通知，Mux/AnyTLS/原生 UDP 入站读端的终止不能穿过 Link；relay 启动前的终止也被一次事件丢弃。将 CancellationSource 纳入 MultiBufferReader 的强制契约，framing reader 委托数据来源，逻辑子流拥有自己的源；relay 直接订阅读端，保持唯一请求链路。CancelPending 只通知当前操作，Stop 永久保留原因并同步通知后来订阅；组合 transport 对临时事件重新订阅，终止不再开启。全面迁移并删除旧 CancellationEvent 公开类型与测试入口。 | 全量 Release 构建成功；CTest 110/110，219.80 秒。基线四项均等待约 3 秒、终止后仍发送 4,000 字节，资源不足也降成 CANCELLED；修复后活动取消约 60 ms 结束、提前终止立即结束，均未发送。取消源测试覆盖永久终止、后来订阅、反复转发、重入及无分配；relay 行为增至 57 项。新增 4 个真实面板限速 Mux/AnyTLS 场景：会话失败不发送第三批，正常 FIN 则完整发送 180,000 字节。既有 27 个原生回归通过，共 31 项。 |
| 35 | Mux 读取循环以 detached 启动，done 标志后的一次 post 不能证明借用状态已归还；动态 TCP/UDP 子请求也依赖事后等待计数。新增 Worker-local 有限任务组，启动前取得 join continuation，统一持有读取、帧处理与动态子请求，等到每个 co_spawn 完成后才释放会话。父取消、未捕获失败和部分启动失败均取消并收束已启动任务；删除 detached、读取完成通道、子请求完成通道和 post 等待。 | 全量 Release 构建成功；CTest 111/111，219.87 秒。新增测试覆盖动态子任务、父取消后异步清理、首个失败保留、启动回调失败、执行器归属，以及普通 new 和 Asio 实际对齐分配路径的 21 个失败点（8 个部分启动）。既有 31 个原生网络场景全部通过，包括 Mux/AnyTLS 面板限速取消与正常 FIN。 |
| 36 | AnyTLS detached 子请求在父取消后仍可存活，FinishRun 的计数/timer 等待不能覆盖异常退出；父子 shared_ptr 相互持有掩盖了运行时借用边界。AnyTLS 帧循环与所有子请求统一加入有限任务组，Handler 直接持有父会话，子流只在同一 Worker 借用父会话；删除旧计数、timer、完成 helper、detached 和 shared_from_this。任务组增加显式取消，AnyTLS/Mux 整体会话退出时同步取消子流来源及所有子任务的异步操作，覆盖尚未进入 relay 的等待。 | 全量 Release 构建成功；CTest 首次 111/112（220.10 秒），迁移唯一失败的旧计数等待契约后定向 1/1 通过，全部 112 项已验证通过；31/31 原生网络场景通过。基线父 Handler 返回时仍有 2 个子请求，会话错误则不能自行唤醒 pre-relay 等待。新增 9 个真实入站生命周期场景均在返回前完成 2 个子请求的异步清理，包括父取消、异常帧、物理 EOF、真实子流分配失败、写入和写入锁阻塞，以及 Mux 取消；21 个任务组分配失败点继续通过。 |
| 37 | AnyTLS 重复 SYN 会复用活动子流并重置解析状态，两个请求并发改写同一 context；双索引状态的 iterator 还可能跨 await 被子请求完成路径删除。子流 ID 改为会话内严格递增，非法 SYN 回复 Alert 并结束会话；流与接收阶段合并为一个拥有所有权的条目，读取只保留共享条目，删除重复创建 helper 和状态表。 | 全量 Release 构建成功；CTest 112/112，220.88 秒；35/35 原生网络回归通过。新增 10 个身份/状态场景及 4 个真实 TLS 身份场景。另一个地址与首包同帧的探索探针失败，已保留为下一轮问题，未算入通过的回归。 |
| 38 | AnyTLS 在帧循环中将首个 PSH 当作完整目标并清空整帧，丢弃同帧首包且拒绝跨帧地址。每个 SYN 现在启动一个拥有生命周期的解析/请求任务，帧循环只做会话控制和分发；删除帧驱动的目标/UoT 状态、StreamEntry、旧地址 reader 和三层 dispatch helper。逻辑解析保留剩余 MultiBuffer，TCP 首包按所有权进入 Dispatcher，UoT 复用同一剩余字节序列。 | 全量 Release 构建成功；CTest 112/112，220.88 秒；48/48 原生网络回归通过。新增 11 个 Handler 解析场景及 13 个 TLS/TCP/UoT 场景，基线两种丢包/跨帧失败均已修复。另发现 v1 客户端仍收到 v2 控制帧，作为下一轮未解决问题保留。 |
| 39 | AnyTLS 入站忽略客户端版本并无条件发送 v2 控制帧，出站使用 find("v=2") 误将其他字段当作版本。统一协议私有精确键值解析及版本校验，会话只保留一次确定的 v1/v2 能力枚举；SYNACK、ServerSettings、心跳按协商结果启用，重复设置及错误控制状态终止会话。删除旧摘要 helper、握手 bool 和窄整数/子串版本判断，客户端标识改为 cnode。 | 全量 Release 构建成功；CTest 112/112，220.98 秒；75/75 原生网络回归通过。新增 30 个解析边界检查、15 个真实 TLS 入站和 12 个真实 TLS 出站场景；两个旧二进制失败均转为通过。 |
| 40 | Dispatcher 原先只在 relay 阶段观察读端取消，已停止请求仍可进入出站，嗅探/路由 DNS/握手等待未联动取消。使用有限任务组持有完整请求，把实际读端取消桥接到该请求的 Asio 取消范围；DNS 返回后检查取消，订阅随子任务销毁并等待实际完成，保留逻辑错误原因及成功 relay 结果。嗅探保留 LinkError 和内存不足分类。 | 全量 Release 构建成功；CTest 113/113，222.65 秒；75/75 原生网络回归。新增真实 Dispatcher/DNS/relay 的 30 个场景；28 项旧实现对照中 20 个失败均转为通过，另新增两项同 Dispatcher 请求隔离检查。 |
| 41 | AnyTLS 出站 Process 启动 detached 物理读取，未捕获分配异常被丢弃，活动请求等待且空闲会话仍可复用。物理任务改由 SessionPool 接纳时启动，显式完成回调持有池状态和会话、处理异常并关闭失效会话；退役取消协程，I/O 状态存活到实际完成。删除旧 detached 和启动标志，明确跨请求根任务与有限逻辑请求的寿命。 | 全量 Release 构建成功；CTest 114/114，224.61 秒；75/75 原生回归。真实 Handler 的 4 项生命周期/异常检查通过，2 项旧实现失败已修复；池任务启动注入 8 次分配故障、24 次成功，全部释放；共享注入工具迁移后原任务组 21 个故障点、8 次部分启动仍通过。 |
| 42 | AnyTLS 入站为每条 SYN 接纳的有限子任务增加绝对握手预算，覆盖目标、UoT 和 SYNACK，并在进入 Dispatcher 前 join 和撤销定时器；同一会话最多 128 条未结束子流，超额只拒绝新流并退役 ID。共享门闩等待可单流取消，实际帧写入中断则关闭物理会话。 | 全量 Release 构建成功；最终 CTest 114/114，228.06 秒；84/84 原生回归。新增 9 项真实 TLS 检查及 5 项 Handler 生命周期检查通过，旧版本仅 SYN 超时及第 129 流接纳两项复现失败。 |
| 43 | AnyTLS 入站移除逐 PSH 的嵌套队列，改为拥有字节计数的 MultiBuffer；合并小片段，按至少半块的密度约束转移大块，队列最多 16 个 Buffer。删除重复字节计数、队列收缩状态及专用 include；容量等待、FIN 排空、取消 join 和 UoT 解码保持原职责。 | 全量 Release 构建成功；CTest 114/114，230.42 秒；84/84 原生回归。24 项真实 Handler 队列/分配检查通过；2,048 个单字节帧从 2,048 块降至 1 块，完整帧仍转移原 Buffer，六项 UoT 包边界回归通过。 |
| 44 | AnyTLS codec 保留非 I/O 原始异常；通用入站和物理会话所有者负责分类，逻辑端点以 LinkError 传递已有原因，四个物理写入口异常时关闭会话。子任务从自己持有的 Context 记录失败，避免索引清空后漏记。 | Release 全量构建成功；CTest 全量 115/116，修正一条过宽契约后单项复测 1/1，116 项均已验证；84/84 原生回归。新增 240 项 codec、32 项通用入站、3 项 SYNACK、15 项出站故障场景全部通过。 |
| 45 | AnyTLS 出站移除逐 PSH 嵌套队列、重复计数及收缩状态，两端共用私有字节聚合函数。逻辑输入整体移交，异常关闭先发布终态再清空及取消；删除无调用 Sid、重复终止入口和多余参数，子流直接使用所属会话的 io_context。 | 全量 Release 构建成功；CTest 116/116，237.43 秒；84/84 原生回归。28 项新增出站队列场景和 24 项原入站队列场景通过，2 KiB 单字节分帧从 16 MiB 降至 8 KiB 数据块容量，整帧直接转移与 UoT 包边界均验证。 |
| 46 | AnyTLS 出站满队列改为物理读任务内等待容量，消费和关闭唤醒等待；移除正常突发的资源不足拒绝分支，保留原容量与真实分配失败分类。 | Release 全量构建成功；CTest 116/116，238.73 秒；原 84 项加新增 6 项网络回归，共 90/90。31 项出站队列场景通过，真实暂停读取的 8 MiB 响应由截断恢复为完整交付并复用连接，取消与超时仍有效。 |
| 47 | 独立官方实现对照，确认 AnyTLS FIN 被误当作半关闭；新增固定官方版本、验证构建元数据及二进制哈希的网络测试，并纠正文档中的错误语义。尚未修改生产关闭逻辑。 | 官方客户端/服务端四项对照通过；同一测试下 cnode 四项全部失败，进程退出 1，作为待修复基线保留。确认 FIN 后双向额外数据、重复 FIN、本地 EOF 后未及时关闭及复用失败。未重跑 C++ 构建或宣称旧 116/90 项足以覆盖此问题。 |

构建与回归日志保存在 `build/round1-full-build.log`、`build/round2-build.log`、`build/round3-build.log`、`build/round4-build.log`、`build/round5-build.log`、`build/round6-full-build.log`、`build/round7-build.log`、`build/round8-build.log`、`build/round9-build.log`、`build/round10-build.log`、`build/round11-build.log`、`build/round12-build.log` 和对应的 `build/roundN-ctest.log`。第十二轮全量 CTest 用时 26.38 秒。烟测脚本与结果位于 `build/round12-monitor-smoke.ps1`、`build/round12-smoke-result.json`，日志在 `build/round12-monitor-smoke/logs/`。烟测覆盖正常监控运行，不代表代理协议端到端验证；Linux RSS 分支尚未在 Linux 执行。

第十三轮构建和回归日志为 `build/round13-full-build.log`、`build/round13-ctest.log`；旧退出路径基线记录为 `build/round13-before-ctest.log`。进程退出不会等待连接或上传队列排空，失败诊断同步写 stderr；README 与 AGENTS 已同步此边界。

第十四轮构建和回归日志为 `build/round14-build.log`、`build/round14-ctest.log`。原工作区再次核对，仅有既存未跟踪 `.codex/`；本 worktree 的累计改动仍未提交、推送或部署。

第十五轮日志为 `build/round15-build.log`、`build/round15-ctest.log`。停机契约测试迁移为 `controller_monitor_contract_test`，检查独立循环与删除后的公共边界。

第十六轮日志为 `build/round16-build.log`、`build/round16-ctest.log`，原生失败基线在 `build/round16-before-ctest.log`。独立探针为 `build/round16-replay-probe.py`，修复前观察在 `build/round16-before-replay.log` 与 `build/round16-panel-replay/result.json`；该 JSON 是旧行为证据，不能当作修复后的状态。探针和测试仅使用 loopback、测试密钥与空流量，测试进程已结束，未触及线上面板。

第十七轮日志为 `build/round17-build.log`、`build/round17-ctest.log`，挂起 POST 的旧行为证据在 `build/round17-before-ctest.log`。原生 HTTP 回归实际在 Windows 执行，未跳过；请求取消与响应保留也由真实 Asio 协程行为测试验证。HTTPS 关闭握手的接入完成源码检查和编译，尚未用真实 TLS 对端注入故障。测试结束后核对本 worktree 的 cnode 进程数为零。

第十八轮日志为 `build/round18-build.log`、`build/round18-test-final-build.log`、`build/round18-ctest.log`。原生心跳失败基线在 `build/round18-before-ctest.log`；通过后的完整测试输出另存为 `build/round18-last-test.log`，其中记录 `panel heartbeat count=2 gap=60s while the same POST remained pending`。本轮真实网络测试均在 Windows 执行且未跳过，测试进程已结束。

第十九轮日志为 `build/round19-build.log`、`build/round19-test-final-build.log`、`build/round19-ctest.log`，完整测试输出另存为 `build/round19-last-test.log`。迁移前的单节点生命周期基线在 `build/round19-before-ctest.log`（通过）；初版探针只查控制台而漏掉应用 error 日志，其失败记录在 `build/round19-fixture-initial.log`，不是产品故障证据。最终双节点观察记录为 `panel lifecycle ready/failure/refresh/missing/recovery with isolated companion=1`，产物目录 `build/panel_lifecycle_test/` 保留测试配置和日志。该回归验证控制面操作及真实 TCP 监听生命周期，不代表协议认证和完整代理流量验证。Windows 原生网络用例均未跳过，测试进程已结束。

第二十轮日志为 `build/round20-build.log`、`build/round20-ctest.log`，完整测试输出另存为 `build/round20-last-test.log`。事务独立验证在 `build/round20-transaction-ctest.log`，变异验证在 `build/round20-mutant-ctest.log`，恢复保护后的验证在 `build/round20-restored-ctest.log`；变异失败是人为撤销保护的测试结果，不能当作原二进制的现场故障。操作层故障注入执行生产事务实现，以测试 Runtime 模拟完成前后的部分副作用；未在真实 Worker 或 VPS 上注入系统故障。全量回归后仅删除 control.cpp 已无使用的 include 和多余空行，主程序复编通过，记录在 `build/round20-final-build.log`。本轮 Windows 原生网络测试未跳过，测试进程已结束。

第二十一轮日志为 `build/round21-build.log`、`build/round21-final-build.log`、`build/round21-ctest.log`，全量输出另存为 `build/round21-last-test.log`。真实旧二进制失败基线在 `build/round21-baseline-collision.log`，明确显示节点 1、2 使用同一旧标签且都宣告 ready。修复后的独立验证在 `build/round21-focused-ctest.log` 与 `build/round21-focused-last-test.log`，三个原生用例的配置和日志保留在 `build/panel_collision_test/`、`build/panel_collision_race_test/`、`build/panel_static_collision_test/`。这些用例在 Windows 配置两个 Worker 执行，Windows 实际 TCP 监听仍由 Worker 0 持有；尚未在 Linux 上实际验证多 Worker 的 SO_REUSEPORT 竞争，也没有注入真实 UDP 冲突。UDP 共用地址重叠判定并单独接入 Worker 检查，完成源码检查、编译和地址语义单测。TCP 验证覆盖监听存在和所有权拒绝日志，不代表完整协议认证与代理流量验证。原工作区仍只有未跟踪 `.codex/`，未提交、推送或部署。

第二十二轮真实旧程序基线在 `build/round22-baseline-ctest.log` 与 `build/round22-baseline-last-test.log`：同名配置显示静态端口与 10086 共用 `test-vmess-10086` 且服务启动；端点冲突则在运行态启动阶段强制退出。旧同名用例因为进程未按预期拒绝配置，被测试拥有者在 10 秒后终止，不能将该退出当作产品主动拒绝。修复后的独立回归为 `build/round22-focused-ctest.log`、`build/round22-focused-last-test.log`；原生启动产物在 `build/test_mode_*_test/`。初次构建暴露新测试对冗余 RecomputeModes 调用的链接依赖及字符串字面量哈希歧义，记录为 `build/round22-build.log`；测试配置改用普通 StreamSettings 已归一化的默认值、查找使用显式 string_view 后，`build/round22-final-build.log` 构建成功。变异检查脚本为 `build/round22-mutant-check.py`，失败证据在 `build/round22-mutant-ctest.log`，脚本 finally 恢复原源码字节；`build/round22-restored-build.log` 记录恢复后的完整构建。全量 CTest 和输出分别在 `build/round22-ctest.log`、`build/round22-last-test.log`。用户批次测试执行真实 UserStore 并在测试可执行文件中替换分配器；准备测试只替换协议凭据回调，原生进程测试执行真实 VMess 构建与 TCP 监听，未验证完整代理认证和流量。

第二十三轮的旧异常边界验证在 `build/round23-baseline-build.log`、`build/round23-baseline-ctest.log`、`build/round23-baseline-last-test.log`。先将原生产传输值操作等价移出 config.cpp，保留 noexcept 行为，再链接到真实分配失败测试；set_terminate 处理器记录调用并以 71 退出。这是生产函数的独立进程验证，未在真实线上面板更新中注入内存故障。新实现的独立验证在 `build/round23-focused-ctest.log`、`build/round23-focused-last-test.log`，记录通用与出站各 11 个分配失败点。完整构建为 `build/round23-build.log` 与 `build/round23-final-build.log`，全量回归为 `build/round23-ctest.log` 与 `build/round23-last-test.log`。原生网络回归均在 Windows 执行，未跳过；各协议完整客户端握手未单独重测。旧源码提取和调用迁移脚本留在 `build/round23-extract-stream-settings.py`、`build/round23-normalize-value.py` 作为迁移记录。

第二十四轮旧二进制探针为 `build/round24-credential-probe.py`，六个 case 的完整配置、控制台日志和汇总位于 `build/round24-credential-baseline/`。结果均为 accepted=true、exit_before_harness_cleanup=null；每个仍在运行的测试子进程由拥有者结束，不能将该退出误记为产品拒绝。构建日志为 `build/round24-build.log`、`build/round24-final-build.log`，针对性回归为 `build/round24-focused-ctest.log` 与 `build/round24-focused-last-test.log`；补充显式空/非字符串 method 拒绝后的最终全量输出为 `build/round24-ctest.log` 与 `build/round24-last-test.log`。Shadowsocks 一次性调用迁移脚本为 `build/round24-migrate-ss.py`。本轮 SS2022 身份链限制直接对应现有生产 TCP/UDP 编解码器能力；未修改协议线格式。所有原生网络用例在 Windows 执行且未跳过；新增凭据用例验证冷路径拒绝、启动和独立密钥字节，不代表真实上游端到端代理握手验证。原工作区保持不变，未提交、推送或部署。

第二十五轮基线为 `build/round25-baseline-build.log`、`build/round25-baseline-ctest.log` 和 `build/round25-baseline-last-test.log`：测试直接链接修改前的 TrojanCodec，关闭普通 C++ new 分配后出现 bad allocation。Vision 基线脚本 `build/round25-vision-baseline.py` 复用上一轮拥有子进程的探针框架，完整配置及结果位于 `build/round25-vision-baseline/`；明文 TCP 与 WebSocket+TLS 均 accepted=true，进程由测试拥有者结束，未验证实际代理握手。首次针对性回归 `build/round25-focused-ctest.log` 因新用例把 VLESS 自定义 ID not-a-uuid 错当成无效 UUID 而失败；源码明确支持 1–30 字节 ID，此记录是测试假设错误，不能当作产品缺陷。修正为超长 ID 拒绝并补充有效自定义 ID 后，`build/round25-focused-final-ctest.log` 和 `build/round25-focused-final-last-test.log` 记录 5/5 通过。构建为 `build/round25-build.log`、`build/round25-final-build.log`，全量结果和输出为 `build/round25-ctest.log`、`build/round25-last-test.log`。Trojan/AnyTLS 哈希和 VLESS UUIDv5 的固定向量独立核对 Python hashlib/uuid；其中 SHA256 校验解析后摘要，未单独验证 AnyTLS 的真实 TLS 认证链路。协议准备迁移脚本为 `build/round25-prepare-credentials.py`。原生回归全部在 Windows 执行，未跳过；没有线上部署或真实上游互操作验证。

第二十六轮真实链路脚本为 `tests/anytls_pool_integration.py`，仅依赖 Python 标准库，证书及密钥为 `tests/fixtures/anytls-pool/` 内的公开 loopback 测试材料。单 Worker 失败基线在 `build/round26-baseline-single-worker/` 及同名 `.log`：min=0 时 1 条连接未回收，min=1 时 2 条连接均未回收且下一次请求产生第 3 次建连。首个探索基线 `build/round26-baseline/` 在 Windows 配置两个 Worker，实际监听由 Worker 0 持有；为明确验证每个 Worker 的保留语义，正式基线和最终验证改为单 Worker。所有统计在测试拥有者结束子进程之前采集。首次修复后的真实链路结果为 `build/round26-integration/`，最终结果为 `build/round26-integration-final/`，日志分别同名加 `.log`。它们是独立执行的 TLS/TCP 集成探针，不计入 CTest 数量；对端是本地可控 AnyTLS 测试实现，未覆盖 AnyTLS v2 SYNACK 协商、UDP/UoT 或真实外部服务互操作。

本轮构建记录为 `build/round26-build.log`、`build/round26-final-build.log`、`build/round26-reviewed-build.log`；最后一份包含线性清理和空池释放。针对性 CTest 在 `build/round26-focused-ctest.log`、`build/round26-focused-last-test.log`，最终全量在 `build/round26-ctest.log`、`build/round26-last-test.log`。迁移脚本为 `build/round26-migrate-pool.py`。池单测执行真实模板和定时器，以轻量 Session 替身检查资源关闭和线程身份；真实网络探针补充生产 ClientSession、协议认证、转发和复用验证。调度异常分支完成代码检查，未注入真实分配失败。原生 CTest 在 Windows 执行且未跳过；未提交、推送或部署。

第二十七轮旧二进制基线在 `build/round27-baseline-no-fin-observed/minimum-0/result.json`：downlinkOnly=1 时，客户端等待读结束 5 秒仍超时，测试结束前出站 TLS 连接仍为 1。`build/round27-no-fin-probe.py` 是该单场景探针；修复后同一探针结果在 `build/round27-fixed-no-fin/`。这些超时结果来自测试拥有者的等待上限，不能当作产品自行收敛。正式脚本扩展为 `tests/anytls_pool_integration.py --suite relay`，仍只依赖 Python 标准库和公开 loopback 证书。最终六项 relay 验证在 `build/round27-relay-integration-final/`，两项空闲池回归在 `build/round27-pool-integration-final/`，日志分别为同名 `.log`。所有连接统计均在测试结束子进程前采集。

`build/round27-mutant-check.py` 临时撤销 Cancel 中的在途写关闭，finally 恢复原始源码字节并完整重建。`build/round27-alert-write-mutant/result.json` 记录 2.031 秒才完成，晚于测试 1.8 秒上限；测试对端在 2 秒才恢复读取。最终实现处理同类 Alert 用时约 0.625 秒，证明请求结束依赖真实取消，而非等待对端恢复读取或默认 30 秒超时。客户端主动断开探索保存在 `build/round27-cancel-write*`，未能独立确认该路径已触发逻辑端点 Cancel，暂停读取也影响对端的 EOF 观察，未作为缺陷结论或通过证据；最终验收使用明确的逻辑 Alert 触发取消。

本轮构建为 `build/round27-build.log`、`build/round27-final-build.log`、`build/round27-mutant-build.log`、`build/round27-restored-build.log`；最后一份是恢复保护后的完整 Release 构建。全量结果和输出为 `build/round27-ctest.log`、`build/round27-last-test.log`。没有新增 CTest 数量，8 项 TLS 探针独立执行。普通写超时场景同时要求客户端读写结束，且上传不足 64 MiB，以确认实际产生了写入背压；持续下行场景观察到 9 个追加小包，仍约 1 秒结束。成功会话在 1 秒请求超时配置下空闲 3.5 秒后仍被复用。原生验证在 Windows 单 Worker 执行，未覆盖 AnyTLS v2 SYNACK、UDP/UoT 或外部服务互操作；未提交、推送或部署。

第二十八轮旧二进制基线为 `build/round28-dns-write-probe.py` 与 `build/round28-baseline-dns-write/result.json`：write=1、DNS 超时=10 时，Shadowsocks 原生 UDP 请求等待 4.015 秒仍未关闭，DNS 服务已收到查询；这是探针观察上限，进程由测试拥有者结束。首次修复结果在 `build/round28-fixed-dns-write/`，约 1.031 秒关闭。正式脚本 `tests/udp_relay_integration.py` 使用独立 AES-128-GCM Shadowsocks 对端、真实 UDP 回显和黑洞 DNS，仅在 loopback 运行；Python 依赖 cryptography，DNS 使用 127.77.0.2:53，非特权 Unix 可能无法绑定该端口。

本轮中间实现曾将写半关闭等同整个端点关闭；新增延迟回复探针在 `build/round28-halfclose-review/` 对 Freedom、Shadowsocks 均得到 IncompleteReadError。这是重构过程中发现并修正的回归，不是原基线缺陷。最终保留读侧登记直至下行预算结束，7 项最终原生结果在 `build/round28-udp-integration-reviewed/results.json`，日志为同名目录加 `.log`；DNS 用时约 1.016–1.031 秒，取消后共用 socket 的请求仍完成 20,480 字节往返。AnyTLS 的六项 relay 与两项空闲池回归分别在 `build/round28-tls-relay-regression/` 和 `build/round28-tls-pool-regression/`。这些网络探针独立执行，不计入 CTest 数量，全部结果在结束测试子进程前采集。

首次独立测试构建暴露 UDPSession 对预编译头内 Asio include 的隐式依赖，补齐显式 include 后通过；旧源码契约还匹配已移除的队列与方法，更新为共同端点所有权和有界队列要求。相关记录为 `build/round28-focused-build.log`、`build/round28-focused-build-final.log`、`build/round28-focused-ctest.log` 和 `build/round28-public-contract-ctest.log`。普通注销的分配计数测试在 Windows 旧缩容实现上也通过，`build/round28-unregister-baseline-ctest.log` 不是失败基线；移除注销路径上的可选 rehash 是保证跨 STL 的无分配契约，不声称已复现该分配故障。最终完整构建为 `build/round28-reviewed-build.log`，全量回归为 `build/round28-reviewed-ctest.log` 与 `build/round28-reviewed-last-test.log`。原工作区仍只有既存 `.codex/`，没有遗留本轮测试进程；未提交、推送或部署。验证范围为 Windows 单 Worker、SS AES-128-GCM 与 Freedom 原生 UDP，未验证 Linux 多 Worker、SS2022 真实对端或外部服务互操作。

第二十九轮先以未修改的 TimeoutScheduler 生产源码链接故障测试，记录为 `build/round29-baseline-build.log`、`build/round29-baseline-ctest.log` 与 `build/round29-baseline-last-test.log`：普通取消抛出 bad_alloc，令牌析构吞掉一次失败，提前插入触发两次分配失败，三者的剩余回调均未触发。`tests/timeout_scheduler_allocation.hpp` 仅通过测试目标的 forced include 拦截 Asio 实际 aligned_new，涵盖 Windows 的 _aligned_malloc，保留原配对释放函数；不修改 Asio 依赖源码或生产分配路径。普通 C++ new 的禁用另行覆盖事件索引整理。

共享调度器修复后的首次验证在 `build/round29-focused-ctest.log` 与对应 last-test，三个基线场景均为零取消分配、剩余事件执行。扩展测试在 `build/round29-expanded-ctest.log`、`build/round29-diagnostic-test.log` 暴露旧 ScheduledSleep 的 noexcept 通道唤醒导致异常退出（0xc0000409）；迁移 AsyncDelay 后直接取消真实 timer，`build/round29-delay-ctest.log` 通过。后续测试曾把 io_context 外的 Asio cancellation_signal.emit 也放进禁分配区，并仅给 Windows 上的 1 毫秒事件 10 毫秒观察期，记录为 `build/round29-final-focused-ctest.log`；前者超出本组件显式 Cancel 的无分配契约，后者受系统定时粒度影响。最终保留显式 Cancel 的普通/Asio 双重禁分配，父取消验证实际完成与复用，并给事件 100 毫秒观察期；不将这两项测试假设当作额外生产缺陷。

最终针对性结果在 `build/round29-reviewed-focused-ctest.log`、`build/round29-reviewed-focused-last-test.log`，完整 Release 构建在 `build/round29-build.log`，全量回归在 `build/round29-ctest.log` 与 `build/round29-last-test.log`。网络回归分别为 `build/round29-udp-integration/`、`build/round29-tls-relay-regression/`、`build/round29-tls-pool-regression/`，各自 results.json 全部通过，日志为同名目录加 `.log`，15 项探针不计入 CTest 数量。回调基础设施异常仍交由进程运行期失败边界处理；故障注入未覆盖完成回调中重新挂起的全部内部失败点。本轮在 Windows 执行，未单独验证 Linux 定时器后端或真实 Mux 背压互操作；原工作区保持不变，未提交、推送或部署。

第三十轮基线为 `build/round30-baseline-build-final.log`、`build/round30-baseline-ctest.log` 和 `build/round30-baseline-last-test.log`。测试直接执行旧 relay 模板：7 字节首包加 5 字节后续数据得到 result=12、context=5；目标抛出 LinkError(RESOURCE_EXHAUSTED) 却返回 RELAY_WRITE_FAILED；speed_limit=1000 时，2,000 字节首包在 0 毫秒写出且 context=0。迁移脚本为 `build/round30-migrate-initial.py`，修改前涉及文件的完整字节保存在 `build/round30-before/`。协议握手与首包不再合并为同一写入；协议线格式保持原样，用户数据统一接受 relay 限速和统计。

初次全量构建 `build/round30-build.log` 已生成主程序，但三个测试替身仍使用旧 Outbound::Process 签名；迁移替身后，`build/round30-expanded-build-final.log` 记录针对性构建通过。旧 access-log 契约还要求 prewritten_bytes 和独立首包错误分支，已迁移为禁止协议预写入统计、要求拥有型首包转交与本地分配失败分类，相关结果在 `build/round30-expanded-ctest.log`、`build/round30-contract-ctest.log` 和 `build/round30-contract-final-ctest.log`。新增行为测试实际比较字节顺序、全部计数和 Buffer 回收，覆盖有/无控制入站；750 字节首包后再写 750 字节时，后一次写入约等待 0.5 秒，证明没有在首包之后重新初始化限速器。

`build/round30-move-fault-mutant.py` 仅将 MoveToMultiBuffer 的失败检查暂时恢复为旧的忽略返回值，用 finally 恢复原文件字节并重建。`build/round30-move-mutant-ctest.log` 与对应 last-test 记录 failed=0、retained=0、recovered=0；恢复后的 `build/round30-move-restored-ctest.log` 和 `build/round30-move-restored-last-test.log` 记录失败被报告、17 字节原始数据保留、随后转换成功。该测试预先持有 64 个 Buffer，耗尽当前 Worker 的回收缓存，再禁用普通 new，保证触发实际分配失败；它不代表 InitialPayload 的追加/复制路径已经验证。

新原生脚本 `tests/initial_payload_integration.py` 只依赖 Python 标准库和公开 loopback TLS 证书，独立校验 VLESS UUID、Trojan SHA224、AnyTLS SHA256 及目标地址，再比较客户端与对端完整字节和 SHA256。Freedom、VLESS、Trojan、AnyTLS 各覆盖首次写入 0、17、24,000 字节，加后续 126 字节，并验证服务器问候可在后续数据前返回。首个 `build/round30-initial-integration/` 中四项无首包用例等待超时，原因是测试配置沿用默认嗅探预读；明确关闭 sniffing 后，`build/round30-initial-integration-final/` 和最新主程序的 `build/round30-initial-integration-reviewed/` 均为 12/12。该超时不作为本次出站迁移的回归结论。TCP 首次写入大小不等于单次内核读取大小，结果证明完整链路的字节完整性，不声称整个 24 KB 必然在一次读取中到达。

最终完整构建为 `build/round30-final-build.log`，全量回归为 `build/round30-ctest.log` 与 `build/round30-last-test.log`。其余网络回归在 `build/round30-udp-regression/`、`build/round30-tls-relay-regression/`、`build/round30-tls-pool-regression/`，日志均为同名目录加 `.log`；27 项原生用例独立执行，不计入 CTest 数量。原生验证范围为 Windows 单 Worker、VLESS 普通 TCP、Trojan/AnyTLS 本地 TLS 和已有 UDP 场景；未覆盖真实 VMess 上游、SS TCP/SS2022、VLESS Vision/加密/XUDP、AnyTLS v2 SYNACK 或 Linux 后端互操作。原工作区保持不变，未提交、推送或部署。


第三十一轮基线文件为 `build/round31-baseline-build-final.log`、`build/round31-baseline-ctest.log` 和 `build/round31-baseline-last-test.log`：首包由 17 字节追加至堆存储、首包赋值、MultiBuffer 第九块插入和已有 33 字节尾块的跨块追加，禁用实际分配时四项均未保留正确状态。原始两个容器头保存在 `build/round31-before/`，批量调用迁移前的文件在其 `migration/` 子目录，迁移脚本为 `build/round31-migrate.py`。初次主程序构建发现 VMess 的具名 MultiBuffer 构造仍交入裸指针，随后连同全部同类生产和测试调用迁移，记录在 `build/round31-main-build.log` 与最终 `build/round31-build.log`；没有保留裸指针兼容重载。

`tests/buffer_ownership_test.cpp` 直接执行真实容器，每个矩阵用例先清空 Worker 回收缓存并持有 64 个 Buffer，再逐次减少普通 new 的可用分配次数。八组矩阵共执行 44 次，其中 36 次实际分配失败、8 次完整成功，覆盖 inline 到 heap、已溢出追加、事务赋值、多块追加、inline/spill 指针扩容、带 UDP 元数据的整段搬移及前缀拆分；每次失败检查原内容与计数，随后重试并检查完整字节顺序。测试跟踪普通 new/delete，作用域退出后清空回收缓存，验证所有受测分配均已释放；Buffer 对齐由 static_assert 约束在普通分配覆盖范围内。按值接收的单块 guard 失败后被销毁；批量操作在资源准备成功前不消费源容器。这两种所有权语义在 AGENTS 与 README 中明确区分。

针对性结果位于 `build/round31-focused-ctest.log`、`build/round31-focused-last-test.log`、`build/round31-matrix-ctest.log` 和 `build/round31-matrix-last-test.log`。最终回归为 `build/round31-ctest.log`、`build/round31-last-test.log`。原生结果位于 `build/round31-initial-integration/`、`build/round31-udp-regression/`、`build/round31-tls-relay-regression/`、`build/round31-tls-pool-regression/`，日志为同名目录加 `.log`；27 项探针独立于 CTest，均通过。验证仍限于 Windows 及现有 VLESS、Trojan、AnyTLS/TLS、Freedom/SS UDP 场景；VMess、SS TCP/SS2022、Vision 与加密的改动由完整编译及现有协议测试覆盖，未补充真实上游互操作。原工作区仍仅有原 `.codex/`，未提交、推送或部署。


第三十二轮令牌桶基线在 `build/round32-baseline-build.log`、`build/round32-baseline-ctest.log` 和 `build/round32-baseline-last-test.log`，实际输出 first=1001ms、second=0ms、maximum consumption wait=-1999ms。取消基线在 `build/round32-cancel-baseline-build.log`、`build/round32-cancel-baseline-ctest.log` 和对应 last-test：有控制入站约 3,015 ms 返回超时，无控制入站约 3,013 ms 后写出 4,000 字节并返回 OK，对端读失败也要约 3,009 ms 才结束。测试端点使用实际 TimeoutScheduler 截止回调；因其只能取消 I/O，原先无法结束另一份 AsyncDelay。

原始两个头在 `build/round32-before/`，relay 迁移脚本为 `build/round32-relay.py`。初次针对性构建发现脚本误删了无控制路径的局部结果状态，已完整恢复原有状态，记录于 `build/round32-focused-build.log`、`build/round32-focused-build-final.log`、`build/round32-focused-build-reviewed.log`。`build/round32-focused-last-test.log` 显示两个超时场景约 1,009/1,013 ms 结束，写入为零；读失败立即结束。进一步比较最终结构化错误时发现同伴 CANCELLED 会覆盖原有明细，`build/round32-expanded-last-test.log` 记录该失败，随后统一在两个 relay 出口写入选定的最终错误。最终 CTest 还覆盖相反方向的半关闭和零秒预算。

`tests/token_bucket_test.cpp` 提供真实时钟基线、确定性额度行为及测试专用命令流，`tests/token_bucket_oracle.py` 用 Python 大整数直接累计千分之一字节余额并向编译后的真实 TokenBucket 输入 22,800 次消费；覆盖 38 种固定或随机速率、零/极大数据量、分数额度、积累上限、提前预留、负起点和较大单调时间。`build/round32-token-oracle/commands.txt` 保存可重放输入，`results.json` 与同名 `.log` 记录零差异。大整数模型与 C++ 商余/二分计算相互独立；此验证证明所测试的毫秒记账语义，不表示跨平台计时精度或性能基准已经验证。

完整构建和回归分别为 `build/round32-build.log`、`build/round32-ctest.log`、`build/round32-last-test.log`。原生结果在 `build/round32-initial-integration/`、`build/round32-udp-regression/`、`build/round32-tls-relay-reviewed/`、`build/round32-tls-pool-reviewed/`，日志为同名目录加 `.log`。首次 `build/round32-tls-relay-regression/` 的 trickle_no_fin 在约 1.031 秒已正确关闭，但测试后台发送任务继续使用关闭的 TLS writer，报 Python AttributeError；对端现在在连接关闭前取消并等待其子任务，重跑六项 TLS 与两项池回归通过。`build/round32-tls-cleanup-repeat/` 又连续重复该关闭场景三次，均无对端异常。这里没有将测试端异常归为 cnode 的转发错误，也没有忽略该异常来判通过。

27 项原生场景不计入 CTest；限速取消由真实异步等待测试和已有 UDP socket 限速测试覆盖，未新增完整面板下发限速的 TCP 原生探针。验证环境仍为 Windows；Linux 后端、真实 VMess/SS TCP/SS2022、Vision 与加密上游互操作范围保持此前限制。原工作区仍未更改，未提交、推送或部署。

第三十三轮基线为 `build/round33-baseline-build.log`、`build/round33-baseline-ctest.log`、`build/round33-baseline-last-test.log`。新增 mode 5 至 9 均失败：无控制目标 EOF 后等待约 3,009 ms，仍上送 4,000 字节并返回 OK；两端限速期间的外部取消或 phase 超时也要约 3 秒才能返回。首次事件迁移及无控制停止任务的针对性结果在 `build/round33-half-close-build.log`、`build/round33-focused-ctest.log`；随后增加资源不足原因、阻塞读取和真实 TCP/UDP 验证，没有把最初通过的限速用例当成全部取消语义已完成。

`build/round33-expanded-ctest.log` 记录测试控制端点将极大秒数直接转换为毫秒而立即超时；源码核对发现真实 TcpStream::StartPhaseDeadline 也采用相同转换，已饱和处理。删除 relay 自己的重复 phase 截止后，`build/round33-network-ctest.log` 又暴露无限速、有控制端点在目标已 EOF 后收到取消仍可能挂住。现在取消订阅不依赖限速开关，记录终止原因后同时取消两端；读取开始前检查已经到达的终止，读取返回后也检查，避免 TCP 把 operation_aborted 表示为空读取时被误判为正常 EOF。真实 TCP 测试直接链接 AsyncStream/TcpStream 实现，没有依赖主程序 PCH，补齐该源文件自己的 Asio include。

`tests/cancellation_event_test.cpp` 在拒绝普通 new 的作用域内验证一次通知、128 个订阅者、移除自身及其他订阅、通知中注册后续操作、重入通知、订阅先销毁和事件源先销毁。通知会先摘下当前批次；后来注册的操作只接收后续事件。事件不是永久取消标志，relay 自己保留本次终止原因；事件源与订阅均不能移动。TcpStream 原有移动构造/赋值没有生产或测试调用，却会移动 socket 而丢失回调及订阅身份，已连同实现删除；源文件删除前备份为 `build/round33-before/tcp-before-move-removal.cpp`。迁移脚本及其他备份位于 `build/round33-cancellation.py`、`build/round33-half-close.py` 和 `build/round33-before/`。

完整针对性回归为 `build/round33-control-reviewed-build.log`、`build/round33-control-ctest.log`、`build/round33-control-last-test.log`。53 个 relay 场景包括 12 个限速终止、10 个带真实异步等待的阻塞读取、18 个实际 loopback TCP，以及原有 13 个首包/分配失败行为。TCP 外部取消和父取消约 50 至 65 ms 返回；读/phase 超时约 1 秒。idle 测试预先接收数据，既有惰性活动检查会在第一次检查时续调，因此约 2 秒到期，测试按该真实策略验证，未将其改为精确空闲一秒。UDPChannel 的两个新增场景在约 19 秒额度等待之前以取消或 phase 超时结束，成功发送及统计均为零。大超时、无限速取消、限速取消和终止错误明细均有行为断言。

最终完整构建为 `build/round33-build.log`，全量回归为 `build/round33-ctest.log` 与 `build/round33-last-test.log`。原生结果在 `build/round33-initial-integration/`、`build/round33-udp-regression/`、`build/round33-tls-relay-regression/`、`build/round33-tls-pool-regression/`，日志为同名目录加 `.log`；逐项验证了 12/7/6/2 个结果及空的 peer_errors，共 27 项，独立于 CTest。gRPC/XHTTP 会话通知迁移已完整编译，但未增加对应传输的真实网络取消探针。TCP 直接 relay 验证也不代表面板下发限速的完整配置路径已覆盖。环境仍为 Windows，Linux 和此前列明的真实上游互操作范围未扩大。原工作区仍仅有原 `.codex/`，未提交、推送或部署。

第三十四轮基线为 `build/round34-baseline-build.log` 和 `build/round34-baseline.log`，通过 `cnode_relay_initial_payload_test --source-cancellation` 直接执行旧 relay：活动子流取消、活动子流资源不足、启动前已取消、启动前资源不足四项分别约 3,003/3,013/3,014/3,003 ms 返回，均已上送 4,000 字节，结果全部为 CANCELLED。后两项显式保留待交给 relay 的拥有型首包，证明只补订阅仍会漏掉先前终止。`build/round34-source-regression.log` 记录修复后的约 65/63/0/0 ms 和零成功字节，并正确保留资源不足。

修改前源码备份在 `build/round34-before/`，迁移脚本为 `build/round34-migrate.py`、`build/round34-owned-sources.py`。公开旧 CancellationEvent 类型已由 CancellationSource 完整替换；测试入口为 `tests/cancellation_source_test.cpp` 和 `cnode_cancellation_source_test`，未保留别名或旧 CMake 目标。MultiBufferReader 必须提供取消来源，VLESS pending/UDP/Vision/encryption、VMess、Shadowsocks、Trojan UDP、UoT 等 framing reader 委托底层来源；Mux TCP/UDP、AnyTLS 入站子流及原生 UDP ClientSession 自持终止状态。Link 的 reader 自身携带此契约，不增加协议特判或另一条请求链路，也不依赖可空的 AsyncStream control 才能通知 relay。

取消源仍为 Worker-local、无锁且稳定地址。CancelPending 不影响后来开始的操作；Stop 保留首个非 OK 终止原因，普通关闭以 CANCELLED 表示，后来订阅在显式 Resubscribe 时同步收到终止通知。CancellationSubscription 是内嵌、不可复制或移动的监听者基类，以具名 OnCancellation 实现交付，不保存通用函数指针或 void* 上下文；派生字段必须先完成初始化再订阅，受保护析构不允许经基类删除。Unsubscribe 显式撤销当前注册，source 析构只解除注册而不通知。监听者可在 OnCancellation 中 Resubscribe；gRPC/XHTTP 会话组合在临时取消时先重新订阅再转发，永久终止则同步传播且不重开。`tests/cancellation_source_test.cpp` 在禁止普通 new 的作用域内覆盖终止前后订阅、重复 Stop、四次独立临时取消转发和订阅前已关闭的来源；保留批次重入、自身/同伴删除与事件源先销毁场景，并增加显式撤销、跨源重新注册和通知期间销毁来源场景。第三十四轮针对性构建及测试记录为 `build/round34-focused-build.log`、`build/round34-focused-ctest.log` 和 `build/round34-focused-last-test.log`，不代表后续监听者 API 迁移的验证结果。

新脚本 `tests/substream_cancellation_integration.py` 启动 loopback HTTP 面板、真实 cnode 和 TCP 目标。面板下发 id=1、固定测试 UUID、speed_limit=1，经 api -> RuntimeUser -> UserSet -> UserStore -> 入站认证进入普通 Dispatcher/outbound/relay。该 API 的 1 Mbps 按既有定义换算为 131,072 bytes/s。VLESS Mux 和 AnyTLS/TLS 各发送三批 60,000 字节：先确认前两批已到目标，再确认第三批仍在限速等待；注入非法会话帧，目标随子任务取消关闭，第三批未发送。另两项用正常逻辑 FIN，目标在约 0.313/0.328 秒后收齐 180,000 字节再关闭，证明永久终止未污染正常半关闭语义。触发前断言目标尚未关闭，避免把意外提前断连当成成功。会话失败的耗时落在同一个 Python 时钟刻度内，不把输出 0.0 解释为零延迟性能结论。

新网络结果位于 `build/round34-substream-integration/` 和加强触发前断言后的 `build/round34-substream-reviewed/`，各有四项逐字节/hash 结果及面板用户请求计数。最终完整构建为 `build/round34-build.log`，回归为 `build/round34-ctest.log`、`build/round34-last-test.log`；既有原生结果在 `build/round34-initial-integration/`、`build/round34-udp-regression/`、`build/round34-tls-relay-regression/`、`build/round34-tls-pool-regression/`，同名 `.log` 保存过程输出。31 个原生结果均独立于 CTest，逐项检查 passed 和空的 peer_errors。`build/round34-validation.json` 记录二进制及证据哈希。

本轮扩大到真实面板限速的 Mux/AnyTLS 上行取消与正常 FIN，未验证 gRPC/XHTTP 实际网络上的重复取消或同一物理连接内的子流隔离。原生 UDP 入站退役时的来源传播已迁移并完整编译，但没有新增对应退役的原生网络探针。取消发生在 DNS、出站连接或握手期间是否及时结束，也不由已进入 relay 的测试证明。环境仍为 Windows，Linux 及此前列明的其他真实上游互操作限制保持不变。原工作区仍仅有原 `.codex/`，未提交、推送或部署。

第三十五轮将 Mux 的 client_reader_loop、帧处理循环和动态 TCP/UDP dispatch 纳入 `src/common/awaitable_task_group.hpp/.cpp` 的有限任务组。任务组只处理协程所有权和取消，不理解协议、session、路由、面板或 relay；每个子请求继续走唯一 Dispatcher 链路。任务组在启动任何子协程前取得最终完成 continuation，启动哨兵防止部分启动时提前恢复父作用域，子请求在真正的 co_spawn 完成回调内归还所有权。每个子任务有独立取消信号，Worker-local 链表在通知前摘除节点，避免重入时继续遍历已释放节点。父任务取消和未捕获失败停止任务组，不再接受新任务，并等待已启动任务结束；首个失败不会被清理引起的伴随取消覆盖。

Mux 保留 active_sub_loops 作为正常 EOF 的业务排空计数，生命周期等待由任务组完成。删除读取 done_signal、sub_done_signal、WakeDone、两个事后等待循环和一次 net::post；Mux 中已没有 detached 或直接 co_spawn。正常帧循环结束时先停止队列和物理读取，再取消子流，任务组在释放 sub_sessions 和队列前收齐所有完成。控制面既有 RunAwaitableBatch 的“延迟取消、等待全部有限操作完成”语义保持独立，本轮不改动其调用者。

`tests/awaitable_task_group_test.cpp` 验证运行中追加子任务、父取消后仍需完成 15 ms 异步清理、启动回调或子任务失败时自行取消等待者、保留最初异常，以及子任务和调用者分别恢复到指定执行器。故障注入同时覆盖普通 new 和 Asio 的实际 aligned_new 路径，关闭 awaitable frame recycling；扫描 21 个分配失败点，其中 8 个有部分子任务已经启动。失败轮不由测试额外唤醒等待者，必须由任务组自行取消并收束；仅成功轮由测试打开闸门。定向证据为 `build/round35-focused-build.log`、`build/round35-focused-ctest.log`、`build/round35-focused-last-test.log`。未新增全进程持续 OOM 或操作系统分配失败测试，不将该扫描扩大解释为所有内存故障都已覆盖。

完整构建为 `build/round35-build.log`；第一次构建发现私有头文件相对路径不匹配，修正后重新完整构建通过，初次输出保存在 `build/round35-build-include-failure.log`。全量回归为 `build/round35-ctest.log` 和 `build/round35-last-test.log`。原生结果位于 `build/round35-initial-integration/`、`build/round35-udp-regression/`、`build/round35-tls-relay-regression/`、`build/round35-tls-pool-regression/`、`build/round35-substream-reviewed/`，分别核对 12/7/6/2/4 个 passed 与空 peer_errors。31 项均独立于 CTest。Mux 会话失败只发送前 120,000 字节，正常 FIN 完整发送 180,000 字节后结束；协议字节和 hash 与既有预期一致。修改前 Mux 与 CMake 源码位于 `build/round35-before/`；`build/round35-validation.json` 保存二进制及验证证据哈希。

本轮直接验证通用任务组的取消与失败所有权，以及真实 Mux 成功、异常帧退出和逻辑 FIN；未在完整 cnode 进程内注入 Mux 分配失败，未新增多 Worker 压测或 Linux 验证。DefaultDispatcher 的来源取消在 DNS/出站握手阶段是否及时传播仍未解决；AnyTLS 入站仍以 detached 启动子请求，并在 FinishRun 中 CancelAll 后通过计数和 timer 等待，需要后续迁移。原工作区仍仅有原 `.codex/`，未提交、推送或部署。

第三十六轮基线为 `build/round36-baseline-build.log` 与 `build/round36-baseline.log`。测试直接链接真实 AnyTLS Handler、codec、协议凭据、Validator、UserStore 和注册工厂，以受控 AsyncStream 提供认证及两条 SYN/PSH 请求；通用 Dispatcher 测试实现停在可取消的异步 timer，模拟尚未订阅逻辑来源的 DNS/拨号阶段。旧实现收到父取消后 Handler 已返回，active-at-return=2、finished-at-return=0；非法会话帧则在观测窗口内没有返回，也未唤醒两个等待者。测试在记录后主动放行旧子请求并等待完成，保留所有借用对象以避免为了复现而制造悬空访问。此证据证明退出/取消边界问题，不是对真实 DNS resolver 或真实出站握手的故障注入。

AnyTLSDemuxSession::Run 现在先建立有限任务组，任务组内的帧循环调用 ReadFrames，并将动态 TCP/UoT dispatch 注册到同一组。正常会话结束先 CancelAll，再显式取消任务组；异常结束先停止物理/逻辑输入，由任务组记录首个异常并取消其余任务，最后收齐完成回调。AwaitableTaskGroup::Cancel 允许会话主动停止所有 Asio 子任务，重复调用保持幂等，之后 Spawn 被拒绝；单独停止逻辑 CancellationSource 无法覆盖尚未进入 relay 的异步等待，因此 Mux 的整体退出路径也增加同一调用。控制面 RunAwaitableBatch 继续保留原来的有限批量语义。

Handler 协程直接持有 AnyTLSDemuxSession 值对象；AnyTLSSubStream 对父会话使用同一 Worker 的非拥有引用，生命周期由上述 join 边界覆盖。子流本身仍由索引表和活动请求共同持有，保证关闭或移除索引后已经启动的请求仍能完成清理。父/子两处 enable_shared_from_this、相互 shared_ptr 持有、active_dispatches_、dispatch_completion_、CompleteDispatch、WaitForDispatches、FinishRun、detached 与对应 include 均已删除，同时删除未被调用的 PushInput 单参数重载。Mux 删除未使用的 awaitable_operators using，独立测试编译不再依赖预编译头提供它。

最终测试入口为 `tests/substream_inbound_lifecycle_test.cpp` / `cnode_substream_inbound_lifecycle_test`，初始化阶段临时使用的 anytls_inbound_lifecycle 文件和 CMake 入口已完整改名。九个场景包括 AnyTLS 父取消、非法会话帧、物理 EOF、收到第三条 SYN 后实际子流创建分配失败、父取消时物理写入与另一子流写入锁阻塞、会话失败时同样的写入阻塞，以及 Mux 父取消、非法会话帧和物理写入阻塞。每项都先证明两条请求已经在执行；取消后的测试 Dispatcher 保留 20 ms 异步清理并继续读取所借用的 context，最终返回时 active=0、finished=2，transport 已析构、挂起读写均归零，AnyTLS 在线设备租约已经释放。父取消与协议错误的返回分类单独核对，伴随取消不能覆盖会话的原始协议错误。该测试仅替换外部 AccessLogSession sink，不验证集中日志提交，原生网络测试仍执行真实生产日志路径。

`tests/awaitable_task_group_test.cpp` 新增主动 Cancel、重复 Cancel、停止后拒绝新任务，以及主动停止仍保留正常父结果的验证。普通 new 与 Asio 实际对齐分配路径原有扫描继续覆盖 21 个失败点、8 个部分启动。AnyTLS 的单次分配故障另在 SYN header 返回后触发普通 new，检查父作用域保留 bad_alloc 且等待已有两个子请求完成；未模拟持续全进程 OOM。定向输出为 `build/round36-focused-ctest.log`、`build/round36-focused-last-test.log`，最终生命周期目标构建为 `build/round36-lifecycle-build.log`，所有最终代码另通过完整构建和全量 CTest。

完整构建为 `build/round36-build.log`，全量结果为 `build/round36-ctest.log` 和 `build/round36-last-test.log`。原生结果位于 `build/round36-initial-integration/`、`build/round36-udp-regression/`、`build/round36-tls-relay-regression/`、`build/round36-tls-pool-regression/`、`build/round36-substream-reviewed/`，逐项核对 12/7/6/2/4 个 passed 以及空 peer_errors；31 项独立于 CTest。Mux/AnyTLS 面板限速时的会话失败仍只上送 120,000 字节，正常逻辑 FIN 则完整排空 180,000 字节。相关源文件改动前快照位于 `build/round36-before/`，`build/round36-validation.json` 保存二进制及证据哈希。

本轮验证的是整个容器会话退出的取消和所有权；单独逻辑子流在 Dispatcher 嗅探/DNS/握手期间的来源停止边界仍待继续审查。未新增 AnyTLS UoT 的真实网络探针、Linux 验证或多 Worker 压测。相邻状态机仍发现重复 SYN 会通过 GetOrCreateStream 复用已有子流并将状态重新设为 PendingTarget，需要下一轮复现是否形成共享同一 context 的并发 dispatch；协议版本协商和 FIN 行为也不能仅凭现有回归认定完全符合规范。原工作区仍仅有原 `.codex/`，未提交、推送或部署。

全量 CTest 首次有一项失败：protocol_public_surface_contract_test 仍强制要求 AnyTLS 源码包含 WaitForDispatches 和 active_dispatches_。本轮将该架构契约同步迁移为禁止旧计数等待、detached 及父子循环持有，并检查 AnyTLS/Mux 经任务组启动、取消和 join 子请求。`build/round36-contract-ctest.log` 与 `build/round36-contract-last-test.log` 记录该项补测通过。产品二进制没有再修改，因此保留首次全量的其他 111 项通过结果和 31 项原生结果，不把补测描述为第二次完整 112 项运行。

第三十七轮基线 `build/round37-baseline.log` 直接复现重复活动 ID 启动两个 Dispatcher、发生 active context 重叠，并在异步清理中发现 conn_id/目标端口已改变；重复待解析 ID 会被旧实现接受，完成后的 ID 也能再次启动请求。旧产品的测试二进制保存在 `build/round37-baseline-lifecycle.exe`。新实现对 SYN 统一验证设置握手、非零且大于历史最大 ID、无数据；历史最大 ID 不随子流移除而回退，递增间隔不要求连续。异常 SYN 尝试写 Alert 后按协议错误退出，任务组负责取消并 join 已启动的请求。

`StreamEntry` 将 AnyTLSSubStream 与接收阶段放在同一个共享对象中；索引查找仅返回拥有所有权的条目，Dispatcher 使用指向内嵌子流的 aliasing shared_ptr。即使子请求在读取下一帧 payload 的 await 中退役，读取协程仍持有有效条目，后续数据不能复活已关闭的来源。删除 `stream_states_`、`GetOrCreateStream` 及跨 await 使用的索引 iterator。目标解析前收到 FIN 会立即移除待处理条目；已启动请求保留既有正常 FIN 排空语义。

身份测试覆盖活动/待解析 ID 重复、完成后的 ID 重用、倒退、零、SYN 携带数据、UINT32_MAX 回绕、合法不连续递增、目标解析前 FIN 和读取 payload 期间请求退役。十项均无 context 重叠或异步改写；原九个容器生命周期场景也继续通过。`tests/anytls_identity_integration.py` 使用真实面板、cnode TLS 入站和 TCP 目标：三种非法 ID 只建立原来的一条目标连接，收到 Alert 后物理会话结束；合法 ID 7→19 建立两条目标连接，分别完整传送 20/21 字节并核对 SHA256，FIN 后 heartbeat 仍有回应。所有 Python 对端任务均有取消与 join，四项 peer_errors 为空。

协议依据为 2026-09-10 核对的 [AnyTLS 官方协议](https://github.com/anytls/anytls-go/blob/main/docs/protocol.md)，其客户端 ID 递增约束用于拒绝不符合约定的 SYN。同期 [参考实现 session.go](https://github.com/anytls/anytls-go/blob/main/proxy/session/session.go) 对重复活动 ID 选择忽略，不重置已有流；本轮采用更严格的错误拒绝，不能描述为与参考实现处理方式完全相同。下载的只读参考文本保存在 `build/round37-upstream-session.go`；协议版本和所有 FIN 细节仍未完成一致性审查。

完整构建和全量 CTest 输出分别为 `build/round37-build.log`、`build/round37-ctest.log`、`build/round37-last-test.log`。独立原生回归目录 `build/round37-{initial-integration,udp-regression,tls-relay-regression,tls-pool-regression,substream-reviewed,identity-integration}/` 的 results.json 分别核对 12/7/6/2/4/4 个 passed 与空 peer_errors。`build/round37-validation.json` 保存二进制、基线、测试和参考文本哈希。原工作区仍仅有原 `.codex/`，未提交、推送或部署。

回归之后另做的 `build/round37-coalesced-probe.py` 将地址与第一批 20 字节放进同一 PSH，真实 TLS 探针超时，目标连接数为零；结果位于 `build/round37-coalesced-probe/results.json`。同一身份脚本用两个 PSH 分开发送时通过。源码显示 PendingTarget 在解析地址后 clear 整个 payload，丢弃了后续数据；零建连与 Dispatcher 嗅探等待相符，但此探针没有单独观测 DNS/嗅探内部状态。该失败作为下一轮未解决问题保留，不计入上述 35 项通过回归。

第三十八轮先保存上一轮产品为 `build/round38-baseline-cnode.exe`，哈希与第三十七轮验证清单一致。`tests/anytls_stream_parsing_integration.py` 在旧产品上分别发送“SOCKS 地址 + 60,000 字节同一 PSH”和逐字节地址，二者均在等待目标/回显时超时，未建立目标连接；结果位于 `build/round38-parsing-baseline/results.json`。这补齐第三十七轮探索失败的稳定回归，未使用改后的产品冒充旧基线。

AnyTLS 会话在合法 SYN 时构建独立 context、发布子流索引并注册 RunStream 任务；ReadFrames 仅处理会话控制、完整读出 PSH 并移交对应子流、以及逻辑 FIN。ProcessStream 从 MultiBufferReader 读取逻辑字节流，ReadSocksTarget 只复制最多 259 字节的地址前缀，消费准确的前缀长度；同帧剩余数据和后续队列的数据顺序保持。TCP 使用 InitialPayload 的显式 MultiBuffer 移动构造转交剩余数据，UoT v1/v2 直接继续解析同一 pending 缓冲。仍只有 Dispatcher -> outbound -> relay 的请求链路，没有预先发送用户首包。移除 MultiBufferByteReader、ParseSocksAddress、StreamEntry、StreamState、PendingTarget/PendingUotRequest、SpawnDispatch/RunDispatch/StartDispatch 及帧循环内的子请求失败构造逻辑。

解析过程与 Dispatcher 一起受有限任务组管理。错误/截断地址只对当前子流记录失败并尝试 FIN，随后移除索引，另一子流仍可完成；整个会话终止仍取消并 join 所有等待地址、UoT 或 dispatch 的任务。源对象所有权跨 await 保留，严格递增 ID 不回退；不存在跨 await 借用可能被其他子任务删除的索引 iterator。目标只在子任务内归一化一次，普通 TCP 必须满足现有 TargetAddress 校验，UoT magic address 仍允许零端口。

真实 Handler 测试新增十一项：60,000 字节同帧首包、IPv4/IPv6 逐字节地址、253 字节合法 DNS 名、非法类型、空域名、普通目标零端口、地址中途 FIN、等待地址时父取消，255 字节无效域名，以及非法 UoT v2 connect 标志。四条合法请求核对完整首包，其余七项均未进入 Dispatcher，并在退出前完成解析任务清理；原来的十九项生命周期/身份测试保持通过。新增缓冲测试在禁止分配的作用域内接收和交出 9,000 字节 MultiBuffer，核对原缓冲指针和完整字节，验证 TCP 剩余数据转交没有额外分配或 payload 拷贝。一次定向失败来自测试最初将 255 字节单标签误当合法 DNS 名；保留 `build/round38-invalid-domain-fixture-ctest.log`，改用现有 DNS 规则允许的 253 字节分段名称，并另保留 255 字节拒绝场景，未放宽产品校验。最终增加日志观察后定向 4/4 通过见 `build/round38-logging-focused-ctest.log`。

首次全量 CTest 为 111/112，唯一失败的 protocol_access_log_contract_test 仍要求旧 report_predispatch_failure/report_child_creation_failure。核对后将契约改为检查 ProcessStream 的原始错误返回、RunStream 的单一失败上报、context 在任务注册前构建及准入失败分类；并补回任务注册发生 bad_alloc/异步取消/其他异常时的子流失败记录，之后交由容器取消并 join。Handler 测试的外部 AccessLogSession sink 现在用固定容量观察数组，验证六条已结束的非法 TCP/UoT 请求恰好记录一次，保留 stream_id、TCP/UDP 分类和原始错误；等待地址的父取消另核对作用域收束。该观察不替代集中日志上传端到端验证。测试观察字段最初误用 uint32_t，编译器拒绝 session 的 uint64_t stream_id 收缩转换；已按真实类型修正，初次输出保存在 `build/round38-logging-fixture-type-build.log`。初次全量证据保存在 `build/round38-initial-full-ctest.log` 与 `build/round38-initial-full-last-test.log`；补齐产品日志后重新完整构建、完整运行 112 项 CTest，并用最终二进制重新执行全部 48 项原生回归，最终结果没有沿用修改前二进制。

十三项新增原生测试使用真实面板用户、TLS AnyTLS 入站、Freedom 和本地 TCP/UDP 目标。IPv4/IPv6 同帧及跨帧各校验 60,000 字节双向 SHA256；交错场景先让子流 1 只发送两字节地址，子流 2 仍完成 60,000 字节，再补齐子流 1 并完成 17,000 字节。非法/截断子流收到 FIN 时另一子流仍正常。UoT v1、v2 connect、v2 packet 各有同帧与跨帧组合，目标收到两个独立的 9,000/19,999 字节 UDP 包；返回编码逐字节核对，包含目标 metadata 和包长度。每项结束前 heartbeat 均有回应，peer_errors 为空。不同测试临时 UDP 端口不同，所以携带地址的完整回复 hash 允许不同，真实 payload 的两个 hash 固定且一致。

全量构建、CTest 和最终原始测试输出位于 `build/round38-build.log`、`build/round38-ctest.log`、`build/round38-last-test.log`。原生结果目录 `build/round38-final-{initial-integration,udp-regression,tls-relay-regression,tls-pool-regression,substream-reviewed,identity-integration,parsing-integration}/` 分别验证 12/7/6/2/4/4/13 项，共 48 项，独立于 CTest。`build/round38-validation.json` 保存产品、旧产品、回归、失败基线和下一轮探针哈希；`build/round38-before/` 保留本轮修改前相关源码。AGENTS 和 README 已同步逻辑字节流职责。没有 Linux 验证、多 Worker 压测或持续全进程 OOM 故障注入；原工作区仍仅有原 `.codex/`，未提交、推送或部署。

相邻版本审查另发现：入站仅解析 padding-md5、无条件发送 ServerSettings/SYNACK，出站以子串 find("v=2") 判断版本。`build/round38-version-probe.py` 对真实 TLS 入站声明 v=1，在完整收到 60,000 字节回显后，记录到 cmdServerSettings(10,0) 和 cmdSYNACK(7,1)，探针因此失败。2026-09-10 复核的 [AnyTLS 官方协议](https://github.com/anytls/anytls-go/blob/main/docs/protocol.md) 明确仅双方支持 v2 才启用这些功能，v1 客户端应禁用 v2 特性。此问题尚未修改，结果保存在 `build/round38-final-version-probe/results.json`，不计入 48 项通过回归。

第三十九轮保存 `build/round39-baseline-cnode.exe`，哈希与第三十八轮最终验证清单一致。`tests/anytls_negotiation_integration.py` 对旧产品声明 v=1，仍收到 ServerSettings(10,0) 和 SYNACK(7,1)；另一场景由本地 TLS 服务器声明 note=v=2\nv=1，第一条 VLESS 请求成功、复用同一 TLS 的第二条请求却因错误启用 SYNACK 等待而失败。对端已记录 stream ID [1,2]，peer_errors 为空；证据位于 `build/round39-negotiation-baseline/results.json`。这两个场景使用与最终回归相同的客户端/服务器脚本，分别覆盖入站错误功能启用和出站子串误判。

协议私有 codec 新增 ParsePeerSettings：按完整行和第一个等号识别精确的 v、padding-md5 键；未知有效键忽略，CRLF 与空行允许。版本必须是完整的非零 uint32 十进制值，拒绝尾随字符、符号、空白、溢出、重复版本键和重复 padding 摘要键。缺失 v 时按 v1 处理；有效未来版本与本地支持上限相交，归一化为 SessionVersion::V1/V2。PeerSettings 及摘要字符串只在握手处理时存在，入站和出站会话均只保留 optional<SessionVersion>，不常驻原始设置或握手摘要。协商值只发布一次，普通请求直接消费确定的能力，不再在帧循环中推断版本。

入站仅在协商为 v2 时发送 ServerSettings、每个 SYN 对应的 SYNACK 和心跳响应；客户端在设置前创建流、重复设置、发送服务器方向命令、以非零 ID 发送会话设置或使用未协商的心跳时，发送 Alert 并结束会话。出站收到 ServerSettings 前使用 v1 能力，精确解析服务器版本后再决定复用请求是否等待 SYNACK；错误设置、重复设置、错误 ID/方向及未协商的 v2 控制帧会关闭物理会话并唤醒逻辑请求。删除 ParseSettingsPaddingMd5、handshake_done_、peer_version 字节存储和 find("v=2")。DefaultClientSettings 从同一支持版本常量生成版本，并声明真实 client=cnode，继续携带默认 padding 摘要。

2026-09-10 核对的 [AnyTLS 官方协议](https://github.com/anytls/anytls-go/blob/main/docs/protocol.md) 规定双方支持 v2 时才启用新增功能；v1 客户端应禁用 v2 功能，客户端尚未收到服务器版本时也保持 v1 行为。单次 settings、重复已知键拒绝及 uint32 数值上限是本实现用于固定会话状态和消除歧义的明确约束，不能扩大表述为规范逐字要求；未知扩展键保持可忽略。更严格的状态验证不保留会话内重新协商或子串识别的旧行为。

三十个 codec 检查包括缺失版本、v1/v2/未来版本、20/256/UINT32_MAX、CRLF、空行、未知字段中的伪版本、重复键、非法字符、整数溢出、嵌入 NUL，以及本地版本、client 名和默认摘要一致性。原三十个真实 Handler 生命周期、身份、目标/UoT 解析场景继续通过。十五个原生入站场景覆盖正常及非法协商、已活动请求期间重复设置、错误方向、错误 ID 和未协商心跳；十二个原生出站场景覆盖未收到服务器声明、v1/v2/未来版本、伪版本字段、非法版本与复用期间重复设置。有效场景均在同一 TLS 连接上完成 stream ID 1 和 2；v2 对端还分别验证两次心跳响应，v1 对端不依赖 ACK。非法出站协商要求真实对端观察连接关闭且请求在两秒内失败，不能以测试超时当作拒绝成功。

最终构建及全量证据为 `build/round39-build.log`、`build/round39-ctest.log`、`build/round39-last-test.log`。原生结果目录 `build/round39-{initial-integration,udp-regression,tls-relay-regression,tls-pool-regression,substream-reviewed,identity-integration,parsing-integration,negotiation-integration}/` 分别核对 12/7/6/2/4/4/13/27 项 passed 与空 peer_errors，总计 75 项，独立于 CTest。构建前的定向回归为 `build/round39-focused-ctest.log`；随后进一步收窄会话存储，并使用最终二进制完整重建、全量验证及全部原生回归。修改前源码位于 `build/round39-before/`，`build/round39-validation.json` 保存最终源文件、测试、二进制及旧基线哈希。AGENTS 和 README 已同步职责与状态约束。

本轮完成版本协商，不将这些结果解释为 AnyTLS 全部 FIN 语义、子流握手资源界限或所有物理会话协程所有权均已证明。未新增 Linux、多 Worker 压测或持续 OOM 注入；原工作区仍仅有原 `.codex/`，未提交、推送或部署。

第四十轮先将第三十九轮最终产品复制为 `build/round40-baseline-cnode.exe`，哈希与上一轮清单一致，并保留修改前 Dispatcher 源码及使用旧实现构建的新测试程序。`build/round40-baseline-dispatcher.log` 记录 28 个场景，其中 20 个失败、8 个通过：已停止的读端仍返回 OK 并调用出站；逻辑取消后嗅探、握手和 pending 等待未及时结束，需要夹具额外发出父取消收束；路由 DNS 收到父取消后仍执行 handler 查找。嗅探将 bad_alloc 和 LinkError(RESOURCE_EXHAUSTED) 都改写为 SOCKET_READ_FAILED。旧实现失败证据独立保存，不计入最终通过数量。

DefaultDispatcher 继续保留唯一 Dispatch -> outbound.Process -> relay 链路，在内部复用已有有限 AwaitableTaskGroup 持有一次完整请求。实际 reader 的 CancellationSource 订阅在请求子协程内创建，订阅的回调只取消这一请求的任务组；它在子协程退出前撤销，所借用任务组此时仍由完成回调持有，避免父协程等待恢复期间留下悬空回调。提前停止的 reader 在订阅时同步报告原始原因，直接返回且不执行路由或出站。父取消、逻辑取消与启动失败均沿既有 cancel/join 实现收束；请求负载计数和 AccessLogSession 的作用域覆盖实际完成。该处理没有新增协议分支、公开生命周期 wrapper 或第二条请求链路，也不要求存在 AsyncStream control。

路由 DNS 返回后立即读取 Asio cancellation_state；如果已经取消，先抛出 operation_aborted，再进入原有通用错误处理，不再改写解析 metadata、继续规则选择或查找 handler。这个检查是必要的，因为 DNS 的失败结果和协程取消并非同一返回通道。由逻辑取消产生的 CANCELLED 恢复为来源原始原因；嗅探显式保留 LinkError，bad_alloc 到达通用 RESOURCE_EXHAUSTED 边界。成功 relay 的结果仍保持成功：正常 Cancel/Close 也会通知入站来源，不能单凭曾收到通知覆盖已完成结果。原本的 relay 读失败分类也继续保留。

新增 `tests/dispatcher_cancellation_test.cpp` 使用真实 DefaultDispatcher、DNS 和 DoRelayLink；仅替换外部日志上传 sink，以及用于精确控制等待的通用入站/出站端点。30 个场景分别覆盖带控制端的拥有型流和无控制端的借用型逻辑流：提前 Stop、嗅探等待、出站握手等待、真实 loopback UDP DNS、父取消、CancelPending、正常直通/relay、relay 读失败、嗅探内存不足和 LinkError，以及 RESOURCE_EXHAUSTED 原因保留。取消后的受控等待额外异步清理 20 毫秒，验证请求负载仍存活，返回时 active 为零、终态只记录一次；借用读端返回后再次通知也不再调用旧订阅。最后两项让同一 Dispatcher 上的两个请求同时等待，取消其中一个，另一个正常完成。真实 DNS 使用 127.0.0.42:53 并确认确有查询数据，本次两个 DNS 场景均执行、未跳过；无绑定低端口权限的平台会明确报告跳过该网络场景。

最终全量构建为 `build/round40-build-final.log`，CTest 完整输出为 `build/round40-ctest.log` 和 `build/round40-last-test.log`。新增测试的首次链接缺少 TLS SNI parser 源文件，已补齐；主程序构建又发现夹具的额外 src include 路径掩盖了私有头路径问题，随后统一为相对私有路径并删除夹具的额外 src 搜索路径。修正后使用最终代码重新完整构建并运行全部验证；前面的失败日志继续保留。原生结果目录为 `build/round40-{initial-integration,udp-regression,tls-relay-regression,tls-pool-regression,substream-reviewed,identity-integration,parsing-integration,negotiation-integration}/`，分别 12/7/6/2/4/4/13/27 项，共 75 项 passed，peer_errors 为空，各进程 exit 0。AGENTS 与 README 同步完整请求取消、订阅寿命及正常收尾语义；`build/round40-validation.json` 保存基线、最终源文件、测试和二进制哈希。

本轮证明通用取消边界和所列可控故障；新的握手用例使用通用测试出站，不能扩大为已对每一种实际协议握手逐项完成故障注入。既有 75 项原生协议回归全数重跑，但没有新增 Linux、多 Worker 压测、持续 OOM 或生产验证。AnyTLS 出站物理 ReadLoop 的退役/join，以及完整 FIN 语义和待解析子流资源界限仍待独立审查。原工作区仍只有原 `.codex/`，未提交、推送或部署。

第四十一轮确认物理读取不借用单条请求 Context，因此会话在请求之间继续读取控制帧是需要保留的职责。实际缺口是 Process 以 detached 启动 ReadLoop，完成与未捕获异常均未被会话池观察。新的真实 Handler 测试先在旧实现上运行：活动请求处理 ServerSettings 时注入一次 codec 协程/字符串分配失败，请求在 180 毫秒观察窗口内未完成，需要额外父取消收束；另一次先完成正常请求，再在空闲 UpdatePaddingScheme 读取时注入同类故障，后续请求仍使用唯一一条物理连接并失败。两项分别保存在 `build/round41-baseline-lifecycle-final.log` 的 mode 0/1。mode 2 的退役延迟清理本来就通过，不能据此声称旧实现已证实存在释放后访问。旧产品、测试程序和源码另存于 `build/round41-baseline-cnode.exe`、`build/round41-baseline-lifecycle-test.exe`、`build/round41-before-{anytls_outbound.cpp,session_pool.hpp}`；产品哈希与第四十轮最终清单一致。

SessionPool::Adopt 现在统一启动每个物理 Session 的 Run，完成回调同时拥有池 State 和 Session；根协程中的读取、帧解析、控制写入和门闩只能借用该 Session 自有状态及所属 Worker 的寿命依赖。回调处理未捕获 bad_alloc、I/O 和其他异常，保留 RESOURCE_EXHAUSTED 等分类；任何已经返回或抛出的物理任务都关闭其会话、通知逻辑请求并从索引移除，不能再借出。异常诊断仅使用池 tag 和错误码，不借用请求 Context，日志异常不会绕过关闭。正常退休的 CANCELLED 不额外打印任务失败警告。

ClientSession::CloseAll 在首次关闭时取消物理协程的 Asio cancellation signal，同时终止写入门闩、逻辑请求和 transport。Process 中的 co_spawn、detached、read_loop_started 及手动启动分支已删除；物理任务由池管理，有限逻辑请求仍按原请求/relay 范围完成。Remove 在删除索引前保留关闭对象的拥有引用；整体 Retire 先移出所有索引条目，再广播关闭，避免回调与被遍历索引相互干扰。池门面销毁及索引移除只表示停止接纳与发出取消，并非同步 join：显式物理根任务继续持有自身全部 I/O 状态，直到 co_spawn 的实际完成回调退出。没有把请求专属数据延长到空闲期，也没有为常驻物理任务增加协议外公开 wrapper、Worker 特判或第二条请求链路。

`tests/anytls_outbound_lifecycle_test.cpp` 只替换外部 DialOutboundTransport，运行生产 target builder、Handler、codec、SessionPool、logical endpoint 和 relay。最终四项检查包括活动 settings 分配异常、空闲 padding 更新异常后重新拨号、Handler 退役时后台读取额外异步清理 20 毫秒，以及认证写入后已到达的早期 settings 异常；对应期望为原始 RESOURCE_EXHAUSTED、失效会话不复用、无在途读取时才析构 transport。后续正常请求仍完整收到 reply。测试夹具本身的 DNS 初始配置缺少 server 曾报错，补齐 loopback server 后才执行旧实现对照；目标地址为 literal，未把该夹具表述为新增 DNS 网络测试。

会话池原有空闲回收、最小空闲数、占用租约、旧定时回调和独立 Worker 检查改为运行真实异步 Session::Run。新增物理任务失败与其他会话隔离、退役后异步清理，以及 32 次启动故障点尝试，最终触发 8 次分配失败、24 次成功，所有弱引用在操作结束后释放。初次仅覆盖 operator new 时，Asio 的 Windows 对齐分配未被注入，只有一个故障点，因此检查失败；随后把原任务组专用工具完整迁移为 `tests/async_allocation_fault.hpp`，覆盖普通分配及 Asio aligned_new，并在这些测试中关闭协程帧缓存。两个调用方和 CMake 强制 include 同步迁移，删除旧文件/命名；原任务组 21 次故障及 8 次部分启动仍通过。该注入覆盖单次分配失败恢复，未声称验证持续全局 OOM。

最终全量 Release 构建为 `build/round41-build.log`，完整 CTest 为 `build/round41-ctest.log`、`build/round41-last-test.log`，定向验证为 `build/round41-focused-final-{ctest,last-test}.log`。池单元测试最初缺少新异常映射依赖 error.cpp，已补入 CMake；构建和故障注入检查的中间失败日志继续保存，最终产品及所有测试重建后重新全量验证。八组原生输出目录 `build/round41-{initial-integration,udp-regression,tls-relay-regression,tls-pool-regression,substream-reviewed,identity-integration,parsing-integration,negotiation-integration}/` 分别验证 12/7/6/2/4/4/13/27 项，共 75 项 passed、peer_errors 为空、进程 exit 0。AGENTS、README 和公开表面契约同步任务所有权及旧入口删除；`build/round41-validation.json` 保存全部关键文件哈希。

本轮未改变进程立即退出策略，不把池门面退役等同于新的全局优雅关停接口；也未新增真实网络 OOM、Linux 或压力测试。原生 TLS、空闲复用及协议回归保持通过，不能扩大为所有 FIN 语义、全部控制帧数量/大小限制或入站待解析子流期限均已证明。原工作区仍只有原 `.codex/`，未提交、推送或部署。

第四十二轮先用第四十一轮产品运行新增真实 TLS 测试。`timeouts.handshake=1` 时，仅发送 SYN、随后每 100 毫秒发送心跳，旧版本在 1.7 秒观察窗口内没有结束该子流；另一项先创建 128 条待解析流，再发送第 129 条，旧版本在 0.5 秒窗口内没有拒绝新流。两项对端无错误、物理连接仍存活，分别收到 17/5 次心跳回复；未把有限观察窗口夸大为无限运行证明。证据位于 `build/round42-budget-baseline{.log,/results.json}`，旧产品及源码另存为 `build/round42-baseline-cnode.exe`、`build/round42-before-anytls_inbound.cpp`，产品哈希与第四十一轮最终清单相同。

入站继续保持一个物理帧循环和普通 Dispatcher 请求链路。每条被接纳 SYN 记录单调时钟起点，ProcessStream 的有限握手子任务共用一个 `timeouts.handshake` 绝对期限，包含 SOCKS 目标、UoT v2 请求或 v1 首个 datagram，以及 SYNACK 写入。SYNACK 保持在已解析 SOCKS 目标之后、读取 UoT 数据之前，避免要求等待 SYNACK 的客户端提前发送应用握手。定时 token 留在拥有任务组的子任务中，过期取消逻辑读端与该子任务的 Asio 操作；组内协程实际结束后才进入 Dispatcher。开始时检查剩余预算，准备完成后再检查绝对时间，防止已就绪 continuation 抢在迟到定时回调前把过期地址交给 Dispatcher。心跳及零碎 PSH 不刷新起点，已完成握手的 relay 不再携带该定时器。

同一 Session 的并发接纳预算固定为 128，覆盖待解析和已经进入 Dispatcher、尚未结束的子流；在分配 SubStream、Context 和任务之前拒绝超额 SYN。v1 发送 FIN，v2 发送含错误信息的 SYNACK 后发送 FIN，已有流保持可用；拒绝时也推进最后使用 ID，不能在释放名额后重用被拒绝 ID。128 是本实现的资源预算，不是协议规定的上限；[AnyTLS 协议](https://github.com/anytls/anytls-go/blob/main/docs/protocol.md)规定 v2 SYNACK 非空数据表达子流建立失败。静态和面板配置均进入同一 Handler，未增加第二套配置解释或公开兼容入口。接纳数量与现有每子流 65,535 字节排队 payload 限制共同限制排队有效载荷，但不能据此声称会话总内存小于 8 MiB：Buffer 分配容量、片段数量和其他在途状态仍需单独审查。

握手超时等待共享写入门闩时，只取消等待者，不能取消正在写入的其他逻辑请求。一旦获得门闩并开始物理帧写入，三个实际写入入口发生错误或异常都关闭会话，因为取消时无法证明未写出半帧。新增 C++ 检查运行真实 Handler、codec、UserStore 和子任务组，用可控 transport 验证部分 SYNACK 后超时、部分 SYNACK 后父取消与额外 20 毫秒清理、被另一已建立流占用门闩时的单流超时、超额拒绝 ID 的复用，以及 Worker 延迟后就绪地址与逾期定时回调的竞争。五项都检查子任务和 I/O 完成后才销毁 transport；门闩超时记录保留原 SID 与 TIMEOUT。未用该夹具声称覆盖真实网络故障或全局 OOM。

`tests/anytls_handshake_budget_integration.py` 新增 9 项真实 TLS/面板/目标连接测试：仅 SYN、半个地址、逐字节域名、UoT v1/v2 初始请求不完整、握手后持续转发、v1/v2 待解析流超额及 128 条真实已建立流超额。五项超时后同一物理会话均成功建立新流，迟到旧 ID payload 未到达目标；待解析流释放名额后可接纳更大 ID，活动容量场景仍有原流完整回显。第一次 9 项通过后补齐绝对时间竞争检查，最终产品重建并重新运行全部 84 项。`build/round42-native-processes.json` 保存九个脚本实际退出码及产品哈希，所有 results.json 的 passed 为真且 peer_errors 为空。

全量 Release 构建为 `build/round42-build.log`。首次全量 CTest 的唯一失败是 access-log 源码契约仍精确匹配旧 ProcessStream 单参数调用；新参数是 SYN 接纳时间，实际预分发错误与日志运行时检查已通过。契约同步允许后续参数，保留结果进入统一失败记录的检查，单独验证后重新跑完整 CTest，最终为 `build/round42-ctest-final.log`、`build/round42-last-test-final.log`；首次日志保存在 `build/round42-{ctest,last-test}.log`。AGENTS 和 README 同步资源接纳、绝对期限与物理写入错误边界，`build/round42-validation.json` 保存关键证据及最终文件哈希。

本轮没有新增 Linux、线上部署或内存压力验证；FIN 完整语义及排队片段对实际内存的影响仍未完成审查。原工作区仍只有原 `.codex/`，没有提交、推送或部署。

第四十三轮用真实 AnyTLS Handler、codec、UserStore 和一个暂停消费的 Dispatcher 复现小帧排队放大。测试记录 `sizeof(Buffer)` 的实际分配与释放，测量前清空 Worker 回收缓存，读取排队快照前再次归还已释放的缓存块，避免把缓存保留误算为队列所有权。旧实现把 2,048 个单字节 PSH 保留为 2,048 块，2 KiB 有效数据对应 16 MiB 数据块容量；完整的 65,535 字节单帧则原本只有 8 块，作为无需修复的对照。旧测试以观察模式正常退出，第一项打印 bounded=0，不能写成旧测试进程退出失败。两项取消后都能释放，未声称旧队列泄漏。证据为 `build/round43-baseline-queue.log` 和 `build/round43-queue-baseline-test.exe`；旧产品 `build/round43-baseline-cnode.exe` 的哈希与第四十二轮清单相同。

AnyTLSSubStream 现在直接拥有一个 MultiBuffer 作为输入字节队列。PushInput 从实际载荷取得字节数，容量判断只读取队列的 byte_size，不再依赖调用方传入的 frame length 或独立 queued_bytes。追加先按最终字节数预留足够的指针槽位，之后才修改字节和转移 BufferGuard。能够装入尾块的小片段直接合并；若尾块不足半块且下一大块不能整体装入，则只复制补足半块的前缀，剩余大块直接转移，不重新压紧或复制整块。队列中除尾块外每块至少包含 4,096 字节，所以 65,535 字节的有效数据最多需要 16 个 8 KiB Buffer。这个规则保留大块直接转移，并防止线上的小帧数量变成大量 Buffer 和队列节点。

读取一次转移整个队列的 MultiBuffer 所有权，并唤醒容量等待者。逻辑 FIN 继续排空已接收字节；取消清空拥有的队列并唤醒读写等待，父会话仍等待有限任务实际结束。逐帧 QueuedInput、ThreadLocalDeque、queued_bytes、收缩阈值、收缩标志、ShrinkQueueIfDrained 及只为其服务的 container_util include 已完整删除，公开表面契约防止恢复这些状态。没有增加新的公开 wrapper、协议 buffer pool、Worker 特判或第二条请求链路；静态和面板仍使用同一个 Handler。

扩展后的 C++ 夹具共 24 项：2,048/65,535 个单字节帧、最大整帧、稀疏大小块交替、4 KiB/8 KiB 边界、满队列后的容量等待与恢复、满队列父取消、16 组确定性随机片段和一次队列槽位增长分配失败。单字节 2 KiB 用量从 2,048 块降为 1 块，65,535 个单字节帧用 8 块；所有样例排队最大观察值为 15 块，连同当前物理帧的分配峰值最大观察值为 16 块，均满足理论 16/24 块边界。完整单帧在 Dispatcher 观察到的各数据块地址与 codec 的读取地址逐一一致，验证这一场景没有复制。分配故障准确注入 128 字节指针槽位分配，原始 bad_alloc 经任务组保留，旧请求异步清理完成后才销毁 transport，排队及在途 Buffer 全部释放。新增计数仅存在于测试分配器，没有修改生产内存统计或增加热路径原子计数。

上述容量只约束接收队列的数据块。单一物理帧读取最多另持有 8 块；已转交 Dispatcher/relay/UoT 的数据、Buffer 元数据、TLS/传输状态和 Worker 回收缓存另计，不能将 128 KiB 队列上限当成整个 Session 的 RSS。理论上界来自字节密度不变量，24 个样例只是运行时证据，未把样例数量说成穷举或吞吐压力测试。

全量 Release 构建为 `build/round43-build.log`，全量 CTest 为 `build/round43-ctest.log`、`build/round43-last-test.log`，新增检查使该生命周期测试的执行预算从 10 秒调整为 20 秒。九组原生脚本仍为 12/7/6/2/4/4/13/27/9 项，共 84 项 passed、peer_errors 为空、实际进程 exit 0，脚本记录的产品哈希与当前产品相同。六项真实 TLS UoT v1/v2、连接/逐包模式及分片场景均收到两个精确的 9,000/19,999 字节 datagram，校验内容哈希及边界，证明本次字节聚合仍由后续 UoT decoder 解释包边界。AGENTS、README 和架构契约同步队列边界，`build/round43-validation.json` 保存关键证据与最终哈希；本轮没有提交、推送或部署，原工作区仍只有原 `.codex/`。

第四十四轮以实际 codec 和可控 AsyncStream 注入异常，确认旧实现将非 I/O 异常转换为 socket 读写失败。16 个操作各覆盖正常完成，以及七类故障在开始前、传输三字节并异步恢复后发生，共 240 项；旧实现通过 112 项、失败 128 项，进程退出 1，所有 Buffer 仍正常释放。故障包含 bad_alloc、保留 BLOCKED 的 LinkError、真实取消/超时/reset 系统异常、原始 runtime_error 和非标准异常；读取 Header/Text/Payload/Discard、直接/分批/带 padding 写入都执行生产代码。证据为 round44-codec-baseline.log 和对应测试二进制，未把旧错误分类问题描述为内存泄漏。

codec 删除八个兜底 catch 和无独立语义的 MapWriteException，仅将真实 IoSystemError 映射为 ErrorCode。协议拒绝、EOF 和零字节写入仍用结果值表达；非 I/O 异常由调用方作用域与 RAII 收束。通用 proxyman 的 accepted TCP 和已准备逻辑 transport 两个协议 Process 边界分别处理 LinkError、bad_alloc 和 IoSystemError，未知异常为 INTERNAL；没有向该层加入具体协议分支。32 项夹具使用真实 proxyman Handler，两种入口、直接异常/实际 codec 两种来源和八种结果，确认日志在 transport 释放之后记录一次正确终态；旧代码有效基线为 14 项通过、18 项失败，修复后 32 项全部通过。逻辑 transport 的外部构建边界由夹具替代，并非真实 gRPC 网络覆盖；协议调用之前的 metadata/transport 构造异常不在此次修复范围内。

AnyTLS 逻辑端点不再把已有 ErrorCode 转为伪造的 io_error、connection_reset 或 no_buffer_space，而是抛出通用 LinkError。出站物理任务完成与四个取得串行写租约的入口在会话所有权边界分类异常，立即 CloseAll，再由原异常到达请求；残缺帧不能被复用连接或后续控制帧继续使用。新增 15 项实际 Handler/codec/pool/relay 检查覆盖物理读取、开流、TCP payload、UoT payload 和 FIN，各注入内存、逻辑和未知异常，验证错误、实际注入次数、三字节部分写入、旧连接完成清理以及下一请求重新拨号成功。payload 的未知异常保持 relay 现有 RELAY_WRITE_FAILED 阶段分类，其他拥有者的未知异常为 INTERNAL，测试同时确认没有虚构 OS 错误码；没有为统一标签而改变 relay 的原职责。

实际 AnyTLS 入站的三项 SYNACK 部分写入故障还复现了独立日志缺口：物理写入取消会先清空子流索引，RunStream 再按 sid 查找上下文时无法记录失败。旧观察模式进程退出 0，但三项均打印 failures=0、passed=0；现在子任务从自身持有的 sub.ctx 记录，三项均为 failures=1、joined=1、passed=1。该记录不依赖索引仍然存在；Dispatcher 已提交的终态继续由现有 AccessLogSession 幂等逻辑保护。启动接纳失败仍使用当时存在的子流索引，没有留下无调用 helper。

本轮保留了验证过程中不应计作产品证据的失败：codec 夹具先补齐 MSVC /Zc:preprocessor 和抽象 Cancel 接口；proxyman 初始夹具误启用 PROXY protocol，修正为 Off 后才取得上述有效旧基线。出站初始 payload 故障未触发，是首会话不等待 SYNACK 导致测试 padding 更新晚于写入；夹具等待对端设置实际被消费后才放行首个请求，并按照既有 relay 阶段分类校正两个未知异常期望。round44-outbound-io.log、round44-outbound-io-final.log 等中间记录全部保留，最终证据来自全量 CTest 的 round44-last-test.log；未宣称这 15 项全部在旧源代码上复现过失败。

全量 Release 构建实际退出 0；全量 CTest 用时 234.12 秒，115/116 通过，唯一失败是旧 access-log 源码契约禁止整个 inbound handler 出现 RESOURCE_EXHAUSTED。该检查本意是防止把连接限额写成资源故障，范围却覆盖了真实 bad_alloc；保留 CONNECTION_LIMITED 的正向约束，移除全文件禁令后，失败项独立复测 1/1 通过。全量日志和单项复测日志分别保存，未伪称修正后又执行了一遍完整测试。新增 290 项定向场景及原有生命周期/会话池测试均在全量运行通过。九组原生回归为 12/7/6/2/4/4/13/27/9，共 84 项 passed，peer_errors 为空，实际脚本进程均退出 0；六项 UoT 网络场景保留精确的 9,000/19,999 字节数据报。最终产品哈希与原生 runner 记录相同，旧产品副本哈希与第四十三轮清单相同。

AGENTS、README、公开表面和访问日志契约同步职责边界，round44-validation.json 记录源码、测试、全部本轮顶层证据和九组原生结果哈希。本轮没有提交、推送或部署，原工作区保持原状。

第四十五轮通过真实 AnyTLS 出站 Handler、codec、会话池、逻辑端点和 relay 复现小帧排队放大，只替换外部拨号边界。夹具让物理读循环完整接收预设帧之后再放行开流写入，确保读取排队快照时应用尚未消费；快照前清空 Worker Buffer 回收缓存，通过实际分配/释放记录测量数据块所有权。旧实现把 2,048 个单字节 PSH 保留为 2,048 块，即 2 KiB 有效数据对应 16 MiB 数据块容量；65,535 字节整帧仍只有 8 块，作为正常对照。两个旧场景均交付正确字节并最终释放，观察模式进程退出 0；第一项 bounded=0，不能表述为旧进程失败或内存泄漏。round45-queue-baseline.log 和 round45-queue-baseline-test.exe 保存实测，旧产品副本哈希与第四十四轮清单一致。

出站 LogicalStream 现在只拥有一个 queued_payload_ MultiBuffer，从真实内容取得字节数并整体移交消费者。QueuedPayload、ThreadLocalDeque、queued_bytes、收缩阈值/标志/方法及 container_util include 全部删除。单参数 PushPayload 成为唯一接收入口，不再让帧头长度充当队列的第二份事实；无调用的 Sid 方法、sid_ 字段和构造参数、只服务析构的 Cancel 入口及重复 Fail 入口一并删除。RegisterLogicalStream 直接使用 ClientSession 拥有的 io_context，取消另传执行器的可能；WriteOpenPacket 的无用途 sid 参数也已移除。

入站和出站共用 src/proxy/anytls/payload_queue.hpp 的协议私有 AppendQueuedPayload。它只负责从 codec 的新数据块聚合字节，不决定会话状态、容量策略、唤醒、路由或 relay，也没有引入新的公开 wrapper 或 Buffer pool。追加先预留全部指针槽位，再合并小片段或转移大块；每个内部块至少包含 4,096 字节，故 65,535 字节队列最多拥有 16 块。入站先前的聚合实现已完整移入该函数，原 24 项队列、取消和分配故障检查继续通过。两端各自持有队列及终止状态，跨 Worker 不共享可变数据。

正常 FIN 继续允许排空已接收字节。异常关闭先发布 closed/error，再释放未读队列并通知 CancellationSource，避免取消回调重入时覆盖首个原因；FIN 后的错误同样清空未读数据。出站超出既有 65,535 字节预算仍终止请求并保留 RESOURCE_EXHAUSTED，入站仍等待消费者释放空间。这两种容量策略明确留在所属会话，未混入缓冲聚合函数；是否应将出站正常突发改为背压，仍需后续独立验证。

新增 28 项出站场景覆盖 2,048/65,535 个单字节帧、完整最大帧、稀疏大小块交替、块边界、16 组确定性随机片段、容量超限、满队列取消、指针槽位增长分配失败、排空后再接收完整帧、两种 UoT 分帧和 FIN 后 Alert。2 KiB 小帧现在仅保留 1 块，65,535 个单字节帧保留 8 块；观察到最大排队块数 15、最大分配峰值 16，均在 16/24 块理论队列/单帧范围内。完整帧交给 relay 的各数据块地址与 codec 读取地址一致，验证该场景直接转移；排空后两次接收共 131,070 字节且顺序正确。两项实际 UoT decoder 场景分别把两个数据报的完整编码放入单帧、拆成 29,003 个单字节帧，均输出两个精确的 9,000/19,999 字节数据报，校验内容和边界。

分配失败准确注入 128 字节的指针槽位分配，最终记录 RESOURCE_EXHAUSTED；FIN 后 Alert 场景不会交付排队数据，保留 PROTOCOL_DECODE_FAILED。所有场景关闭后物理 transport 完成清理，没有仍在访问它的读取操作，Buffer 全部释放。测试中的数据块计数只衡量受测所有权，不代表完整 Session RSS；正在消费的数据、UoT 解码缓存、Buffer 元数据、TLS/传输状态及 Worker 回收缓存需另计。理论队列上限来自密度不变量，28 个样例不是全部输入穷举或吞吐压测。

全量 Release 构建退出 0，CTest 116/116、237.43 秒；出站生命周期测试因增加场景将超时预算从 10 秒改为 20 秒。九组原生回归仍为 12/7/6/2/4/4/13/27/9，共 84 项 passed、peer_errors 为空、实际进程退出 0，runner 记录的最终产品哈希一致。AGENTS、README 与架构契约同步两端队列和终止边界，round45-validation.json 保存源码、测试、旧基线和当前验证的哈希。初次夹具构建的局部变量遮蔽警告已修正，日志保留；全量构建仍存在既有 RateLimiter 对齐填充警告。本轮未提交、推送或部署，原工作区保持原状。

第四十六轮用真实 VLESS 入站、AnyTLS/TLS 出站和可控异步对端检查大响应。有效旧基线中，快速读取的 2 MiB 响应完整收到且复用原连接；暂停客户端读取 0.4 秒的 8 MiB 响应仅收到 2,818,048 字节，之后的新请求需要第二条物理连接，对端没有协议错误。对应测试进程退出 1，结果保存在 round46-pressure-baseline-final/results.json；旧产品哈希与第四十五轮清单一致。初始夹具曾把 ServerSettings 的命令值误写为 6，导致 SYNACK 在未协商 v2 时被拒绝，两个请求和恢复对照均失败；核对当前 codec 常量并改为 10 后才取得上述有效基线。初始日志及夹具另行保留，不能把它们的零字节响应算作容量问题证据。

LogicalStream::PushPayload 现在是由唯一物理读取任务直接 co_await 的操作。当已有队列与当前完整帧超过 65,535 字节预算时，物理任务持有这帧及逻辑流，等待 payload_space_signal；它不继续读取下一帧，也不创建额外后台任务。ReadPayload 整体移交队列之后唤醒等待者，Close 同时唤醒数据、SYN 和容量等待；恢复后先检查关闭状态，不能把取消期间持有的旧帧再次追加。原有共享 AppendQueuedPayload、16 块队列密度上限和 Worker-local 所有权不变，真实分配失败仍通过物理任务拥有者保留 RESOURCE_EXHAUSTED。正常突发不再触发资源不足拒绝，入站与出站的容量处理现在都形成背压。

出站生命周期夹具共 31 项队列场景。原来 65,535 字节后追加一字节的拒绝场景改为等待后完整收到 65,536 字节；新增三个 262,140 字节场景分别验证恢复消费、取消和一秒半关闭超时。暂停快照观察到消费者、排队和当前待追加帧各持有 8 块，共 24 块，恢复后交付全部字节并处理等待帧后面的心跳；取消和超时等待模拟消费者额外 20 毫秒清理完成，最终 pending-consumer=0、transport 已销毁、Buffer 全部释放。容量等待不借用已结束的请求作用域，而由会话池已有物理根任务和请求的逻辑流所有权覆盖。上述 24 块是这些整帧场景的实测组成，不是任意请求的总内存上限；队列仍最多 16 块，当前物理帧最多 8 块，已交给消费者/UoT 的数据和其他状态另计。

保留的槽位增长故障现在按 128 字节分配定点注入，避免新增协程准备分配先消费原来“下一次分配失败”的开关；它仍验证队列元数据增长失败后释放全部缓冲并报告资源不足。队列与关闭状态没有增加跨线程访问、无界旁路或第二套 payload 存储；私有缓冲函数继续只负责聚合，等待和终止属于逻辑流/物理任务的所有者。

新增六项真实网络回归覆盖 TCP 快速读取、TCP 暂停读取、UoT 快速/暂停读取、背压期间客户端取消和半关闭超时。修复后 8 MiB 暂停场景收到完整 8,388,608 字节，SHA-256 与预设响应相同，后续小请求复用同一物理连接。两项 UoT 场景各交付 256 个交替 9,000/19,999 字节数据报，含长度字段的编码共 3,712,384 字节，逐包长度、全部字节哈希和恢复请求均正确；这使用实际 UoT 解码及 VLESS UDP 编码。四项完整传输都处理了数据中的心跳并保持单连接。客户端在 0.4 秒发出取消后，对端在 0.406 秒观察到连接关闭；配置一秒半关闭期限时，对端在 1.031 秒观察到关闭，两项后续请求都通过新连接完成。

全量 Release 构建退出 0；CTest 116/116、238.73 秒，31 项队列及既有错误分类/生命周期场景均通过。原九组 84 项协议回归以及新增六项网络检查全部 passed、peer_errors 为空，实际执行进程均退出 0，产品哈希与两份进程记录一致。AGENTS、README、架构契约同步背压边界；round46-validation.json 保存修改源码、夹具、有效/无效旧基线、当前二进制、CTest 及 90 项网络结果哈希。本轮未提交、推送或部署，原工作区保持原状。

## 第四十七轮：AnyTLS FIN 官方对照（尚未修复）

官方依据固定在 `anytls/anytls-go` 提交 `fd6167acd6d73b9fa3e607659951847fbc9e6c50`，避免把可变的 main 当成可重复基线。直接克隆并检出该提交，使用本机 Go 1.26.3 构建未修改的 `cmd/client` 与 `cmd/server`；`go version -m` 均确认上述完整 revision、正确入口和 `vcs.modified=false`。源码与产物位于 `build/round47-reference`。协议说明：[FIN 与 Stream/Session 关闭](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/docs/protocol.md)；实现依据：[Stream](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/proxy/session/stream.go)、[Session](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/proxy/session/session.go)。

官方 FIN 是整条逻辑流的关闭。接收端将流从索引移除，关闭本地读写且不回复 FIN；本地主动 Close 只发送一次 FIN。Stream 不实现 TCP CloseWrite。官方客户端的本地 TCP EOF 同样会关闭 AnyTLS Stream，不能推导为“仅延迟发送 FIN 即可”。官方内部 pipe 没有队列，PSH 必须先交付给流读取者，后面的 FIN 才被物理循环处理；cnode 的有界队列不能简单照搬立即清空行为，否则会截断已经收到的合法响应。

新增 `tests/anytls_fin_integration.py` 用同一组本地可控对端分别测试官方二进制和 cnode。先检查官方二进制内嵌版本，执行前后校验全部二进制 SHA-256；结果记录进程清理前的存活状态，显式拥有并结束所有监听、连接和读取任务。收到 FIN 与发送迟到数据之间使用心跳响应作为物理解析屏障，避免仅凭 sleep 推断 FIN 已处理。每个场景还检查后续请求和物理 Session 是否可复用。

| 场景 | 未修改官方实现 | 当前 cnode 基线 |
| --- | --- | --- |
| 入站收到客户端 FIN，目标随后尝试发送响应 | 不再转发，FIN 回复 0 次；同一 Session 可继续使用 | 继续转发 19 字节，回复 FIN 2 次 |
| 入站目标 TCP EOF，本端发送 FIN 后客户端继续发 PSH | 不再写目标，目标读取结束；同一 Session 可继续使用 | 仍向目标转发 19 字节，目标读取未结束 |
| 出站收到服务端数据及 FIN，本地上传保持打开 | 完整交付 FIN 前 262,144 字节，立即 EOF；迟到上传 0 字节；复用同一 Session | 数据完整，但一秒内没有 EOF；FIN 后仍上传 19 字节 |
| 出站本地 TCP EOF，发送 FIN 后服务端继续发 PSH | FIN 仅一次，忽略迟到数据，立即 EOF；复用同一 Session | 仍接收 19 字节，一秒内没有 EOF；后续请求使用第二条 Session |

待修复基线二进制为 `build/round47-baseline-cnode.exe`，SHA-256 `A6C4261E0B4DC7D94FC5407A9EEC89EC6EEC6E3D6D8B06B6639F8BD8D1107350`，与第四十六轮产物一致。最终有效结果、构建元数据和日志见 `build/round47-fin-verified`、`build/round47-fin-verified.log`，进程退出 1；四项官方对照通过，四项 cnode 场景失败，所有 peer_errors 为空。这是缺陷证据，不是修复完成的验证。

首版测试的 Python 3.12 清理先等待 server.wait_closed、再关闭已接纳连接，遇到保留空闲连接的官方客户端时等待无法结束。该运行已明确终止，终态退出 -1，不能当成完整测试结果；夹具已调整为先停止监听、关闭连接并 join 任务，再等待监听结束。早期 `round47-fin-baseline`、`round47-fin-baseline-final`、`round47-fin-oracle` 结果保留用于说明夹具演进，最终断言和源码哈希以 `round47-fin-verified` 为准。

本轮没有 C++ 生产代码变更，也没有重建或重跑旧 CTest。前四十六轮中有些 AnyTLS 测试以收到 FIN 触发响应，或要求 FIN 回复，因此它们验证的缓冲/取消机制不能证明正确的 FIN 行为。不得为保留这些绿灯继续维护错误半关闭模型。AGENTS 新增最终约束，README 明确当前缺陷；修复仍是接下来的主任务。

完整迁移必须同时满足：

1. 用通用 Link/relay 语义明确区分 TCP 半关闭与完整逻辑关闭，移除把 AnyTLS FIN 伪装为写半关闭的 trait；Relay 不识别具体协议。
2. 收到 FIN 后禁止新 PSH，FIN 前合法数据按已有内存预算交付完毕；在途写入须保全物理帧边界，不能把残帧 Session 归还池。
3. 本地关闭只发送一次 FIN，远端关闭不回复 FIN；等待地址/UoT/SYNACK、已进入 Dispatcher、正常转发和错误退出都使用同一终态。
4. 完整关闭必须结束并 join 两个方向，区分正常结束与超时/真实故障，不能把伴随取消记成新失败，也不能把真实错误改成成功。
5. UoT reader/writer 传递底层关闭语义，入站与出站同时迁移；共享 Session 的其他请求及后续合法新 ID 继续可用。
6. 迁移旧网络和单元夹具的应用请求边界，保留大响应、限速、背压、内存不足及取消释放覆盖。超时场景不能继续依赖已经关闭的流发送响应。
7. 新官方对照全部转绿后，执行完整构建、CTest、现有网络回归，并新增直接官方互通及关闭竞态覆盖；没有证据的场景继续列为未验证。

## 第四十八轮：AnyTLS 完整关闭与 TLS 取消传递

第四十七轮复现的四项 cnode FIN 差异现已修复。Link 新增通用 EOF 动作和写关闭能力，UoT reader/writer 在类型擦除后仍传递底层语义，Mux 原有的写半关闭动作也转为实际虚接口。AnyTLS 两端使用完整关闭，移除旧半关闭 trait；Relay 没有加入任何具体协议分支。完整关闭先取消并等待两方向 I/O 与限速任务结束，再执行最终关闭；普通 TCP 继续使用原有半关闭预算。

两端的远端关闭状态同时禁止新写入并唤醒读取者，保留 FIN 前已经接收的有界队列；本地主动关闭清空未读数据，只发送一次 FIN，远端关闭不回复 FIN。写入在取得共享门闩后再次检查状态，尚未启动的写入以通用 WriteClosed 正常拒绝，另一方向仍可排空已收数据；已经进入物理帧写入的错误继续关闭整个 Session。入站 RunStream 在成功、准备失败和退出路径统一尝试幂等关闭，SYNACK 和迟到 PSH 不能恢复关闭的流。出站完整成功后清除请求期限并归还会话，错误保留原始原因。

新 relay 单元场景覆盖有、无客户端控制对象两种入口下的上传/下载限速取消、写拒绝后排空，以及最终关闭的 bad_alloc、BLOCKED 和未知异常，共 12 项。旧关闭 helper 吞掉异常的问题同时修正，关闭失败参与最终结果；同伴取消的 operation_aborted 不再虚构为逻辑故障的 OS 错误码。原 AnyTLS 生命周期、部分物理写入故障和有界队列检查均保留，通过实际应用请求触发响应，取消了以 FIN 触发服务端响应的旧假设。

真实受阻写入另外暴露 TLS 取消传递缺口：TlsTcpLayer 用 lambda 包装 SSL handler，却丢失关联取消槽。将其传递给 socket 读写后，remote-fin-during-write 从约 2.063 秒降至 0.656 秒，在对端 2 秒恢复读取之前结束；正常写超时与 Alert 仍通过。`tests/tls_cancellation_integration.py` 用 SSL MemoryBIO 发送不完整 TLS 记录，将 cnode 留在 SSL 内部读取。旧产品一秒内未发送 close_notify；修复后立即进入关闭握手，对端确认后 TCP 结束，同一 AnyTLS 入站会话保持可用。首版该夹具没有确认 TLS 关闭，修复前后都等待确认，不能作为读取修复证据；最终有效基线和修复结果是 `round48-tls-partial-verified-{baseline,fixed}`。

最终产品 SHA-256 为 `71621f7a8cd579b8f19e28680730abd92af4804832e75529a5dfd83c1a3a4fa8`。全量 Release 构建实际退出 0；CTest 实际退出 0，109 项执行通过，8 项因 DNS fixture 无法绑定 53 端口而明确跳过，不能表述为 117 项均执行通过。当前该端口由本机 verge-mihomo 占用，没有修改或停止该进程。7 项旧 UDP 网络场景起初同样无法启动；夹具改为只有 DNS 场景才创建 DNS listener，随后 4 项数字地址回显与迟到回包检查通过，剩余 3 项 DNS 相关场景仍未在本轮运行。

真实网络验证共 107 项通过：原 90 项中的 87 项、固定官方提交的 8 项 FIN 对照、2 项 TLS 取消、4 项直接互通及 6 项提前 FIN。官方对照使用未修改的 `fd6167acd6d73b9fa3e607659951847fbc9e6c50` 客户端和服务端。直接互通两个方向分别检查远端 FIN 和本地 EOF，每项连续两个请求经计数 TCP 中继，只建立一条物理会话，完整响应为 262,144 字节且哈希一致。提前 FIN 检查 SYN、半个目标地址及 UoT v1/v2 各 128 条准备中子流关闭后恢复名额；出站第 2 个流在 SYNACK 前收到 FIN，分别验证零数据及 8,032 字节排空，第 3 个流仍复用同一物理连接。

原生 runner 首次总体退出 1：UDP 端口受占用，握手夹具的 TLS 清理异常，以及汇总器把官方报告对象误当作单个用例。握手清理改为观测完成后主动中止测试连接并等待结束，9 项重新执行通过；官方脚本本身实际退出 0，8 项原始结果均通过，最终汇总直接校验其 cases。直接互通首版夹具向已关闭目标发送额外数据，触发 Python Proactor 清理异常，该次超时未计为通过；最终夹具使用有限 TaskGroup 持有中继两个方向，实际四项退出 0。所有中间失败日志保留，最终来源由 `build/round48-validation.json` 单独列明。

本轮没有新增 Linux、线上或跨平台内存压力验证，未穷举所有 FIN 与开流写入门闩的调度顺序。原工作区已有其他 README、配置、集中日志文档及测试修改，本轮继续仅修改隔离 worktree，没有提交、推送或部署。

## 第四十九轮：DNS endpoint 冷路径归一化

DNS 的配置类型和 Worker service Config 统一保存完整 UDP endpoint，删除 Impl 中由 IP 列表再次构造的服务器表及固定端口常量。服务只读取自身不可变 Config，服务器非空和端口有效性在构造时检查，检查成功后才配置全局结果缓存。端口默认值仅在 JSON 配置入口补齐；裸 IPv4/IPv6 仍表示 UDP 53，显式端口使用 `IPv4:port` 或 `[IPv6]:port`。没有增加协议 wrapper、测试专属生产分支或查询热路径解析，Worker-local DNS 所有权和不可变 L2 结果快照保持原边界。

实际基线比“不支持配置端口”更严重：Windows 下依赖中的 Asio 调用 WSAStringToAddress，接受 IP 加端口，但 make_address 只复制地址部分。旧产品在三个动态 DNS endpoint 场景均成功启动，却没有向测试 resolver 发送任何查询，最终应用请求超时。旧产品 SHA-256 与第四十八轮一致，证据为 `round49-dns-verified-baseline`，三个场景均失败，脚本实际退出 1；未把它们描述为配置拒绝。当前解析先拆 host/port，再解析 IP，严格检查十进制端口范围、完整消费、方括号、空白和嵌入 NUL；IPv4 必须为规范点分十进制，避免平台简写或前导零差异。配置拒绝夹具新增 22 项非法字符串及混合合法 endpoint 的启动检查。

`tests/dns_endpoint_integration.py` 经真实 VLESS -> Dispatcher -> Freedom 链路验证 IPv4、IPv6 及同一 IP 不同端口的服务器切换。每项启动两个 Worker、完成两个实际目标连接，记录查询到达各自独占的动态端口；失败服务器收到查询后才使用后续 endpoint，第二次应用请求不新增 DNS 查询。此次测试没有引入新的重试策略，也没有声称测量跨 Worker 的完整缓存调度顺序。

面板 HTTP fixture、路由 DNS 取消夹具和原生 UDP DNS 场景均使用系统分配的本地端口，配置指向真实绑定 endpoint；删除端口 53 的权限跳过逻辑和 CTest 跳过码/共享端口锁。原来被函数内直接返回成功而跳过的 Dispatcher DNS 取消场景也重新执行。本机 verge-mihomo 继续占用 53 端口，没有为测试改变其状态。

首轮完整构建的主程序链接失败：上一轮未计为通过的互通夹具超时后遗留 cnode 子进程，导致 LNK1104。确认 PID 12864 的可执行路径及 round48 失败夹具目录后结束该进程；它没有使用生产配置。公共 Python Resources 清理现在用 finally 回收所有子进程，异步清理超时记录为夹具错误而不能留下子进程或计作成功。首轮构建退出 1 保存在 `round49-build.log`；处理遗留进程并修正解析拆分后重新全量构建，`round49-build-final.log` 实际退出 0。

最终产品 SHA-256 为 `f221d90d339d8369730c16f41007fb8f0d35adc60cf3c9a58b3b1f231919d267`。全量 CTest 117/117 实际执行通过，没有跳过，耗时 245.94 秒；原先受阻的 8 项面板测试全部执行。原生 16 组脚本共 113 项通过且各进程退出 0，包括完整 90 项原回归、8 项官方 FIN 对照、4 项直接互通、6 项提前 FIN、2 项 TLS 取消和新增 3 项 DNS endpoint。所有 peer_errors 为空，运行前后产品哈希相同；结束后检查当前 worktree 产品没有遗留运行进程。最终来源及哈希记录在 `build/round49-validation.json`。

后续只读探针发现相同平台解析问题仍存在于通用 TargetAddress：VLESS 域名字段为 `127.0.0.1:9` 或包含 `127.0.0.1` 加 NUL 加尾部内容时，Windows 产品实际连接了请求另外指定端口的回环目标；正常 IP 为阳性对照，末尾空格被拒绝。探针进程退出 0 仅表示观测完成，两项畸形输入被接纳是待修复证据，不计入 113 项通过场景。本轮只完成 DNS endpoint 入口迁移，不能据此声称所有协议和配置的 IP 解析均已严格化。

## 第五十轮：统一完整 IP 字面量解析

新增 `common/ip_address.hpp` 的 `iputil::ParseLiteral`，只解析完整 IP 字面量并返回地址值，不解释端口、URL、CIDR 或域名，也不选择 IPv4-mapped IPv6 归一化策略。IPv4 必须是四段无前导零的点分十进制，IPv6 使用固定数组和原生 inet_pton 解析地址部分，数字 scope ID 单独检查范围与完整消费。入口拒绝 NUL、方括号、端口、空白和接口名称，避免 Windows Asio 使用 WSAStringToAddress 时静默丢弃输入后缀；不分配 C++ 字符串来准备地址转换。

完整迁移 TargetAddress、DNS 字面量捷径、DNS endpoint 配置、监听、出站绑定、路由 IP 网络、五种代理出站、XHTTP 下载地址、面板 API host、HTTP/TLS 嗅探、PROXY v1 源地址及 HTTP 真实客户端地址。各入口仍负责自己的语法：endpoint 和 URL 拆分后才能交给 IP 解析器，方括号中必须是 IPv6；出站地址和 DNS 查询入口分别判断合法 DNS hostname。TLS 的 IP SAN 配置改用地址字节，不再让另一个字符串解析器重新解释地址；DNS 身份需要字符串分配，因此移除内部配置函数错误的 noexcept 声明，让分配失败能够向调用方传播。

删除公开出站 ParseLiteralAddress helper，并把其生产调用迁移到通用入口；删除 domain_name 中重复的 IPv4 判定，域名模块不再实现 IP 解析。GeoIP 内没有调用者的 AddCIDR(string)、Match(string) 及只服务它们的 ParseCIDR 实现直接删除，保留实际使用的二进制 CIDR 和 address 接口。源码扫描确认 src/include 中不再有 Asio 文本 make_address、旧 helper 或其他文本地址转换调用，二进制协议解码的 make_address_v4/v6(bytes) 保留。

真实 VLESS -> Dispatcher -> Freedom 请求基线使用第四十九轮产品，SHA-256 为 `f221d90d339d8369730c16f41007fb8f0d35adc60cf3c9a58b3b1f231919d267`。10 项中有 4 项误接收并实际到达后端：IPv4 带端口、IPv4 带 NUL 后缀、映射 IPv6 带 NUL 后缀、带方括号的映射 IPv6。新版全部 10 项通过，合法 IPv4、映射 IPv6 及其完整十六进制形式仍收到准确响应。补充产品存活检查后重新验证，旧版脚本退出 1，新版退出 0，全部场景的产品在清理前仍在运行；旧版失败和新版成功均不能由进程崩溃解释。最终记录为 `round50-ip-verified-baseline` 和 `round50-native-ip-literals-final`，较早的 10 项观测保留，但不重复计入通过数。

新增纯 IP 解析测试与 PROXY 源地址测试；IP 测试涵盖合法/非法字符串、非 NUL 终止的 string_view、数字 scope ID、映射地址类型以及 2304 项地址字节往返。扩展 TargetAddress、监听、绑定、路由、TLS 身份测试，配置启动夹具增加 55 项拒绝场景，覆盖五种出站、面板 ListenIP/SendIP、静态监听/绑定、路由网络及 URL host。

完整 Release 构建退出 0，最终产品 SHA-256 为 `db62ea137713b829fe49abef0628b4c59f5ad9a7a19ff10aa4a0e40f8ecaae66`。CTest 119/119 实际执行通过、无跳过，耗时 246.83 秒；原生 17 组共 123 项通过，各脚本退出 0，peer_errors 为空，产品哈希在验证前后保持一致。最终来源和哈希存入 `build/round50-validation.json`。当前没有可用的 Linux/WSL 运行环境，本轮执行证据限于 Windows MSVC Release；未提交、推送或部署，原始 D:/cnode 的既有修改保持不变。

## 第五十一轮：AnyTLS 开流等待读取持久终态

在生产出站 Handler 的现有生命周期夹具中增加可控写入完成顺序。夹具仅替换外部拨号，实际运行出站准备、SessionPool、codec、逻辑流和 Relay；先完成 SID 1 建立可复用的 v2 会话，再让 SID 2 的开流 AsyncWrite 在帧循环处理完 FIN/错误之后才返回。等待中的新一次物理读取或物理关闭证明终态已被处理，不能用仅复制完帧字节冒充处理完成。对照组在进入等待后才投递相同报文。

扩展后的 16 项基线有 5 项失败：开流写入返回前收到空 FIN、带数据的 FIN 或 Alert 时，旧 WaitSynAck 忽略已经发生的关闭，额外等待 3 秒后返回 TIMEOUT；带数据 FIN 还丢失已接收的 5 字节并丢弃健康连接。错误 SYNACK 文本被截断的两种顺序都把真实 CONNECTION_CLOSED 改写成 PROTOCOL_DECODE_FAILED。正常 ACK、进入等待后收到 FIN/错误、真实无响应超时和父任务取消作为对照；全部场景执行后都完成资源回收及下一次请求恢复。基线程序退出 1，保存在 `round51-open-order-expanded-baseline.exe/.log`；修复后相同 16 项全部通过。最初一次夹具缺少 DNS endpoint，启动前退出，不作为产品失败证据；补全必需配置后才执行上述基线。

将 WaitSynAck 迁移为 WaitOpenResult，直接从同一逻辑对象的 ACK、关闭及首个错误推导结果。正常 FIN 允许 Relay 排空已经接收的内容，错误优先于 ACK；信号只负责唤醒，每次恢复都重新检查状态。删除重复的 ACK 错误、等待中/已超时标志和常驻超时 token，有限等待在协程作用域持有 RAII 令牌，完成、取消或异常退出都会撤销回调。超时通过同一 Close 发布终态，不能覆盖已经到达的 ACK/FIN/错误。错误 SYNACK 先完整读取错误文本，实际读取失败由物理会话以原 I/O 原因终止。本轮未改变协议拒绝时丢弃会话的既有策略，也未把协议终态分支放入通用 Relay。

`tests/anytls_open_order_integration.py` 进一步通过真实 VLESS -> Dispatcher -> AnyTLS/TLS 运行两种 FIN 场景。对端为下一次开流设置 4096 段填充，总计收到 32,767,972 字节填充；接收目标后暂停读取 400 ms，并在反向发送 FIN、可选 8,032 字节响应及心跳。心跳响应通过串行写入门闩，记录填充写入完成后的屏障时刻。旧产品在 FIN 后约 3.454/3.453 秒才关闭，VLESS 响应头缺失，带数据场景未交付响应，恢复请求需要第二个物理连接；新产品约 0.454/0.469 秒完成关闭，响应头及数据完整，同一个物理连接处理 SID 1、2、3。两版产品在清理前都保持运行、没有 peer_errors；旧版脚本退出 1，新版退出 0。最终观测分别存于 `round51-network-open-verified-baseline` 和 `round51-native-open-order`，不把首次收集器在缺失 VLESS 头时提前结束的记录计作完整测量。

最终产品 SHA-256 为 `7c56500708907d5ee598ed57f23cafc9cd731f596c3e9965e7949a3a098f3a90`。完整 Release 构建退出 0；全量 CTest 119/119 实际执行通过、无跳过，耗时 255.13 秒，新增 16 项包含在生产出站生命周期测试内。原生 18 组共 125 项通过，包括上述两个新网络场景，各脚本退出 0、产品哈希保持一致。证据及来源哈希记录在 `build/round51-validation.json`。本轮编辑均在隔离 worktree 中进行，没有写入原始 D:/cnode，未提交、推送或部署；Linux 运行验证仍不可用。

## 第五十二轮：AnyTLS 填充方案与帧编码分层

在旧 ParsePaddingScheme 上增加 C++ 分配拦截器，单次请求超过 1 MiB 时在 malloc 前拒绝。5 项基线中 4 项失败：32 字节规则文本要求单次分配 51,539,607,591 字节，原因是嵌套 vector 按远端最大索引 resize。该容量只是拦截到的分配请求，没有实际分配约 48 GiB 内存，也没有把危险输入发送给旧产品。基线程序及日志保存在 `round52-padding-allocation-baseline.exe/.log`，退出 1。首次 CMake 夹具使用了不存在的源文件路径，生成失败；修正为实际依赖后才取得上述产品基线，不把生成错误算作产品缺陷。

新增协议私有 padding.hpp/cpp，负责文本解析、MD5、尺寸采样和不可变稀疏方案。解析阶段只为实际规则创建映射，再形成排序的连续索引，查询使用 lower_bound，不分配、不写入；codec 只调用只读规则及采样尺寸。保留原始文本、最后有效重复规则、范围交换、常量及 c 标记语义，索引与 stop 采用完整 uint32 范围，stop 必须大于零。删除 codec 内的旧解析器、文本分割容器、摘要计算、按索引扩张容器及旧查找 helper，没有保留转接层。

默认方案构建一次并以 shared_ptr<const PaddingScheme> 共享。入站 prepared settings、各 Worker Handler 和物理 Session 共享完整只读方案，删除多层 raw/md5 字符串复制；出站收到合法更新后替换 const 方案，在途写入继续持有旧对象。空方案仍服务入站无填充写入的实际调用。PaddingScheme 不公开可变记录或 stop，包序号由 Session 递增并在 UINT32_MAX 饱和，是否填充由方案自己判断。

实际 TLS 基线同时发现 stop 的旧行为错误：会话到达 stop 后把索引改为 0，继续套用认证规则。25 字节测试规则下，SID 2 出现多余的 106 字节 Waste，SID 3 又出现 100 和 106 字节 Waste；所有请求使用同一个健康 TLS 连接，产品存活，失败不能由断线或进程崩溃解释。修复后 SID 2 只保留停止前预期的 68 字节 Waste，SID 3 没有填充。基线脚本退出 1，新实现退出 0，记录分别为 `round52-padding-stop-baseline` 与 `round52-native-padding`。

专用 padding 测试仅链接私有模块与 crypto，移除原夹具对 codec、transport、session、stats、日志及 Asio 的依赖。6 项分配测试全部通过，同一 32 字节输入最大 C++ 分配降至 64 字节、累计 376 字节；2,048 条稀疏规则原文 34,832 字节，累计请求 256,222 字节，全部可查询。另有 4,131 项检查，覆盖无效输入、完整索引边界、重复规则、采样范围、认证回退、查询零分配及默认对象复用零分配。该计量描述 C++ 分配请求，不等于整个进程的 RSS。

新增 7 项原生网络场景：字符串/数组配置分别测试 MD5 匹配及更新，每项使用双 Worker、4 个物理连接和 8 条逻辑流；出站测试两种大索引更新、无效更新保留旧方案，以及 stop 后的真实帧行为。原始文本和 MD5 按配置归一化后的字节准确对应，所有出站场景用一个物理连接完成 SID 1、2、3。旧有 AnyTLS/TLS 背压、FIN、UDP/UoT、生命周期及异常分类回归继续保留。

最终产品 SHA-256 为 `51a78b78097175a5b2680ec562964eaf012d7ae6f86ce0ad748fe4a184a07fe8`。完整 Release 构建退出 0，全量 CTest 120/120 实际执行通过、无跳过，耗时 255.06 秒。原生首轮 19 组共 132 项中 131 项通过，唯一失败是未修改的官方参考客户端在 remote-fin 场景收到 Windows 10053，cnode 对应场景及其余场景通过。保留首次失败，给原夹具增加异常堆栈记录后，使用完全相同的三个二进制单独复测 FIN 组 8/8 通过，退出 0；未改变断言或产品代码。第一次异常的具体触发点仍未确定，不能把复测通过说成首次没有异常。最终 132 个不同场景均有通过记录，FIN 组采用 `round52-native-fin-oracle-recheck`，不重复累计首次的 7 项通过。来源、首轮失败和最终观测存入 `build/round52-validation.json`。原始 D:/cnode 的修改保持不变；未提交、推送或部署，执行证据仍限于 Windows MSVC Release。

## 第五十三轮：填充配置在发布前满足更新帧容量

新增原生 AnyTLS/TLS 配置边界夹具，使用原始文本及数组两种入口，验证 ASCII 和 UTF-8 文本。旧版 8 项中 3 项失败：65,536 字节的方案被接纳，进程完成启动，但客户端请求更新时连接关闭，没有更新帧、响应或目标连接；65,535 字节及以下能完整下发并完成应用请求。基线使用第五十二轮产品 `51a78b78097175a5b2680ec562964eaf012d7ae6f86ce0ad748fe4a184a07fe8`，程序始终存活，记录位于 `round53-padding-bounds-baseline`，脚本退出 1。

入站协议 prepare_settings 在构建方案前按统一的 kMaxFramePayload 检查归一化原文长度，超限返回准备失败并记录容量原因。静态启动的 PrepareStartupInbounds 通过同一 PrepareBuildRequest 接收结果，在发布用户及构建监听之前报告配置错误。校验位置负责协议可发送性，JSON 解析仍负责字符串或数组归一化，padding 模块继续负责方案语义。UTF-8 字节和数组元素之间的换行均纳入长度，保持单个 UpdatePaddingScheme 帧的 16 位容量边界。

最终边界夹具 8/8 通过：31、65,534、65,535 字节的合法方案返回完整原始字节并实际连接目标；65,536 字节的 ASCII、UTF-8 字符串及 UTF-8 数组均在服务启动前退出 1，目标请求数为零。UTF-8 超限样本只有 21,862 个字符，证明检查的是字节数。首次新版采集器只在控制台查找具体告警，导致三个已正确拒绝的配置被判为失败；实际原因位于 error_*.log。补充文件日志读取后，使用相同产品二进制重新执行，控制台通用错误和文件中的具体容量告警均被验证。首次记录保留，最终结果为 `round53-native-padding-bounds-final`。

原生 FIN 组本轮出现一次 Windows 10053，堆栈定位到 Python 客户端的 observe_eof。旧夹具在响应读取结束前向已收到 FIN 的连接写入 LATE，可能中止同一客户端 socket 的未完成读取。独立纯 TCP 对照实验不使用 cnode 或官方代理程序：8 次先写迟到数据均在完整收到 262,144 字节后报告 10053、没有观察到 EOF；8 次先读完并确认 EOF 再写迟到数据均正常。实验位于 `round53-fin-observer-probe.py/.json/.log`，旧 FIN 夹具保存在 `round53-fin-observer-before.py`。

FIN 夹具改为先在上传仍打开时验证响应完整性及 EOF，再发送迟到数据并检查对端没有收到它。应用内容、EOF、FIN 数量、后续连接复用和迟到数据不转发的断言继续执行，避免故意的迟到写入污染先前的读取观测。相同三个二进制下，修正后的官方与 cnode FIN 场景 8/8 通过，记录为 `round53-native-fin-oracle-final`。

最终产品 SHA-256 为 `a6a0487c49db52b79025d0e65ca01eec0ff86bf99be348b4c266dc1c21a4cc3b`。完整 Release 构建退出 0，全量 CTest 120/120 实际执行通过、无跳过，耗时 255.04 秒。原生首轮 20 组 140 项中 136 项通过，保留上述三项日志采集失败和一项 FIN 观测失败；两组夹具修正后分别 8/8 通过，最终按不同场景累计 140 项，未重复计数。结果、失败来源及哈希在 `build/round53-validation.json` 中归档。未提交、推送或部署，原始 D:/cnode 的既有修改保持不变；本轮执行环境为 Windows MSVC Release，Linux 运行仍未验证。

## 第五十四轮：下发填充方案归属出站客户端

固定参考版本 `fd6167acd6d73b9fa3e607659951847fbc9e6c50` 的协议文档要求服务器下发的方案归属连接该服务器的 Client，并供后续新建会话使用。本轮核对该参考目录 HEAD 及工作树状态，版本一致且没有修改。旧实现把方案保存在单个 ClientSession 中，新物理连接的认证、settings 及数据填充重新使用默认值。

新增原生 TLS 重连夹具，分别验证不同服务器端点、相同端点不同出站凭据、65,535 字节认证填充。每项由客户端 A、B 交错建立 5 个物理连接，先接收各自方案及一个无效更新；对端用 Alert 结束物理会话，并等待收到 cnode 的关闭后再发起下一请求，避免借到尚未处理 EOF 的空闲连接。基线 3 项均失败，后续共 9 次连接仍使用 30 字节认证及默认 MD5；15 次应用请求均成功，产品存活，无 peer_errors。对照记录为 `round54-client-padding-baseline`，脚本退出 1。

新增仅属于 Worker-local 出站客户端的 PaddingState，Handler 和自己的物理任务共享该状态的所有权，内部始终保存 shared_ptr<const PaddingScheme>。更新在所属 Worker 内整体替换，物理连接结束后由 Handler 继续保存方案。不同 Handler 即使地址、端口或 tag 相同也独立构建状态，后台任务持有状态而非借用 Handler；该设计不使用进程级可变缓存或跨 Worker 状态。

新连接在认证前取得 opening_scheme 快照，认证长度、首次 ClientSettings 摘要及首次开流帧都使用它。开流成功后释放快照，其是否存在同时表示 settings 是否已发送，删除独立 settings_sent 标志。后续写入读取客户端当前方案，并在各次 I/O 期间持有本次快照。DefaultClientSettings 完整迁移为接收方案的 ClientSettings，旧默认格式化入口和物理会话独立方案字段均已删除。认证缓冲按 34 字节头加实际 uint16 填充长度临时构建，在认证作用域结束时释放，最大方案长度可使用而不受原来 30 字节数组容量限制。

现有生产出站生命周期夹具新增一次可控交错：首个请求保持活动并下发 A=45，第二物理连接认证写入期间让第一连接下发 B=91；心跳响应证明 B 已处理后，才完成第二连接的认证写入。第二连接仍发送 A 的认证、MD5 及 160 字节开流 Waste；第三连接发送 B 的认证、MD5 及 224 字节 Waste。随后在旧 Handler 后台清理仍未结束时构建相同参数及 tag 的新 Handler，新连接恢复默认 30 字节认证和默认摘要。四个物理任务都完成关闭、销毁和 join，认证序列为 `30,45,91,30`。专用运行与最终 CTest 均通过。

新版原生 3 项全部通过，A/B 分别保持自己的方案，最大认证场景的后续 A 连接完整发送 65,535 字节填充；客户端设置摘要、实际 Waste 长度及重连次数均准确。完整 Release 构建退出 0，最终产品 SHA-256 为 `ae5a8ad429f18b83f0affc4452eb11191655675e6442b8ede9100f15a494d873`。CTest 120/120 实际执行通过、无跳过，耗时 255.11 秒；原生 21 组共 143 项全部通过，各脚本退出 0，无 peer_errors。来源及哈希在 `build/round54-validation.json` 中归档。原始 D:/cnode 修改保持不变，未提交、推送或部署；WSL 当前没有已安装的发行版，运行验证限于 Windows MSVC Release。

## 第五十五轮：认证长度与会话分段规则分离

重新核对固定参考目录 HEAD 为 `fd6167acd6d73b9fa3e607659951847fbc9e6c50` 且工作树无修改。其协议文档将索引 0 定义为不可分段的认证部分；cmd/client/myclient.go 使用索引 0 的采样结果，缺省为零；proxy/padding/padding.go 允许仅含 stop 的方案。旧 cnode 把认证存为普通帧记录，只读取第一条规则的最小值，缺失、c 标记或长度超限时回退为 30。

新增原生 TLS 下发及重连夹具，共 19 项、136 个物理连接。每项先从默认方案学习已知的 45 字节方案，再接收候选更新；心跳响应确认更新已处理，Alert 后等待对端观察到关闭，再建立新连接。逐次验证认证哈希、实际 uint16 长度及全部零填充、ClientSettings 摘要、目标地址、应用往返和 EOF。基线 `round55-auth-padding-baseline` 使用第五十四轮二进制，3 项控制场景通过、16 项未满足新约束：缺省和显式零仍发 30 字节，stop-only 保留旧 45 字节方案，两个长度范围各 32 次全部只取 45，11 项无效认证更新错误替换方案。全部 136 次应用往返完成、产品存活、无 peer_errors；其中 28 个连接的长度或摘要不符，另外两项通过采样不变化识别。拒绝不支持的认证格式是本轮明确收紧的接纳规则，不表示参考实现也逐项拒绝它们。

PaddingScheme 为认证保存独立的有界单范围，不再将索引 0 放入会话记录。SampleAuthPaddingSize 对已校验的范围采样，删除 AuthPaddingSize 及 kDefaultAuthPaddingSize；协议私有 ParseRange 和 SampleRange 被认证与会话解析复用。缺少认证规则或显式 0-0 时长度为零；正数范围允许逆序并采用半开区间，相等时为常量，所有可能输出必须满足 uint16 容量，65535-65536 合法。认证 c 标记、多个范围、空值、格式错误、零与正数混合或可能溢出的范围均拒绝整个方案；有效重复认证规则以最后一条为准，任何无效认证行都会使方案失败。会话规则保留正数分段、c 标记和最后有效重复项语义，stop-only 及仅含被忽略数据项的方案可编译为空填充策略。

出站认证调用完成迁移，仍持有第五十四轮的 opening_scheme 快照。静态入站通过既有 prepare_settings 接收同一解析结果，补充字符串超界范围及数组 c 标记的冷路径拒绝检查。codec 错误传播测试原先使用索引 0 构造帧填充，现迁移到真实会话索引 1，继续验证原有错误和所有权行为。README 已写明单段约束、空方案及无隐式回退语义。

新版原生认证组 19/19 首次通过：缺省、stop-only 和显式零发送零字节；两个范围产生多个不同长度，均在 [45,77) 内；上边界完整发送 65,535 字节；全部 11 项无效更新保留此前 45 字节方案及其 MD5。原始基线与最终对照保存在 `round55-auth-padding-baseline` 和 `round55-native-auth-padding`。

完整 Release 构建退出 0，最终产品 SHA-256 为 `1aff655ba958e8c506877191ddc820f985a3785533580b0ee59bbc8bd692f164`。CTest 120/120 实际执行通过、无跳过，耗时 255.46 秒；其中 padding-policy 8,243 项检查和 6 项分配检查通过，2,048 条稀疏规则累计 C++ 分配仍为 256,222 字节，上一轮认证中更新及 Handler 退役快照检查继续通过。原生 22 组 162 项全部首次通过，脚本退出 0，无 peer_errors。配置测试会在成功后清理前段生成目录，证据保留其源文件和本轮实际 CTest 日志，不重建目录冒充执行记录。来源与哈希在 `build/round55-validation.json` 归档。运行验证限于 Windows MSVC Release，未执行 Linux 验证；原始 D:/cnode 保持原有修改，未提交、推送或部署。

## 第五十六轮：会话填充服从协议容量

旧 WritePacketWithPadding 将有效尺寸限制为大于 7 且小于 Buffer::kSize（8,192），并依赖同样大小的静态零填充块。规则解析却接受这些范围，导致已经发布的策略在发送时失败。固定参考 `fd6167acd6d73b9fa3e607659951847fbc9e6c50` 的 writeConn 允许任意正数分段，帧头可以跨 Write；纯 Waste 的长度字段为 uint16，意味着预构建记录的所有可能输出均须可编码。

新增原生 TLS 夹具 `anytls_frame_padding_integration.py`：先学习已知方案，再下发候选方案，经心跳确认和物理关闭后重连两次，验证认证、settings、目标请求、完整应用往返及每个 Waste 的长度和全部零字节。19 项基线共 76 个物理连接，3 项通过、16 项失败；其中 28 次请求因发送失败未完成，另 4 次请求完成但接受了超限更新，摘要与应保留方案不符。两项静默接纳分别是 c 后的超限规则及先超限、后有效的重复项。所有基线子进程存活，无 peer_errors，保存在 `round56-frame-padding-baseline`。

同一夹具还以未修改的官方客户端执行 14 项可编码场景，全部通过，涵盖 1/7/8 字节分段、8,191/8,192/8,193/16,384 字节、65,535 字节、半开及逆序边界、先分段后填充、纯 Waste 和 c 标记。官方客户端 SHA-256 为 `f1684b54f68892cade49eb109f44af5dfb76d32822f7900b4d90427772b6b159`，go version -m 验证固定提交及 vcs.modified=false。其 client 字段比 cnode 长 8 字节，混合 Waste 的预期长度据此调整，字段顺序按 Go map 语义比较；超限候选未发送给官方实现。首次参考结果位于 `round56-frame-padding-reference`。

ParseRanges 现在区分可忽略的无效 token 与已解析但不可编码的范围；后者使整个方案失败。每个正数范围的最大可能采样值须不超过 UINT16_MAX，包含 c 后或后续会被重复项覆盖的范围。认证和会话解析共用私有 LargestSize 计算，半开上界 65,536 只在实际输出不超过 65,535 时有效。静态入站沿同一 prepare_settings 拒绝不可编码方案，补充字符串常量超限和数组范围超限检查。

codec 删除 Buffer::kSize 判断及 ZeroPaddingBlock，直接消费预构建的正数尺寸。纯数据分段使用已有 packet 的只读 span，在 WriteAll 完成前保持所有权；只有混合填充或纯 Waste 才构建本次临时 record。私有 AppendWaste 按 uint16 长度扩展并清零目标区，使用已有帧头编码函数，不保留长期 scratch。所有实际 I/O 错误继续由 WriteAll 传回，不增加协议外分支或第二条链路。

新版原生场景 19/19 首次通过，76 次应用请求全部完成；五项超限候选均保留已学到的方案和 MD5。官方对照 14/14 也在最终回归中通过，完整验证 65,535 字节纯 Waste，而非仅证明连接存活。codec 错误测试扩展至 277 项，包括小分段、两个连续的大填充帧以及在第二帧内累计传输 65,536 字节后触发异常；全部通过并释放所跟踪 Buffer。padding-policy 8,259 项和 6 项分配检查通过，稀疏存储的累计分配界限保持不变。

完整 Release 构建退出 0，最终产品 SHA-256 为 `bb5f13c7eab2d84df7ad3d4fd8a4f22cc46a492d9be9ede56fff459cff40d6ee`。CTest 120/120 实际执行通过、无跳过，耗时 255.30 秒；原生 24 组 195 项全部首次通过，各脚本退出 0，无 peer_errors，其中包括本轮新增的 14 项官方客户端对照。证据及文件哈希保存在 `build/round56-validation.json`。运行验证限于 Windows MSVC Release，未执行 Linux 验证；原始 D:/cnode 修改保持不变，未提交、推送或部署。

## 第五十七轮：HTTP/2 半关闭、写入串行化与协议 EOF 传递

使用原生 TCP/TLS HTTP/2 夹具观察服务端同一物理连接上的三个流。空闲重复 RST_STREAM、确已受阻的下载期间重复 RST_STREAM 均在旧产物通过；PING 屏障后，保留流与新建流继续完成应用请求，没有观察到取消破坏共享帧。初版受阻场景未证实反压、半关闭观察也缺少等待，保留在 round57-grpc-baseline 及 round57-grpc-fixture-initial.py；修正观察条件后的基线位于 round57-grpc-baseline-observed，不能把夹具问题计为产品缺陷。

有效基线中的 TCP/TLS END_STREAM 两项均失败：目标收到数据后持续等待写方向结束，5 秒内没有终止 trailers，进程仍存活。GrpcStream 和 GrpcServerSubStream 原先继承 WaitForPeer；现在明确返回 ShutdownPeerWrite。VLESS 的 pending/buffered/encryption/Vision reader、VMess 和 Shadowsocks TCP reader/endpoint 沿底层传递该语义，UDP 仍保留自身语义，Trojan TCP 原本直接使用底层流。Shadowsocks 出站写关闭等待底层 AsyncShutdownWrite。Relay 的通用实现和默认 EOF 策略未改变，协议判断仍留在协议内部。

HTTP/2 END_STREAM 结束一个发送方向，RST_STREAM 结束指定流；gRPC 使用终止 trailers 表达响应结束。验证依据为 [RFC 9113 流状态](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.1)、[RST_STREAM](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.4) 和 [gRPC HTTP/2 协议](https://grpc.github.io/grpc/core/md_doc__p_r_o_t_o_c_o_l-_h_t_t_p2.html)。原生 h2 的非空 DATA+END_STREAM 另有遗漏：旧代码先返回数据，没有记住结束标志；夹具收到 READY 后仍等不到 EOF。现在独立记录 input_done，消费已收数据后返回 EOF，反向上传仍可继续。

真实协议串联暴露 VMess 空结束帧编码失败。移除吞异常逻辑后，日志明确记录 VMess client EOF encrypt failed。当前 AWS-LC 的 custom EVP cipher 将 null input 视为结束操作；原实现对空明文执行 EncryptUpdate(nullptr, 0) 后再次 EncryptFinal，使第二次结束失败。VMessCipher 现在跳过空明文 Update，统一由 Final 生成标签。独立 cipher 测试在修复前退出 1，修复后验证 20 个连续空/非空块、零密钥零 nonce 的 AES-GCM 空标签，以及两种 AEAD 空标签篡改拒绝。删除无调用的 ResetCount；结束帧的分配、加密、随机填充和写入失败按现有错误路径返回。响应 EOF 通过现有 FlushResponseBody 发送，保证空应用响应也先发响应头。

扩展请求次数后，串联测试还出现只收到 16,276 字节便中断的情况，记录在 round57-grpc-eof-expanded 和 round57-grpc-stress-trace。源码中，单连接 GrpcStream 的 DATA 写入与读取协程发出的 SETTINGS/PING/WINDOW_UPDATE 没有共同串行化，可能在底层挂起期间交错。现在所有数据写入、控制帧和结束帧共用 Worker executor 上的 AsyncWriteGate；取消/关闭唤醒等待者，租约限定在完整写入期间，不引入跨线程锁。修复后四种协议、VMess AES/ChaCha/none/zero 和空响应串联全部完成；每种场景在同一前端物理连接连续执行 8 个请求，每个请求校验 48,001 字节的精确往返或预期空响应。

本轮新增 grpc_substream_integration.py 六项、grpc_eof_integration.py 十二项；后者包括八项协议串联及 gRPC trailers / h2 DATA 在 TCP/TLS 上的四项响应 EOF，验证关闭响应方向后仍能上传 18 字节。所有夹具在清理前记录目标 EOF 和进程状态，清理过程取消并等待子任务结束。VMess cipher 层的损坏标签验证不等于请求/响应 EOF 解码器已验证标签，后者列入下一轮审查。

完整 Release 构建退出 0，最终产品 SHA-256 为 `2eb87de33c7ea884b1ff222bbce888faa76b6f3fecbd830b33c2d676af2dc194`。CTest 121/121 实际执行通过、无跳过，耗时 255.36 秒；原生 26 组 213 项在最终回归中全部首次通过，脚本退出 0、无 peer_errors。新增八项串联共完成 64 个请求，四项响应 EOF 场景均在收到 EOF 后继续成功上传。原始 D:/cnode 状态保持不变，未提交、推送或部署；运行验证限于 Windows MSVC Release。失败基线、最终结果、源码和产物哈希保存在 `build/round57-validation.json`。

## 第五十八轮：共享有界 Hunk 解析与客户端传输职责

旧客户端和服务端 ReadNextGrpcMessage 在读到五字节长度头后立即构造 ByteVector(len)，尚未读取消息体。将两处原始函数体和原始 protobuf helper 提取到隔离异步夹具，使用项目实际 allocator、只提供长度头的输入和 1 MiB 分配拦截器。4 MiB、4 MiB+1 和 UINT32_MAX 的六次请求均在读取消息体前触发相应尺寸分配；最大请求为 4,294,967,295 字节，全部在分配前被拒绝。原始函数提取信息、源码哈希、独立 CMake 夹具及结果保存在 round58-baseline-harness 和 round58-baseline-allocation.log。这是原函数的隔离分配观测，超大长度没有发送给旧产品进程。

新增私有 grpc_hunk.hpp/cpp，两端统一持有 Worker-local GrpcHunkDecoder。Feed 增量接收 HTTP/2 DATA 中的实际字节，长度头使用固定五字节状态，不按声明长度 reserve/resize。消息正文上限明确为 4 MiB，与 [gRPC 默认接收上限](https://grpc.github.io/grpc/cpp/group__grpc__arg__keys.html)一致；这是 cnode 的资源策略。实际收到的正文按有上限的几何增长存储，完整 protobuf 校验后才暴露只读 data 视图；Consume 和 Clear 释放已消费或关闭消息的存储。HTTP/2 队列、取消和原始 body 读取继续归属于各自的传输对象。

解析验证字段号、wire type、varint 溢出、字段长度、未知字段和有深度上限的未知 group；检查整个消息而非遇到首个 data 就返回。重复的 singular bytes 字段使用最后一个值，后一个空值覆盖先前数据，符合 [protobuf 编码语义](https://protobuf.dev/programming-guides/encoding/#last-one-wins)。零长度消息和没有 data 的合法消息继续等待下一条；消息头或正文被截断时报告错误，不把半条消息当成正常 EOF。发送端将大写入分成多条满足同一上限的 Hunk，字节流语义保持一致。

删除两端重复的 ReadNextGrpcMessage / ReadGrpcBytes、旧 ReadProtoVarint / DecodeGrpcHunkData 以及各自的完整消息存储和游标。单连接传输更名为 Http2ClientStream，删除从未构造的 Server role、对应分支和无用途的 conn_id 成员；客户端仍负责单个物理连接，服务端子流仍由既有 session 持有。没有增加 public wrapper、协议外判断或第二条请求链路。

新增 grpc_hunk_test 验证分片、拼接消息、重复字段、非法尾部、varint/字段号溢出、未知 group 深度及完整 4 MiB 边界；对长度头和少量已收正文分别观测分配，并跟踪消费后的释放。头部声明 1,024、4,194,304、4,194,305 和 UINT32_MAX 时消息分配均为零；前两项等待正文，后两项立即拒绝。4 MiB 消息的存储上限和扩容期间旧/新分配的临时峰值分别核验，不将峰值等同于最终持有量。

原生 grpc_hunk_integration.py 用 TCP/TLS 分别驱动真实入站与出站解析器。48 项旧产物基线中 20 项通过、28 项失败：重复字段和未知 group 未按预期处理，非法尾部、越界字段号和溢出 varint 可使先前 data 进入代理协议或目标。初次观察把拒绝后的 TCP reset 计为夹具错误，已保存初版；诊断确认 ConnectionResetError 后，仅在无应用输出的拒绝场景接纳该关闭，保留接收的全部字节并检查恢复请求。修正后的基线为 round58-hunk-baseline-observed，未发生 peer_errors。

新版 56 项全部通过，包含四个完整 4 MiB 消息的收取与应用验证，以及额外八个超限长度头拒绝场景；所有场景检查应用结果、进程存活和后续请求恢复，入站还验证同一 HTTP/2 物理连接的新流。超限长度头仅针对已由单元测试证明有边界的新产物发送。对应最终回归位于 round58-native-grpc-hunk。

完整 Release 构建退出 0，最终产品 SHA-256 为 `ba11e5084b93e8d6a9d24e80c0c57875128930c00adc77a9469e2e19d91096a7`。CTest 122/122 实际执行通过、无跳过，耗时 255.57 秒；原生 27 组 269 项在最终回归中全部首次通过，脚本退出 0、无 peer_errors。Hunk 单元测试 2,115 项检查通过：只收到两字节正文时分配 256 字节，完整边界消息最大单次分配 4,194,304 字节，累计分配 12,648,208 字节，扩容瞬间峰值 7,028,656 字节，消费后所跟踪的大块分配归零。运行验证限于 Windows MSVC Release；原始 D:/cnode 状态保持不变，未提交、推送或部署。证据及文件哈希保存在 `build/round58-validation.json`。

## 第五十九轮：统一 HTTP/2 会话入口与错误边界

原服务端将流 ID 无效和达到 256 流容量都折叠成 CreateStream 返回空指针，调用方因此关闭整个连接。接收队列超过 4 MiB 时虽然只取消该流，却发送零字节载荷的 RST_STREAM。原生夹具暂停目标读取，以有上限的上传制造真实队列压力；旧产物六个 TCP/TLS × gRPC/h2/XHTTP 场景均返回空 RST_STREAM。另六个容量场景先确认 256 个流已接纳，第 257 个请求导致共享连接断开。该夹具观察控制帧并限制上传总量，不是完整 HTTP/2 流控验证器。

将 GrpcServerSession / GrpcServerSubStreamState / GrpcServerSubStream 更名为私有 Http2ServerSession / Http2ServerSubStreamState / Http2ServerSubStream，明确它们服务所有 HTTP/2 body codec。删除 gRPC 独立处理首个 HEADERS、CONTINUATION 和子流构造的路径，统一通过 StartHttp2ServerSession、HandleFrame 和唯一的流准入点处理首流及后续流。首个流也由 prepared transport handler 进入既有 inbound -> Dispatcher -> outbound -> relay 链路；原 HEADERS 的 END_STREAM 标志跨 CONTINUATION 保留。

会话先完整解码 header block，再执行流 ID 和容量准入，拒绝的流也更新连接级 HPACK 状态。准入成功后只在所属 Worker 构造及持有子流，服务端 SETTINGS 明确公布最大并发流数 256。容量拒绝通过 REFUSED_STREAM 返回，接收队列超限通过 ENHANCE_YOUR_CALM 返回，均编码四字节错误码。新流 ID 在容量拒绝后仍推进，释放一个已接纳流后允许更大的新 ID 进入。容量测试在被拒绝的 513 号流上增加 HPACK 动态项，恢复流 515 引用索引 62 并完成实际代理通信，验证拒绝没有破坏共享压缩状态。

统一 ResetStream 和 FailConnection 区分流与连接生命周期。RST_STREAM 的错误长度、零 ID、偶数 ID和 idle ID 按连接错误处理，发送带最后流 ID 和错误码的 GOAWAY 后关闭；SETTINGS 和 PING 的结构及连接归属在首流之前和运行态使用同一入口校验。行为依据 [RFC 9113 的流与连接错误区分及 RST_STREAM 定义](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.4)。未知扩展帧仍按 HTTP/2 规则忽略，独立 CONTINUATION 和服务端收到 PUSH_PROMISE 作为协议错误处理。

CloseAbortive 现在停止并移除所属子流，再通过共享写入门发送 CANCEL；正常 Close 保留原有 trailers / END_STREAM 语义。拿到写入门后重新确认流仍被会话持有，阻止排队期间已被移除的流继续发送数据或成功结束帧。移除无调用的 StreamId 访问器、子流无用途的 conn_id 状态及构造参数；XHTTP 各模式复用已准入子流，不再各自构造，并去掉 co_spawn 失败后解引用已移动 upload 的路径。

新增 http2_server_errors_integration.py，最终旧产物基线为 60 项中的 4 项通过、56 项失败。新版验证六个真实队列超限、六个 257 流准入与恢复、六个分片首 HEADERS 的 END_STREAM、24 个运行态错误 RST_STREAM 和 18 个首流之前的控制帧错误。流错误检查现有流通信、PING、恢复新流及关闭后的帧；连接错误检查 GOAWAY 错误码、关闭和后续新连接恢复。新增 XHTTP 网络验证限于 stream-one，其他 XHTTP 模式仍需补充独立端到端回归。

初版 XHTTP 夹具缺少配置归一化后的尾部斜杠，已修正并保留初版及其观察结果。初版 END_STREAM 观察器和原 Hunk 拒绝测试仅等待成功 trailers；实际空代理请求或解析失败现在通过 CANCEL 终止。保留初始结果后收紧 Hunk 的 18 个拒绝用例：必须恰好一次收到四字节 CANCEL、目标请求和应用输出均为零，并完成同一物理连接的新流。没有把等待旧 trailers 的超时当作新版消息解析失败。

最终 Release 全量构建退出 0，产品 SHA-256 为 `287064422efc40c9bfe1a924dc7653b3746f3b6573ec804ad36ca691027bb1b3`。CTest 122/122 实际执行通过、无跳过，耗时 256.13 秒；最终原生回归 28 组 329 项全部通过，脚本退出 0、无 peer_errors。最终验证结果与逐文件哈希保存在 build/round59-validation.json；原始 D:/cnode 的既有七个修改文件及 .codex/ 保持不变。运行验证限于 Windows MSVC Release，没有执行 Linux 或生产部署。

## 下一轮审查入口

HTTP/2 的完整双向流控、关闭态的后续 HEADERS/DATA、其他类型的帧结构与 HTTP 请求语义校验仍待审查；本轮队列压力用例不证明这些行为完整。XHTTP packet-up / stream-up 的共享连接隔离需补充真实网络回归。

VMess EOF 解码分支目前按长度识别结束、跳过标签认证，需补充请求与响应两个方向的实际帧校验及截断错误归属。

默认嗅探预读对服务器先发协议的等待行为仍待审查。此前已修正协议 Process 范围内的 bad_alloc 分类；该范围之前的 metadata/transport 构造异常归属仍待审查。

继续沿 UDP/Mux/UoT 控制接口检查职责边界，保留唯一 Dispatcher -> outbound -> relay 请求链路和 Worker-local 所有权。后续仍需补充 Linux SO_REUSEPORT 与真实 UDP 冲突验证；面板 HTTP 请求超时的真实 TLS 对端故障注入仍待补充。

## 2026-09-30 阶段审查：面板 PImpl 协程边界

本轮基线 `ebcbd0a`，工作区 `D:/cnode`，未提交、推送或部署。移除 V2Board 外观层七个只做 `co_return co_await impl_->...` 的协程，直接返回 Impl 的任务；`HttpRequest` 同样直接返回拥有 exchange 和超时预算的 `http::RunRequest`。没有新增公开类型、共享所有权或请求链路。

逐项目标审计（是阶段证据，不是全项目完成声明）：

| 要求 / 成功标准 | 当前实物证据 | 覆盖限制 |
| --- | --- | --- |
| 分层清晰：协议、分发、选路、出站、转发各司其职 | `architecture_layering_contract_test.cmake` 检查核心层和协议依赖；本轮检查 `DefaultDispatcher::RouteAsync`、`SelectRoute`、`FinishRoute`、`outbound_handler->Process` | 源码契约不能证明所有实现的语义边界；尚未逐个审查全部协议 |
| 边界清晰：生命周期、取消和临时参数的所有者明确 | `PanelRuntime::client` 唯一持有 API；`request_task.hpp::RunRequest` 持有 exchange，取消后等待其完成；请求取消、超时、面板生命周期与独立心跳行为测试通过 | 本轮网络验证为 Windows；没有新增真实 HTTPS 故障注入 |
| 调用链统一：入站 → Dispatcher → outbound → relay | 检查 VLESS TCP/UDP 入站的 `dispatcher.Dispatch`、分发的 `outbound_handler->Process` 与出站的 `DoRelayLink`；全量含 UDP relay、首包、分发取消和静态出口回归 | 一个协议的调用链检查及全量绿灯不等于全部协议已逐段审计 |
| 无过度协程包装：纯转发不建额外帧，必要收束保留 | 七个 API 外观方法和 `HttpRequest` 直接返回任务；新增源码契约固定这八个入口；恢复 GetNodeInfo 包装的变异实现被契约拒绝，恢复后通过 | `HttpGet` / `HttpPost` 仍需维持表达式内 optional/json/string 临时值到子任务结束；不能机械改成直接 return。其他协程包装尚未全部分类 |
| PImpl 低耦合：实现依赖不逃逸，不为外观新增异步层 | `APIClient` 和完整 Impl 都仅在 `src/api/v2board/v2board.cpp`；API 公共头没有面板实现类型；本轮不改变所有权或公开契约 | 仅检查了此面板和 Router 的 Impl 边界；尚未审查全仓所有 PImpl |

本地 MSVC 19.44、Release、测试开启、LTO 关闭构建通过。最终全量 CTest **142/142，通过，83.62 秒**，无跳过。初始化环境时的失败分别来自缺少 Python、MSVC 默认代码页、AWS-LC 的 C4577 警告以及嵌入式 Python 的导入路径和 cryptography 缺失；补齐本地构建参数和临时 Python 环境后重新跑完整套件，不把早期失败或分批通过当成最终绿灯。没有为环境问题修改产品源码。

证据在 `C:/Users/Administrator/AppData/Local/Temp/cnode-architecture/`：`configure.log`、`build.log`、`build-final.log`、`ctest-final.log`、`contract-mutant.log`、`contract-restored.log`。临时 Python 仅用于本地验证，未进入仓库。新增契约只证明指定入口没有转发协程，不能替代生命周期行为测试，也不能用 142 项通过宣称整个架构目标完成；目标保持 active。

## 2026-09-30 阶段审查：DNS 客户端与主控 Impl 合并边界

继续检查 PImpl 后发现 `DNS` 同时拥有公开本地服务与远程客户端两种模式：生产走 DNSWorker，部分行为测试却直接构造本地 DNS 并同步读缓存。将缓存、在途解析、上游 socket 和有界 mailbox 直接合并到 `DNSWorker::Impl`；删除 `DNS::Impl`、本地服务构造器、`DNS::Config` 别名和 `DNS::GetCacheStats`，不保留兼容入口。`DNS` 现在只有一个 DNSWorker 引用，所有调用者（包括原本直连服务的测试）走同一有界路径。客户端公共头不再包含服务配置、统计或 PImpl 所有权头。

`DNS::Resolve` 直接返回 worker 任务并在调用时复制域名；`DNSWorker::GetCacheStats` 直接返回 mailbox 任务。解析 Impl 的主入口直接按值拥有域名，删除原 `ResolveOwned` → 本地 server → Impl 的包装链。仍保留 DNSWorker 的满邮箱错误归一化、mailbox 的 executor 切换和持槽收束、实际解析的缓存/取消/在途状态协程；这些不是无职责转发。

`dns_inflight_test.cpp` 新增真实任务创建后复用调用方字符串的基线：旧实现返回修改后的地址，测试失败；修复后取得创建任务时的原地址。另覆盖临时 DNS 客户端已销毁但任务仍能完成、查询及统计两类满邮箱拒绝、取消后两类入口恢复。编译期断言禁止客户端默认构造、本地服务构造及同步统计查询。已有双调用线程结果所有权、DNS 取消、socket/ID 复用、缓存分配失败恢复和分发取消回归继续通过。初版新测试因未指定必需 DNS endpoint 而失败，补齐 loopback endpoint 后才得到有效旧行为基线；不将夹具初始化错误当成产品故障。

五项目标的本轮证据：分层与边界由唯一 DNSWorker Impl 所有权及删除公开本地入口固定；统一调用链由查询/统计都经有界 mailbox 及行为测试固定；过度协程包装由客户端和统计直接返回、解析主入口自身拥有域名消除；PImpl 低耦合由删除第二个 Impl、客户端不包含配置/统计、生产与测试不再分叉实现。全量 MSVC Release 构建成功，最终 **CTest 142/142，83.81 秒，无跳过**。日志为同一临时证据目录中的 `dns-baseline-build.log`、`dns-baseline-test.log`、`dns-owner-final-build.log`、`dns-owner-final-ctest.log`。本轮不修改 DNS wire format 或缓存策略，没有提交、推送或部署。

这些证据覆盖 DNS 与面板的本轮边界，不覆盖全仓 transport/协议包装分类；尤其 transport 的纯读写委托与 framing/首包/写门协程仍需逐个区分并验证。全仓目标继续保持 active。

## 2026-09-30 阶段审查：HTTPUpgrade 委托与 TLS 公共头

`HttpUpgradeStream` 的 `AsyncWrite`、`WriteMultiBuffer`、`WriteBuffers` 不处理协议、状态或关闭预算，只转发参数；改为直接返回底层任务。读端仍需要消费 HTTP 握手剩余字节，异步写关闭仍需要维护关闭状态，均保留。没有扩大修改到 Http1BodyStream 的 chunk framing、XHTTP 的延迟上传或 HTTP/2 子流关闭检查；这些分支不能仅凭出现 `co_return co_await` 就机械移除。

新增 `tests/http_upgrade_integration.py` 并接入 CTest，四项真实 Windows loopback 场景包括：握手与 VLESS 首包合并、分片握手、raw → VLESS/HTTPUpgrade → freedom 串联、相同串联的 HTTPUpgrade/TLS。每项逐字节校验 **180,469 字节**双向数据、VLESS 响应头、两方向 EOF 和清理前产品存活；夹具拥有并收束对端任务。旧写包装下四项也全部通过，是等价性基线，不是协议缺陷复现或性能测量。恢复 AsyncWrite 的转发协程时，新增源码契约明确失败；恢复直接返回后通过。

`tls_stream.hpp` 原本已有 PImpl，但仍包含完整 `tcp_stream.hpp`、`tls_config.hpp` 和 `<openssl/ssl.h>`。改为前置声明及 OpenSSL 不透明类型头 `<openssl/ossl_typ.h>`，公开签名不变。新增 `tls_public_surface_test.cpp` 独立编译、不使用 PCH，验证只包含此公共头时 TCP、TLS/REALITY 配置和 SSL/SSL_CTX 均不完整，同时仍可检查工厂、构造器、native handle 和握手任务的类型。人工重新引入 TCP 头时，编译断言与源码契约都失败；恢复后完整构建和测试通过。没有新增 adapter 或 type-erasure。

本轮证据继续对应五项目标：分层由 HTTPUpgrade 保持字节传输职责、TLS 实现依赖不进入公共头固定；边界由 pending 字节与关闭状态协程保留及网络 EOF 检查固定；统一调用链由真实 VLESS 串联走同一 Dispatcher/outbound/relay 验证；纯转发协程由三个写入口直接返回和变异契约固定；PImpl 低耦合由公共头独立编译和不完整类型断言固定。

最终 MSVC Release 构建成功；**CTest 144/144，84.86 秒，无跳过**。临时证据目录继续为 `C:/Users/Administrator/AppData/Local/Temp/cnode-architecture/`：`http-upgrade-baseline.log`、`upgrade-focused.log`、`upgrade-mutant.log`、`tls-surface-mutant-build.log`、`tls-surface-mutant-contract.log`、`transport-final-build.log`、`transport-final-ctest.log`。新网络场景的逐项报告在 `build/http_upgrade_integration_test/{coalesced,fragmented,chain,chain-tls}/result.json`。没有提交、推送或部署。

本轮只验证上述透明委托和公共头边界，尚不证明 HTTP/2/XHTTP 全部状态分支、其他协议包装及所有 PImpl 的审计完成。目标保持 active，不用全量测试绿灯代替全仓完成审计。

## 2026-09-30 阶段审查：AnyTLS 窄入口与入站 Manager 公共头

`WriteFrameBody` 仅由 codec 故障测试调用，没有生产调用；其实现只是把 Buffer 转为 span 后再套一个 WriteFrame 协程。删除声明及实现，不做兼容转接。原测试直接以 Buffer 的字节视图调用生产 `WriteFrame`，Buffer 仍由测试请求作用域持有到异步写结束；保留该用例的异常、部分写入和释放检查。codec **279/279** 用例通过，`released=1`。源码契约拒绝恢复此 Buffer 专用包装入口。其他带 padding 的函数仍持有 packet、record 或 MB 直到实际写入结束，不因末尾出现 co_await 就视为纯转发。

入站 Manager 公共 PImpl 头只使用 `const BuildRequest&`，不应传递包含 prepared 用户和凭据定义；改为前置声明，调用方需要构造值时显式包含其定义。不改变 runtime 接口、manager 所有权或请求调用链。同步纠正已过时的 detached 子流与无界 post 注释，明确 Worker-local 替换及跨线程有界 mailbox。新增独立、不使用 PCH 的 `inbound_manager_public_surface_test.cpp`，验证 BuildRequest、Handler 和 Inbound 在公共头中保持不完整，同时 Manager 构造及 NewHandler 的签名可用。恢复 prepared_config include 的变异实现在编译期断言失败；恢复后完整构建成功，定向测试通过。

本轮对应目标：层级边界由 Manager 不传递协议准备数据定义固定；生命周期由已有 WriteFrame 测试在完成前保有 Buffer 及 279 项回收检查固定；统一调用链由测试与生产都进入 WriteFrame 而非测试专用入口固定；无多余协程由直接删除 WriteFrameBody 固定；PImpl 低耦合由独立编译和不完整类型断言固定。这是局部完成证据，仍不代表全仓包装与 PImpl 已逐个审查。

MSVC Release 全量构建成功；**CTest 145/145，84.79 秒，无跳过**。证据继续保存在临时目录：`anytls-surface-build.log`、`anytls-surface-cases.log`、`inbound-surface-build.log`、`inbound-surface-ctest.log`、`inbound-surface-mutant.log`、`inbound-surface-restored-build.log`、`inbound-surface-restored-test.log`。没有提交、推送或部署；目标仍 active。

## 2026-09-30 阶段审查：删除面板未使用调试能力

全仓调用检查确认公开 `api::API::Debug()` 没有生产或测试调用；V2Board 的唯一写入口也是这个方法，`debug_enabled_` 初始 false，因此其三处 HTTP 调试分支一直不可达。完整删除公开虚接口、APIClient/Impl 两层声明与转发、私有状态和专属日志分支。不接入全局日志配置，不增加新开关或兼容入口；`MethodName` 仍用于真实请求构造，保留。其他已有面板成功/失败日志不变。

本轮边界证据：`api.hpp` 不再让产品接口承担未使用的实现调试能力；V2Board Impl 不再保存只为死入口服务的可变状态；HTTP 请求仍直接进入相同 timeout/exchange 链路，未改变请求数据、发送时机、错误分类或 fallback。新增架构契约拒绝恢复该入口及私有状态，全仓搜索确认生产源码没有残留引用。PImpl 和低耦合成功标准在此项满足；其余架构成功标准继续由已记录的调用链、取消和回归证据支撑，不把删除一个死入口视为全仓完成。

完整 MSVC Release 构建成功，**CTest 145/145，84.97 秒，无跳过**。日志为临时证据目录的 `panel-debug-build.log`、`panel-debug-ctest.log`。没有提交、推送或部署。HTTP/2 与 XHTTP 的共享会话、逻辑端点及任务所有权仍是后续审查范围；目标保持 active。

## 2026-09-30 阶段审查：HTTP/2 EOF 串行化与统一网络回归

检查 HTTP/2 共享会话的写门、substream Close/Abort 和物理读任务。`WriteFrameSerialized`、gRPC/raw 数据写协程必须持有写门租约至完整帧结束；trailers、WINDOW_UPDATE 和 RST_STREAM 编码协程持有帧 payload；后台任务持有 session。保留这些生命周期边界，不将其视为无职责包装。`WriteRawEndSerialized` 只传递空 span 和 end_stream 标志，没有自有 payload 或清理职责，改为直接返回已拥有串行化职责的 `WriteRawDataSerialized`，新增契约阻止恢复该层转发协程。

补跑 `grpc_eof_integration.py` 时，初次 12 项均因旧出站 `server` / `server_port` / `uuid` 字段而在配置加载阶段失败；没有进入本次修改的网络链路。这不是 raw EOF 修改的故障证据。将夹具改为当前 `address` / `port` / `id` 契约，不增加生产兼容解析；重跑 **12/12** 通过，另有 `grpc_substream_integration.py` **6/6** 通过。随后把两份脚本接入 CTest（90 秒上限），避免它们长期不在统一回归中、配置漂移却不被发现。

本轮证据：协议串联及 raw/gRPC 响应 EOF 检查支撑统一请求链路；RST/END_STREAM 和共享连接继续可用的检查支撑子流边界；直接返回 raw EOF task、保留实际写门/帧 payload/task 所有者支撑无过度包装。PImpl 边界本轮未变，继续沿用前述独立编译证据。关闭清理任务中最终写失败与“流已移除、不再允许写”的区分仍需故障注入，当前 18 项网络场景不能证明该错误边界完整；不得只因看见 detached 就删除负责保持 session 寿命的任务，也不能把所有 false 一律升级成物理会话失败。

完整 MSVC Release 构建成功；**CTest 147/147，93.52 秒，无跳过**，其中 gRPC EOF 与隔离测试分别用时 9.01、7.65 秒。证据在临时目录的 `h2-eof-build.log`、`h2-eof-integration.log`（旧夹具失败）、`h2-eof-current-config.log`、`h2-isolation-integration.log`、`h2-suite-build.log`、`h2-suite-ctest.log`，独立逐项结果在 `build/h2-eof-current-config/results.json` 和 `build/h2-isolation-audit/results.json`。未提交、推送或部署。全仓目标仍 active。

补充本轮覆盖审计：原 12 项 EOF 场景中的 raw 测试验证的是出站，不直接执行此次改动的 raw 服务端 EOF 入口。因此另增 raw 服务端 TCP/TLS × 有响应/空响应四项，每项在同一物理连接连续执行 8 个流，校验 48,001 字节上传、目标 EOF、精确响应、响应 END_STREAM 及最后 PING 屏障。Peer 测试端按 raw 模式发送未封装的 VLESS 数据，并使用对应 HTTP path；gRPC 模式不变。扩展后 EOF **16/16** 通过，隔离仍 **6/6**。重复运行 CTest 暴露 bridge 夹具的 remote/local 目录不能已存在，修正为可重复运行；其 FileExistsError 是启动前夹具错误，不作为产品故障。最终重新运行完整套件 **147/147，89.47 秒，无跳过**，日志 `h2-suite-final-ctest.log`，独立扩展报告 `build/h2-eof-with-server/results.json`。这里新增的 raw 服务端场景才是对修改入口的实际网络覆盖，不用旧出站场景替代。

## 2026-11-05：会话组迁移与协议生命周期收束

采用地址稳定的 `ExecutionDomain`、单一执行租约与会话组整体迁移，不采用跨 Worker 包转发，也不把整个入站固定到单个 Worker。跨 Worker 的 XHTTP 请求和共享 H2 物理连接先冻结用户回调、合并组归属，再恢复执行。原 reactor 仅投递就绪通知，实际 socket 读写由当前组 owner 执行。移除源地址 CBPF 亲和；独立会话组仍独立调度。

物理连接 capabilities 按需持有协议运行态和轻量分配域；完整 PMR pool 只由 Worker 持有，同 Worker 连接共享尺寸类 slab，迁移前的块通过来源 Worker remote-free 队列归还。进程级连接／设备配额及认证重放状态通过有界控制入口协作。AnyTLS 池与启用 VLESS Encryption 的跨请求状态拥有独立执行域，按原准入 Worker、配置快照及 tag 隔离，借用请求先合组，避免短连接销毁健康池或票据缓存。停机关闭准入、收束请求与池任务、释放服务及域根，排空跨 Worker 归还后再销毁 Worker 池；reactor 与保留完成通道在此之前保持存活。

按用户要求恢复 `PROXY auto` 及默认 `auto`，保留 `off/on`。协议验证覆盖 v1/v2 分片、普通流量保留及畸形输入；部署信任边界见 README。HTTP chunk 与 Connection token 解析、H2/gRPC 消费后返还 credit、padding／reset credit 回收、REALITY 跨记录 ClientHello、共享 TLS 上下文、AnyTLS 超时取消和持久流量账本一并接入现有主链路，不保留旧兼容旁路。

验证中修复了两个独立的生命周期问题：已完成 `co_spawn` 的 cancellation slot 仍保有域 executor，阻止真正的 Finalize；TCP 超时先普通关闭再设置 abortive，导致内核已排队数据继续排空。前者在所属执行域完成边界清除 slot，后者在通知与关闭前标记 abortive。AnyTLS 背压验证只在预期超时路径接受 TCP reset，仍检查限时关闭、旧连接淘汰、新连接恢复和停机退出码；正常传输出现 reset 仍失败。

最终验证环境为 Linux、GNU 14.2、RelWithDebInfo、epoll、mimalloc，未启用 LTO：

| 验证 | 结果与证据 |
| --- | --- |
| 完整 CTest | 176/176，通过；最终运行 62.16 秒。迁移测试使用优化构建下仍执行的断言，覆盖在途 readiness 迁移、并发合组、有界拒绝及域退休 |
| XHTTP 会话迁移 | 明文／TLS × packet-up、stream-up、H2 合组、命名空间隔离，8/8；报告与 syscall 跟踪位于 `build/xhttp-migration-traced/` |
| 原生 I/O 归属 | `plain-h2-merge/ownership.strace` 中同一存活 fd 28 的 recv/send 从 TID 2271088 转到 2271087，中间没有 close；对应目标 socket fd 29 也迁移，非仅应用层回声 |
| AnyTLS 参考场景 | 15 个脚本、16 次调用全部通过，覆盖官方双向互通、帧／padding、背压、取消、超时、池复用与停机；`build/anytls-verified/` |
| 官方 Xray Vision | 双向 × 明文／TLS 1.2／TLS 1.3，6/6；`build/vless-xray-final/` |
| 官方 Xray VLESS Encryption | native／xorpub／random 各 17 次认证请求、16 次恢复、64 次重放拒绝；四个接收 Worker 均有实证；`build/vless-encryption-xray-final/` |
| 官方 Xray XHTTP | 4 个并发 stream-up 请求通过；`build/xhttp-xray-final/` |
| 空闲堆回收 | 两 Worker 真实进程运行 15 秒，启动 3 秒后无 `Worker::CollectHeap` 调用，正常退出；`build/idle-heap-verification/gdb.log` |

参考版本固定为 Xray `a4a3dff5b20c2faae567b742c172c7b95e75c083` 与 anytls-go `fd6167acd6d73b9fa3e607659951847fbc9e6c50`。临时跟踪包装器、GDB 命令及验证脚本已清理，保留结果日志。

边界：本轮没有 Windows 或 Release LTO 验证，也没有性能对比结论。Vision 写端仍使用 cmd 0/1，本轮不宣称新增双向 raw-write。面板 HTTP 200 不等同于远端账本事务提交；unknown 批次不自动重发，未采样的 SIGKILL 前流量不在持久保证内。未提交、推送或部署。

## 2026-11-07：缓冲元数据回收与根层收敛

`ConstBufferSpanBuilder` 的溢出数组原本逐次精确 `reserve(size + 1)`，连续追加产生二次方复制；`AppendBuffers` 借用自身溢出数组时，扩容还会使输入视图失效。先复现自追加仅保留三个片段、丢失后两个片段，再改为几何扩容，并在扩容后按原偏移重新取得自借用视图。永久行为回归覆盖内联转溢出、溢出再扩容、自借用子区间及空片段过滤。

固定微负载为 2,000 次构建、每次逐项追加 1,024 个一字节片段，内联容量 16；Linux x86-64、mise 固定 LLVM musl 工具链，`-O3 -flto -static`，以同一个计数 PMR 记录元数据分配。基线与候选交错运行三组，以下计数每次一致：

| 范围：全部 2,000 次构建 | 基线 | 候选 |
| --- | ---: | ---: |
| 分配次数 | 2,016,000 | 12,000 |
| 累计申请字节 | 16,789,248,000 | 64,512,000 |
| 峰值同时存活元数据字节 | 32,752 | 24,576 |
| 每轮析构后存活字节 | 0 | 0 |

这是元数据构建的分配测量，不代表网络吞吐或进程 RSS；计数资源不是生产 Worker 池。测量期间还有并发测试，因此不把耗时用于性能结论。

`MultiBuffer` 的大批次消费回小批次后原本继续持有峰值指针数组。复现中预留 4,096 槽、逐块消费至仅剩一字节时，分配域仍有两份分配；修改后回到内联槽，域只保留一个 payload 分配，完全清空后归零。永久回归检查部分消费后的资源归还、原 payload 地址与 UDP 目标不变，以及移动后继续消费和最终归零；不把指针数组释放等同于 Worker 映射量或 RSS 立即下降。

按用户要求将 132 个公共头从 `include/acppnode/` 移至 `include/`，同步迁移生产代码、测试和工具的引用；删除 `acpp` 根命名空间，保留按职责划分的子命名空间，不引入兼容头或别名。线上 HTTP User-Agent 属于外部协议字段，不因内部目录和命名空间调整而改写。

迁移后 Linux x86-64 musl Release、LTO 全量构建主程序、全部测试和 `cnode_traffic_journal` 成功；完整 CTest **1,033/1,033** 通过（180 项 unit、853 项真实进程／可控对端 E2E），总用时 72.02 秒。主程序 `--version`、`--help` 正常执行，ELF 确认为全静态。源码、测试、工具已无旧头路径和 `acpp` 根限定；临时探针和产物已清理。未配置外部固定版本参考客户端，未部署，不宣称全仓性能审计完成。

## 2026-11-07：按合并后的布局准备缓冲槽

`MultiBuffer::AppendAndCoalesce` 原本按输入块数预留指针数组，未扣除会合并到现有尾块的数据。真实调用包括 Dispatcher 嗅探、Mux 输入队列、公共地址读取和 WebSocket 读取。先通过公开 API 复现：目标已有八个内联块、尾部空间足够时，拒绝下一次元数据分配仍导致合并抛出 `std::bad_alloc`。新增行为回归在旧实现明确失败。

只有输入块数上界会引起指针数组扩容时，才模拟合并后的实际新增槽数；已有槽位足够的常规路径不增加预扫描。准备全部必要槽位后才修改 payload，保持分配失败时双端字节、所有权及 UDP 边界不变；不新增分配器、缓存或请求层包装。第二项回归覆盖前段可合并、后段 UDP 必须独立成块时的准备失败、重试及最终顺序。

固定微负载为 64 轮，每轮目标八个一字节块、输入 1,024 个一字节块；尾块足以容纳全部输入。Linux x86-64、mise LLVM musl、`-O3 -flto -static`，使用计数 PMR 测量，仅在实际合并阶段计入申请次数与字节。基线／候选交错运行三组，结果一致，且每轮逐字节核对输出：

| 元数据测量范围 | 基线 | 候选 |
| --- | ---: | ---: |
| 64 轮合并分配次数 | 64 | 0 |
| 64 轮合并累计申请字节 | 528,384 | 0 |
| 单轮合并后仍持有字节 | 8,256 | 0 |
| 单轮完全析构后仍持有字节 | 0 | 0 |

计数资源不代表生产 Worker 池；这里只证明消除了该负载的不必要分配和容量滞留，不作 CPU 耗时、网络吞吐或 RSS 收益结论。

musl Release、LTO 全量构建成功，修复后完整 CTest **1,035/1,035** 通过（182 项 unit、853 项真实进程／可控对端 E2E），总用时 62.49 秒，包含新增的分配失败及 UDP 边界回归。主程序 `--version` 正常执行；临时复现与计数程序及其产物已删除。未部署，未运行外部固定版本参考客户端。

## 2026-11-07：TLS 本地读半关闭与对端截断分离

真实 TCP/TLS 回环复现了挂起读取与本地 `ShutdownRead()` 的交错故障：`AsyncRead`、`ReadMultiBuffer` 分别在空闲和已收到三个 TLS 头字节的状态下挂起，读半关闭唤醒后继续进入 SSL，把本地停止接收产生的 EOF 当成对端 `stream_truncated`，随即中止整个连接。四项新增回归在修复前全部失败。

统一 TLS 操作循环在跨输入等待或 engine gate 恢复后、调用 SSL 和借用 payload Buffer 之前，重新判断读方向是否已本地关闭。仅对读取返回 EOF，不改写 SSL 的对端关闭状态，不吞掉真正的 TLS 截断或全连接取消。握手和写方向沿原控制流执行，没有新增状态、分配、定时器或包装层。

修复后五项 TLS 回环测试全部通过：四项新场景验证挂起读取 EOF、后续读取 EOF、连接保持打开、写入精确 payload，以及独立 TLS 对端实际收到 `close_notify`；既有回归继续覆盖部分记录取消恢复、分配失败重试、KeyUpdate、双向背压、大证书握手和读超时。此处使用真实 socket 与独立公共 SSL API 对端，不是模拟 I/O。没有性能、吞吐或 RSS 对比结论。

musl Release、LTO 全量构建成功；完整 CTest **1,039/1,039** 通过（186 项 unit、853 项真实进程／可控对端 E2E），用时 62.44 秒，包含新增半关闭回归及已有 TLS 取消、超时和双向关闭场景。主程序 `--version` 正常。未部署，未配置外部固定版本参考客户端；本轮结论仅覆盖上述已复现的 TLS 缺陷，不代表 QUIC 生命周期或全仓性能审查已完成。

## 2026-11-07：QUIC 子流终结、接收 credit 与取消闭环

按 [RFC 9000 §4.4–§4.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-4.4) 区分流终结和连接级字节记账；接收窗口是否继续开放仍由应用资源预算决定，不能把标准解读为必须立即扩窗。当前 ngtcp2 1.26 只在关闭时自动结算未交付应用的字节，已进入 `QuicStreamState::input_` 的字节由应用负责消费或丢弃后的 credit 归还。

新增独立 C++ 真实 QUIC 对端，使用现有 ngtcp2、nghttp3、BoringSSL 执行 UDP 收发、TLS 1.3、HTTP/3 认证及 [HY2 请求编码](https://v2.hysteria.network/docs/developers/Protocol/)。未使用模拟 TLS、无操作加密、生产 `Connection` 桩或外部 Go 客户端。现有真实 TCP 目标夹具移至共享 E2E support，由 HTTP/2 与 QUIC 场景共用，不保留旧命名空间别名。

复现时维持同一 QUIC 连接和健康 TCP 子流。每个干扰流先发请求头和一个字节，收到真实 DNS query 后确认分发已挂起，再发送后续 payload，排除数据已被 relay 消费的猜测：

- 客户端 reset：64 KiB payload 收到全部 ACK 后 reset；旧实现在第 256 个干扰流停住。
- 应用输入预算拒绝：发送 768 KiB，触发既有 512 KiB 子流输入预算；旧实现在第 29 个干扰流停住。

两条失败路径的独立客户端诊断均为 `connection send credit=0`，不是认证失败或重新建连。原始失败现场位于 `build/musl/e2e-artifacts/cnode-e2e-EgimOF/`、`cnode-e2e-dLoaPF/`。

修复保持原 16 MiB 连接窗口与原输入预算，不扩大配额：终结前先摘除 owner 并快照未消费字节，reset／取消时丢弃并结算，正常关闭时保留可继续读取的尾部但不重复归还；当前回调因准入失败而拒绝的字节也单独结算。QUIC 逻辑流使用状态块内同一取消源，将远端 reset 传播到等待 DNS、拨号等阶段的请求；显式本地关闭仍保留后续读取 EOF 语义。

仅修复 credit 后，测试又暴露了取消未传播造成的请求滞留，以及发包回调重入：保存的 core 在 `ngtcp2_ppe_encode_frame → conn_write_pkt → Connection::Flush` 崩溃。应用层将发包纳入已有 ngtcp2 回调保护，避免终结 credit 通知从发包回调再次进入发送；没有修改第三方库。保存的临时 core 在定位后删除。

针对性真实 E2E 三项通过：272 次客户端 reset、40 次输入预算拒绝后，原健康流和新流仍精确往返；另验证九个正常 FIN 流累计传输并逐字节核对 18 MiB 后仍可复用同一连接。各场景检查进程正常停机。测试耗时不是吞吐基准，本轮没有 CPU 或 RSS 收益结论；新增取消源为流内嵌状态，不引入线程、连接私有池、定时器或跨 Worker 可变共享。

musl Release、LTO 主程序、全部测试目标和 `cnode_traffic_journal` 构建成功，主程序 `--version` 正常。全量 CTest **1,041/1,042** 通过，用时 63.38 秒：186 项 unit 全过，856 项 E2E 中通过 855 项，新增三项 QUIC E2E 在全量并行下均通过。

唯一失败为 `http2_worker_migration` 的明文 `h2-merge` 场景，现场 `build/musl/e2e-artifacts/cnode-e2e-NjKlDH/`。该实例配置为 VLESS/XHTTP，未运行 QUIC；`child.log` 记录 `runtime failed phase=session-domain error=destroying native resource during handoff status=forced`，随后客户端读取 EOF。本轮未修改会话组合并或原生资源销毁机制；保留失败现场，不通过无改动重跑将其记为通过，不把此次结果声称为全量绿灯。未部署；跨实现官方 Hysteria 客户端与 QUIC 路径迁移不在本轮验证范围。

## 2026-11-07：冻结成员的退役与所属 Worker 析构

继续处理上一轮保留的 HTTP/2 `h2-merge` 失败，不改动 QUIC 修复，也不放宽 `UnregisterResource` 的冻结期销毁保护。原现场只记录最后一批已写日志，不能据此断言出错资源就是某条 TCP socket。

新增两个确定性回归：让同组成员使用真实共享超时调度器，取消事件并显式释放其超时服务；准备接管后释放该成员的外部引用，再分别 Commit 和 Cancel。旧实现两项均立即退出，错误与原现场相同。GDB 确认调用链为 `ExecutionDomain::~ExecutionDomain` → `execution_context` 服务销毁 → `DomainTimeouts::~DomainTimeouts` → `NativeResource::~NativeResource` → `UnregisterResource`。这不是未完成 TCP I/O 的资源强行销毁，而是冻结成员最后一个引用释放时，域内服务的合法退役被错误放在解冻之前。

冻结快照现在由组持有，直到所有相关组完成解冻，防止 Freeze 通知或事务结束期间成员提前析构。解冻先解除两个组全部成员的冻结标记，再发布任何业务唤醒，避免已恢复回调借用另一个仍冻结的同组成员。拆组依旧释放原冻结快照中的所有成员。事务结束先清除原生资源借用，再解冻，最后释放根引用；失败路径仍显式回滚后解冻，不增加析构内异步回滚。

域的最后一个元数据引用可能在协调器线程释放；其最终析构现在统一回到已发布的所属 Worker。直接在所属 Worker 结束时不增加投递，跨线程仅投递最终清理，不转交业务数据或访问会话状态；既有协调器退役屏障仍等待域内服务销毁完成。永久回归同时检查旧/新 Worker 的实际析构线程、无用成员释放和剩余成员的执行归属。

事务直接复用唯一冻结快照，删除重复的成员向量、二次收集及对应强引用复制；解冻时释放快照容量，不让空组保留本轮容量。本轮没有吞吐、CPU 或 RSS 基准，不将这些结构性收敛量化为性能收益。

首轮修复的五项生命周期/超时回归全部通过；四 Worker 的 TCP/TLS × packet-up/stream-up/h2-merge/isolation 八项真实进程与网络 E2E 全部通过，检查实际负载回显、共享连接合并与拆离、隔离及停机。原失败现场继续保留。

删除重复事务快照后，musl Release/LTO 的 `cnode`、全部测试目标和 `cnode_traffic_journal` 增量构建成功；最终全量 CTest **1,044/1,044** 通过，其中 188 项 unit、856 项 E2E，用时 62.45 秒，无失败。包含新增 Commit/Cancel 退役回归、原 HTTP/2 合组失败场景及此前三项真实 QUIC E2E。未提交、推送或部署，未声称跨平台验证。

## 2026-11-07：构造失败候选域的同步回滚

执行域注册失败时，候选对象尚未交给 Worker，但其共享指针删除器原先仍将清理投递到目标 Worker。逐点注入普通分配失败后，旧实现的零基故障点 7、8、9、10 都在异常返回时仍持有宿主；必须额外驱动 Worker 才能释放。若构造失败使 Worker 不再启动，这些资源就无法及时回收。测试通过公开 `Create` 契约和宿主弱引用取得证据，不固定实现的分配次数或源码形态。

删除器现在依据既有退役凭据区分所有权阶段：凭据只在全部可失败的注册分配成功后安装，安装前由构造方同步销毁候选；安装后保留原所属 Worker 清理路径。没有增加生命周期标志、兼容分支或异步回滚，没有改变 `bad_alloc` 的传播，也没有放宽已发布域的 Worker 归属。

复用现有一致插桩的超时/执行域测试目标，仅为测试分配器增加线程本地单次故障倒计数；不新增生产故障开关、测试库变体或构建规则。永久回归逐点覆盖构造分配失败，在首次驱动 Worker 之前核验宿主已释放，再验证健康域的真实执行租约、清理和协调器终结。

针对性六项生命周期/超时回归全部通过，包含先失败后通过的构造回滚场景，以及已发布成员 Commit/Cancel 的所属 Worker 析构验证。八项四 Worker TCP/TLS 合组 E2E 全过，真实进程正常转发、拆离、隔离并停机；构造分配失败只在隔离故障注入目标验证，没有在真实服务进程制造系统 OOM。此次消除失败路径的额外投递与延迟引用持有，没有 CPU、吞吐或 RSS 收益声明。

musl Release/LTO 的 `cnode`、全部测试目标和 `cnode_traffic_journal` 增量构建成功；最终全量 CTest **1,045/1,045** 通过，其中 189 项 unit、856 项 E2E，用时 62.64 秒，无失败。未提交、推送或部署；既有 include/命名空间迁移及其他用户改动保持不变。

## 2026-11-07：只发布真实启动状态，避免退役通知锁死

原协调器在跨线程启动投递之前就设置 `start_posted`，但该状态不代表原生通知等待已成功挂载。分别注入启动投递分配失败、首次原生等待挂载分配失败，两项旧实现回归均确认：异常上报后再次调用 `Start()`，已退役宿主虽在所属 Worker 释放，`Finalize()` 仍持续等待，因为退役 eventfd 无等待者。测试在一秒观察截止后记录失败，才手工排空以清理夹具；没有把手工排空当作恢复成功。

删除独立的“已投递”标记，将实际 `started` 状态发布为原子值；只有协调器在可失败的首次挂载成功后以 release 写入，Worker 以 acquire 读取。投递或挂载失败都不发布成功状态，保留原异常，后续显式启动仍可执行。协调器本线程的幂等检查、析构与终结检查只需 relaxed 读取，不用原子操作代替原生资源的单线程归属。

并发冷启动允许提交各自的启动动作，由协调器串行幂等处理，避免调用者提前确认另一次可能失败的尝试；这是冷启动重复投递与状态机复杂度之间的选择。实际就绪后不再投递，正常建域路径由每次原子 `exchange` 改为只读加载；没有新增锁、轮询、线程、重试策略或内部代次。未做吞吐、CPU 或 RSS 基准，不将状态字段收敛和读改写消除量化为性能收益。

针对性八项生命周期/超时回归全部通过，包含两项先失败后通过的启动恢复场景，核验活域阻止提前终结、Worker 释放宿主后由真实原生通知完成终结。八项四 Worker TCP/TLS × packet-up/stream-up/h2-merge/isolation 真实 E2E 也全部通过，覆盖数据回显、合组、拆离、隔离及正常停机。故障注入只在现有隔离测试目标执行，未对真实服务进程制造系统 OOM；未改配置、配额或协议主链路。

musl Release/LTO 的 `cnode`、全部测试目标和 `cnode_traffic_journal` 增量构建成功；最终全量 CTest **1,047/1,047** 通过，其中 191 项 unit、856 项 E2E，用时 62.45 秒，无失败。原构造回滚、成员 Commit/Cancel 退役和三项真实 QUIC 回归均包含在内。未提交、推送或部署，保留既有用户改动。

## 2026-11-07：原生通知重挂载失败后的停机闭环

首次启动恢复之外，通知回调消费完一次原生等待后，下一次挂载仍可能分配失败。旧实现保留 `started=true`：显式 `Start()` 不再挂载；无活域停机等待一个不存在的取消完成；有活域停机则收不到后续退役通知。三个隔离子进程回归在一秒观察截止时均以失败退出，父 GoogleTest 要求正常成功退出，因此没有把强制退出当作修复成功。

回归使用真实 eventfd 与 Asio descriptor 等待：辅助等待消费刚完成等待的回收存储，再仅对真实协调器重挂载注入分配异常，明确检查异常确实发生。辅助等待随后取消并收束。覆盖显式重启、全部域已退役直接停机、仍有活域时终结三个不同边界；成功路径核验宿主释放、原生完成通知驱动终结及协调器弱引用过期。子进程隔离只用于避免在旧实现的悬挂协程上强行析构夹具，没有改生产分配器或私有状态来制造通过。

`ArmReserved` 现在在挂载异常时以 release 撤销就绪并原样抛出，使状态与已不存在的原生等待一致。`Finalize` 在仍有活域时先确保收集器可用，再等待真正的退役完成；若域已退役且等待已失效，则不再等待不存在的取消回调。新挂载若再次失败仍直接上报，没有自动重试循环、轮询、隐藏异步回滚或额外后台任务。

针对性 11 项生命周期/超时回归全部通过；四 Worker TCP/TLS × packet-up/stream-up/h2-merge/isolation 八项真实网络 E2E 全部通过，覆盖回显、合组、拆离、隔离及正常停机。故障边界仅在隔离 C++ 目标注入，未在真实服务进程制造系统 OOM。本轮没有吞吐、CPU 或 RSS 基准；正常通知路径不增加分配、队列、线程或定时器。

musl Release/LTO 的 `cnode`、全部测试目标和 `cnode_traffic_journal` 增量构建成功；最终全量 CTest **1,050/1,050** 通过，其中 194 项 unit、856 项 E2E，用时 62.46 秒，无失败。首次启动恢复、构造回滚、成员 Commit/Cancel 退役及此前三项真实 QUIC E2E 均包含在内。未提交、推送或部署，保留既有用户改动。

## 2026-11-07：HY2 单片 UDP 标识符的接收语义

[Hysteria 2 协议 Fragmentation 条款](https://v2.hysteria.network/docs/developers/Protocol/#fragmentation) 明确：未分片报文的 Fragment Count 必须为 1，此时 Packet ID 和 Fragment ID 的值无关紧要。原解析器对所有报文统一要求 `fragment_id < fragment_count`，错误拒绝合法的非零单片 ID；编码器也有相同限制。V1 未据此修改。

独立 C++ QUIC 对端增加受界限约束的原生 DATAGRAM 收发，使用真实 ngtcp2、nghttp3、BoringSSL 和 UDP socket，不调用生产 UDP 编解码器。旧程序上，ID 0 的单片报文完成目标收取与原路回包；ID 改为 1 后在上行目标收取阶段超时，QUIC 连接仍存活。带阶段诊断的失败现场保留在 `build/musl/e2e-artifacts/cnode-e2e-KgNAdC/`；初次未区分阶段的观察保留在 `cnode-e2e-iaHGPP/`。夹具曾因误用仅属于 HTTP/2 测试的 `Pattern` 未编译，改为本地二进制载荷构造后才取得上述运行证据。

收敛共享索引校验与目标必填判据：仅 HY2 的 `count=1` 忽略 Fragment ID；零分片数及多片索引越界仍拒绝。单片报文无论 ID 如何都要求有效目标，后续分片仍允许省略目标。编码器在分配输出向量之前完成缺失目标拒绝，避免无效输入先 reserve 再返回错误；不改载荷预算、会话上限或分片缓存。

四项新增契约测试覆盖独立线面解码、精确编码、零分片数/多片越界及单片缺失目标；旧实现的合法解码、编码两项失败，修复后通过。真实 E2E 验证 ID 0、1、255，重复无关 Packet ID、包含零字节的载荷、完整双向回显、同一 Session ID 保留出站 UDP 端口、倒序两片重组及后续单片恢复，并检查服务正常停机。

针对性 14/14 通过，包括上述 10 项协议单测与 4 项真实 QUIC E2E；此前 TCP credit/重置/FIN 回归继续通过。公共入站配置夹具移到既有 `quic_peer.hpp`，原调用者全部迁移，不增兼容入口。此次优先修复协议正确性，未声称吞吐、CPU 或 RSS 收益；取消队列策略及数据面资源上限均保持不变。

musl Release/LTO 的 `cnode`、全部测试目标与 `cnode_traffic_journal` 增量构建成功；最终全量 CTest **1,055/1,055** 通过，其中 198 项 unit、857 项 E2E，用时 62.45 秒，无失败。未提交、推送或部署，保留既有用户改动。官方 Hysteria 客户端未运行，本轮互操作证据来自独立 C++ QUIC 对端。

## 2026-11-07：HY2 UDP 取消前归还未读输入

原 `UdpSessionStream::Cancel()` 标记取消后仅唤醒和通知，输入队列直到 Close/析构才清理；而该类读取先检查取消标记，已有输入已不能再被消费。现在在任何唤醒、取消订阅回调之前清空输入并归零字节计数，沿用 RingDeque 的排空归还存储行为。不改变既有取消通知、会话登记、出站或 QUIC 连接状态。

复用一致插桩的 `cnode_test_core` 新增 C++ GoogleTest 目标；不新增生产统计。固定在同一线程、musl Release/LTO 环境，用三个短报文先移交首包，再取消，检查已有测试 Buffer 存量。两个旧实现回归均失败，分别覆盖保留宿主、订阅回调内销毁宿主。观测值仅代表该样本的活跃 Buffer，不是 RSS 或端到端内存基准。

|观测点|修复前活跃 Buffer|修复后活跃 Buffer|
|---|---:|---:|
|进入取消订阅回调时|3|1|
|调用方释放已交付数据后，宿主仍保留|2|0|

回归还验证 PMR 分配拒绝开关下取消完成且没有新的 PMR 分配、重复取消安全、已交付载荷与 UDP 目标仍有效、执行域最终可终结。借用视图在释放拥有型报文之前结束，不依赖析构清理掩盖取消时的滞留。

新增真实 QUIC/UDP 停机场景：观察 DNS 黑洞收到会话目标查询后，再发送后续报文；同一 QUIC 连接的 TCP 请求仍精确回显，然后服务在 DNS 未响应时正常停机。这个场景验证挂起 DNS 与后续流量下的取消收束，不把网络发送量当作服务端队列内存计数。DNS 黑洞夹具移入既有 QUIC 共享头，原 TCP credit 调用者同步迁移，没有复制第二套解析。

针对性 7/7 通过，包含两项资源归还回归和五项真实 QUIC E2E；单片 UDP 双向转发、倒序重组、端口复用及此前 TCP reset/FIN/credit 场景继续通过。未量化 CPU、吞吐或 RSS 收益；未改变队列配额或协议字段语义。

musl Release/LTO 的 `cnode`、全部测试目标与 `cnode_traffic_journal` 增量构建成功；全量 CTest **1,058/1,058** 通过，其中 200 项 unit、858 项 E2E，用时 62.45 秒，无失败。构造回滚、启动/重挂载故障恢复、成员退役及协议回归均继续通过。未提交、推送或部署，保留既有用户改动。

## 2026-11-07：HY2 UDP 队列按 Buffer 容量准入

`UdpSessionStream` 原先只按载荷字节扣除队列预算，而不同 UDP 报文不能共享 Buffer；短报文也各占一个 8 KiB 数据块。Worker 池的空闲缓存上限不会限制这些活跃块。现在复用原计数字段记录未读 Buffer 数，在分配前按实际输入长度计算所需块数，与既有 512 KiB 数据容量预算比较。移交报文时按其 Buffer 数归还准入，Detach、Cancel、Close 清零；不新增状态字段、分配、线程或定时器。

减法不再使用外部载荷长度：非空输入通过 `1 + (length - 1) / Buffer::kSize` 计算块数，只从已有有界块数配额中扣除。原实现在空队列下接受了长度为预算加一的实际输入；回归在修复前确认这个结果，并通过 PMR 故障开关确认其尝试了本应禁止的分配，修复后在分配前拒绝。协议解析层已有独立报文长度限制，此处是内部队列的资源边界修复，不声称这条超长输入能够通过线上协议解析。

沿用相同 musl Release/LTO 与一致 Buffer 插桩配置，在同一线程连续提交 128 个单字节报文且不读取：

|观测点|修复前|修复后|
|---|---:|---:|
|未读 Buffer 数|128|64|
|对应数据容量|1 MiB|512 KiB|

这是准入语义与容量上限验证，不是相同接纳负载下的内存优化基准；积压时小包会比旧实现更早触顶，仍沿用丢弃新报文的策略。数据容量不包含 Buffer 头、UDP 目标、队列元数据和池内碎片，不等同于 RSS，也没有 CPU 或吞吐结论。

永久回归验证满载和仅剩一个块时不分配、读取后允许两块报文进入、FIFO/报文边界/目标/完整载荷保持、已交付数据不被重新借用覆盖、排空后归还全部 Buffer。沿用原取消回归验证订阅回调内销毁宿主及执行域收束；公共执行域夹具由两个真实测试调用者复用，没有新增生产统计入口。

真实 QUIC 停机场景将 DNS 挂起后的上行负载扩至 128 个 700 字节报文，验证同连接 TCP 精确回显及服务正常退出；发送量不作为服务端实际入队数量的证据。针对性 **8/8** 通过，包含三项资源单测与五项真实 QUIC E2E；单片 UDP、重组、出站端口复用、TCP reset/FIN/credit 继续通过。

首次全量为 1,058/1,059 通过，唯一失败是 `ProxyProtocol.OffAutoOnAndDefaultPreserveOptionalHeaderBoundaries` 的日志条数断言。现场保留在 `build/musl/e2e-artifacts/cnode-e2e-FLhddN/`：`error.log` 的 `[off]` 非法协议版本与 `[auto]` 截断头属于不同连接，却具有相同客户端端口，测试按端口字符串加总而误报重复告警。按测试边界规范删除日志文本/精确条数断言及其无消费方的端口采集，不修改生产日志、不重新钉住其他条数。原真实进程的 on/off/auto/default、v1/v2、分段、非法输入及空 EOF/截断半关闭场景全部保留。

清理后重新增量构建 `cnode`、全部测试目标和 `cnode_traffic_journal`；针对性 **9/9** 通过。最终全量 CTest **1,059/1,059** 通过，其中 201 项 unit、858 项 E2E，用时 62.12 秒；实际运行 `cnode --version` 返回 `release:20261107T184606Z`。首次失败与现场保留，不以重跑通过替代原因分析。未提交、推送或部署，保留既有用户改动。

## 2026-11-07：HY2 非空 UDP 原报文中的空分片

[HY2 Fragmentation 规范](https://v2.hysteria.network/docs/developers/Protocol/#fragmentation)要求收齐全部分片再处理，没有规定每片 Payload 必须非空；[官方重组实现](https://github.com/apernet/hysteria/blob/master/core/internal/frag/frag.go)也以片对象是否存在记录到达，而非以 Data 长度记录。原 `HandleUdpMessage()` 却因任一空片直接丢弃重组状态，导致语法合法、原始载荷非空的报文无法转发。

在既有真实 QUIC/UDP E2E 中加入空片位于首、中、尾的非空原报文。旧二进制完成此前单片双向转发与倒序两片重组后，在空首片完成重组时发生上行目标等待超时；现场保留在 `build/musl/e2e-artifacts/cnode-e2e-hjhnhF/`，不是认证失败或仅单元测试推断。

现在在每个在途重组条目内嵌 256 位到达位图，独立记录索引是否已收到；空片计入到达数，但它本身不触发 payload 向量扩容或载荷分配。沿用已有计数器，避免逐片重新统计位图；沿用分片数、总载荷与条目数预算，以及重复片整包丢弃策略，不加单独堆分配、线程或定时器。删除新建状态对首片目标的重复赋值，只在片校验通过后写入目标。

修复后的真实对端验证空首片携带目标、空中片及未分配尾槽的空尾片，均保持原始报文边界、精确双向载荷及同会话出站 UDP 端口。全部非空片已到而空尾片未到时，先经独立完整报文完成双向交换，再补空尾片验证重组；重复空片不能代替缺失片，后续完整报文仍正常。缺片状态留到关闭时随连接正常收束。本次验证的是原始载荷非空的分片报文，不代表新增整体零长度 UDP 报文支持。

针对性 **8/8** 通过，包括三项资源单测与五项真实 QUIC E2E；队列容量、取消回调内销毁宿主、挂起 DNS 停机、TCP reset/FIN/credit 继续通过。对端为独立 C++ QUIC 实现，未运行官方客户端；未量化吞吐、CPU 或 RSS 收益。

musl Release/LTO 的 `cnode`、全部测试目标及 `cnode_traffic_journal` 增量构建成功；全量 CTest **1,059/1,059** 通过，其中 201 项 unit、858 项 E2E，用时 62.47 秒。实际运行 `cnode --version` 返回 `release:20261107T184606Z`。未提交、推送或部署，保留既有用户改动。

## 2026-11-07：稀疏 UDP 分片不按最高片号预分配元数据

原重组器用 `payloads.resize(fragment_id + 1)` 定位载荷，收到一个合法高编号非空片便为大量未到达片创建空容器。改为固定一字节索引表映射到按实际到达顺序增长的非空载荷数组；索引为一基，零表示不携带字节，到达位图继续独立区分空片与缺片。完整接收后按协议片号顺序读取映射，保持载荷顺序，不增加查找分配或逐片线性搜索。条目通过 `try_emplace` 原地构造，避免复制新增索引表和移动临时状态。

固定索引表覆盖 uint8 片号空间，是有界元数据底线；载荷容器仅在实际非空片到达时几何增长，不再由外部片号驱动。代价是普通少片条目的固定索引开销，未以降低报文、载荷或缓存条目配额换取内存下降。

使用构建目录内临时 C++ GoogleTest/CTest 探针启动真实二进制，经独立 QUIC/TLS 对端认证；一个 Worker、同一 Session、64 个不同 Packet ID，每包仅发送一个单字节片。稀疏负载发送 ID 254/count 255，普通少片对照发送 ID 1/count 2；均不补齐原报文。测量前后在同一连接完成 TCP 精确往返，以 Linux `/proc/<pid>/smaps_rollup` 的 `Anonymous` 字节增量比较活跃阶段匿名内存，不把发送量当服务端条目计数。

旧版为修改前保留的全静态二进制，新版来自同一工作区，功能改动仅限此次重组路径，CMake 重配另行生成了构建标识；同机 musl Release、`-O3 -DNDEBUG`、LTO 开启，逐种负载按旧/新/旧/新交错运行，各次使用全新子进程：

|负载与轮次|旧版匿名内存增量（KiB）|新版匿名内存增量（KiB）|
|---|---:|---:|
|稀疏，第 1 轮|1004|44|
|稀疏，第 2 轮|1004|44|
|普通少片，第 1 轮|28|44|
|普通少片，第 2 轮|28|44|

这是该固定负载的匿名内存增量，不是进程总 RSS、峰值、长期稳态或吞吐基准；普通少片对照体现索引表成本，不隐藏这个权衡。

永久真实 E2E 增加 255 片倒序到达、ID 254、最后槽索引 255、包含零与高位字节的精确双向载荷及后续报文恢复；修改前后均通过，防止密集数组误按到达顺序输出或一基索引窄化。首/中/尾空片、缺片等待、重复空片、端口复用与既有取消/容量/TCP credit 场景继续通过，针对性 **8/8**。临时探针、临时 CMake 注册、旧版副本及生成产物已清理；没有新增生产统计入口。

移除探针注册后重新配置并增量构建 `cnode`、全部测试目标及 `cnode_traffic_journal`；最终全量 CTest **1,059/1,059** 通过，其中 201 项 unit、858 项 E2E，用时 62.47 秒，不含已清理的临时测量测试。实际运行 `cnode --version` 返回 `release:20261107T200421Z`。未提交、推送或部署，保留既有用户改动。

## 2026-11-07：UDP 零载荷与 EOF 分离

[RFC 768](https://www.rfc-editor.org/rfc/rfc768) 的 UDP 最小长度为八字节头部，允许零载荷。原生 socket 已能发送和接收这种报文，但缓冲判定、首包容器、批次、relay 及多个协议适配层按零字节丢弃或结束请求。独立 QUIC 对端发送 HY2 首个空报文时，真实目标等待超时；修复前现场为 `build/musl/e2e-artifacts/cnode-e2e-lLOmFJ/`。

统一表示为：无 Buffer 是 EOF/没有报文；至少一个带 UDP 目标的零长度 Buffer 是真实空报文。`SetUdpTarget` 是完整报文的唯一标记入口，必要时借一个 Buffer，替代原有 `SetUdpDatagramTarget`；原始 TCP 空读不能调用它制造报文。空的未标记缓冲仍归还；零报文经过 MoveTo、AppendAndCoalesce、InitialPayload、MultiBufferBatch、嗅探与 relay 时保留目标和所有权。UDP 检查也校验零长度块的目标，不能用空块掩盖混合目标。原生接收复用已经借到的 Buffer，不为零报文另借第二块。

HY2 收发把空报文计为一个数据报、一块缓冲和一个 DATAGRAM 帧；全部为空的分片收齐后仍交付一个空原报文。Hysteria 输入按既有 Buffer 容量预算准入；原生 UDP 输入仍受报文数与共享 payload 容量配额约束。Mux UDP 输入按至少一个 Buffer 的容量记账，出队、取消及析构归还；零回包释放空 Buffer 后仍按帧元数据开销计队列预算。零字节不能绕过队列容量或保持不可回收的缓冲。

[Trojan](https://trojan-gfw.github.io/trojan/protocol)、[UOT](https://sing-box.sagernet.org/configuration/shared/udp-over-tcp/)、VLESS 固定目标和 [PacketAddr](https://github.com/v2fly/v2ray-core/blob/master/common/net/packetaddr/packetaddr.go) 的完整零载荷报文保持收发；PacketAddr 地址之后为空合法，但没有地址的空 segment 仍报解码错误。PacketAddr 双节点 E2E 另复现入站把端口为零的魔术地址交给分发而未读取真实目标，现场为 `cnode-e2e-CdCOlb/`、`cnode-e2e-bBJNlb/`；现在在入站握手期限内读取首份完整报文、经唯一目标绑定入口设置真实目标，再把首包按值交给同一主链。分发层不增加协议特判或默认目标。

[Mux.Cool](https://www.v2fly.org/developer/protocols/muxcool.html) 的 DATA option 与长度正交：NEW 无 DATA 是控制，DATA 长度零是消息；KEEPALIVE 的额外数据丢弃，END 的最后载荷（含零）先交付再关闭输入。`EncodeNewHeaderTo` 使用必填 `has_data`，所有调用者同步迁移，没有默认兼容旁路。[VMess](https://www.v2fly.org/developer/protocols/vmess.html) 的空标准 body 明确表示 EOF，因此普通 VMess UDP 对空报文明示 `NOT_SUPPORTED`，不消耗编码状态、不写 EOF 冒充 UDP；真实结束帧和截断行为不变。

永久回归覆盖零消息经过首包、批次及转发仍保序、目标一致性、满队列拒绝前不分配、读取归还准入、取消不破坏调用方已拥有的空报文，以及控制帧/EOF 的区分。真实 HY2 开启嗅探验证空首包、空回包、全空分片、非空及后续再空；六项 SS classic/AES2022/ChaCha2022 入站与 freedom/SS 下一跳组合验证认证先于零载荷交付、坏认证仍丢弃、同 socket 身份隔离和端口稳定。

另外七条真实双进程链路通过：VLESS none/PacketAddr/XUDP，Trojan TLS，SS UOT v1/v2，AnyTLS UOT v2 connect。覆盖精确双向零/非零载荷、部分链路的多 Buffer 大报文、不同目标和关联端口保真、正常 EOF 及两节点退出；没有以 codec 单测或 mock 回声替代进程互通。首次集成的两个夹具问题分别为遗漏非空回复工厂、旧 socket 测试把成功空报文要求为空容器，均保留原非空回复内容断言并按新可观察契约修正。未量化吞吐、CPU 或 RSS 收益。

最终增量构建 `cnode`、`cnode_tests`、`cnode_traffic_journal` 成功；全量 CTest **1,079/1,079** 通过，其中 208 项 unit、871 项 E2E，用时 62.48 秒。实际运行 `cnode --version` 返回 `release:20261107T204636Z`。README 同步说明零报文支持与普通 VMess UDP 的协议限制；没有运行官方外部客户端，验证环境为当前 Linux musl Release 构建。未提交、推送或部署，保留既有用户改动。

## 2026-11-07：未完成 UDP 分片的双轨到期清理

真实 HY2 对端复现未完成分片一直留在连接中：空闲六秒后补尾片仍向原生 UDP 目标交付 `expired-head:late-tail`；每两秒补一个有效片、持续十六秒后也仍交付完整旧包。两个失败现场分别保留在 `build/musl/e2e-artifacts/cnode-e2e-OFPcAG/` 与 `cnode-e2e-OAjHBG/`。原有容量上限只能限制候选数量，不能结束孤片在长连接中的生命周期。

[HY2 Fragmentation 规范](https://v2.hysteria.network/docs/developers/Protocol/#fragmentation) 要求等待全部片、丢片则丢弃原包，并未规定重组超时数值。研究的[上游 Defragger](https://github.com/HyNetworks/hysteria/blob/master/core/internal/frag/frag.go) 只维护一个 Packet ID，新 ID 替换旧候选；不把这种实现限制当作协议要求。本地保留既有的多候选和乱序支持，增加 README 所列的固定空闲与整体预算，作为资源策略而非解码拒绝规则。

`PendingFragments` 保存不续期的整体截止时间与仅由有效新片更新的到期时间，时间加法饱和防溢出。连接只多存一个缓存的最早唤醒下界：续期或删除不逐片扫描全表，在该事件到期时才扫描至多既有容量上限内的候选并重算；最后一个候选消失时直接交换空 map，归还节点、载荷和 bucket，而非仅 clear 留容量。完整交付、错误丢弃和连接关闭也走同一收尾。

复用已有监听入口的 QUIC expiry 调度：连接发布 native QUIC 与分片截止时间的最小值，在执行域租约内清理，不新增连接级 timer、协程、堆节点、周期轮询或跨 Worker 共享状态。分片单独到期时只重新发布期限，不提前调用尚未到期的 `ngtcp2_conn_handle_expiry`。迁移校验路径读取同一 `Expiry()`，绝对时刻随原连接状态交接，不按目标 Worker 重置。

修复后首次定向真实链路回归四项全部通过：两个到期场景分别耗时 6.04 秒、16.04 秒，原有分片/零报文互通和停机取消也通过。过期报文不交付，后续完整乱序包仍转发，原 UDP 源端口及 QUIC 连接不变。另加入持续有效进度超过初始空闲期限、但未到整体期限仍能组包的正向场景，避免把整体超时测试误当作空闲续期已正确的证据。未量化吞吐、CPU 或 RSS 收益。

最终 `cnode`、`cnode_tests`、`cnode_traffic_journal` 增量构建成功。全量 CTest **1,081/1,082** 通过，用时 62.46 秒，共 208 项 unit、874 项 E2E；本轮 HY2 五项真实链路全部通过，空闲与持续进度场景各 6.03 秒，整体期限场景 16.04 秒。实际运行二进制返回 `release:20261107T204636Z`，`file` 确认 x86-64 静态 ELF。未运行官方外部客户端，未量化性能或内存收益。

唯一失败为 `e2e.config_panel_runtime.RuntimeExit.StartupFailureRollsBackEarlierTcpAndUdpListeners`：Shadowsocks 夹具的子进程在预期被占用的 `44867` 端口启动失败并退出 1，随后重绑早先的 `127.0.0.1:36339` 报 `Address in use`。现场为 `build/musl/e2e-artifacts/cnode-e2e-mnGhgc/`；未定位重绑时的占用者，不能把并行端口竞争推断写成已证实原因。本轮未修改该夹具或启动链路，也未重试掩盖失败。README 已更新当前资源预算，未提交、推送或部署，保留既有用户改动。

## 2026-11-07：回滚与停机 E2E 的端点隔离

沿用上节保留的 `Address in use` 证据，不重跑旧用例确认错误，也不把历史占用者未明的现场改写成已定位的运行时泄漏。确认夹具只按端口在默认回环地址重绑，预留 socket 在子进程启动前关闭；断言没有独立地址维度，不能排除其他并行用例取得该端点。

仅修改 `tests/e2e/config_panel_runtime.cpp`：两个生命周期用例共用一个 RAII 资源预留入口，先在默认回环地址同时持有 TCP/UDP 同端口守卫，再由该独占端口确定 `127.1.<高字节>.<低字节>` 别名，并预留别名上的 TCP/UDP。交给子进程时只关闭别名预留，默认地址守卫始终保留，阻止默认/通配端点抢占，并让“同端口但不同地址仍被其他 socket 占用”成为用例一直存在的条件。配置、连接、数据报及释放检查全部使用完整别名端点，不扩大共享固定端口锁。

TCP/UDP 没有跨协议原子选端口接口，准备阶段最多选择 32 个候选，仅对 `address_in_use` 重新选端口；其他系统错误立即上报。所有失败候选由现有 Socket RAII 立即关闭。这不是子进程启动重试、断言重试或 CTest 重试；正式场景只执行一次。

保留真实两 Worker 子进程：启动失败用例继续故意占住后续监听，要求失败退出并可重新绑定此前的 TCP/UDP 端点；SIGTERM 用例仍覆盖未完成 TCP 握手、UDP 监听与挂起的面板 HTTP 请求，检查对端关闭、任务收束及端点归还。后者去掉额外建连式探测，直接等待面板已接入并建立实际待取消的 TCP 连接。未新增 mock、脚本、特殊生产构建或生产配置语义。

Linux musl 定向 CTest 两项真实进程 E2E 均通过：启动回滚 0.02 秒、SIGTERM 0.03 秒，总耗时 0.08 秒。README 与 AGENTS 不变：本轮不改变用户契约或全局规范。未声称生产吞吐、CPU 或 RSS 改善。

最终构建检查 `cnode`、`cnode_tests`、`cnode_traffic_journal` 成功；全量并行 CTest **1,082/1,082** 通过，其中 208 项 unit、874 项 E2E，用时 62.13 秒，没有启用失败重试。实际运行 `cnode --version` 返回 `release:20261107T204636Z`。本轮只改变测试端点所有权与验证，生产热路径未改；历史现场占用者仍未知，未据此声称修复生产资源泄漏或取得性能收益。未提交、推送或部署，保留既有用户改动。

## 2026-11-07：RingDeque 嵌套右值的移动赋值

沿 UDP 会话共享队列检查 `memory::RingDeque`，发现移动赋值先 `clear()` 左值，再读取右值成员。若右值是旧元素内的子队列，clear 已析构该子队列及其后代，随后读取已结束生命周期的元数据。公开接口回归实际复现 `queue = std::move(children)` 后 `queue.size()` 为零而非预期的两个子项；这是已观察的数据丢失，未将其描述成已经过 sanitizer 检出的错误。

复用现有移动构造和 swap：先把右值存储与资源元数据摘到局部拥有者，再交换到目标，最后析构局部持有的旧内容。无需遍历元素判定嵌套关系，不复制元素、不增加分配，保持原有 noexcept 与资源传播契约。普通移动、直接自移动及源队列变空的接口不变；不引入兼容路径或新的容器抽象。

永久回归放在现有 `thread_memory_pool_test.cpp`：使用只能移动的递归项、首尾回绕后的根队列、非首项的嵌套子队列、第二次后代提取和两个不同 PMR 资源，检查 FIFO 值、后代完整性、资源归属及最终活动块和活动字节归零。原分配器全契约与新增回归均通过。

另在构建目录编译运行独立 C++ 消费程序，使用现有固定 musl Clang 工具链、`-O3 -DNDEBUG -flto=thin` 与静态 mimalloc，实际输出 `descendant tickets=201,202 additional_allocations=0 live_after_clear=0,0`。该结果只证明该消费场景的所有权与零新增分配，不代表吞吐、CPU 或 RSS 收益。临时源码与二进制已清理；README 与 AGENTS 不变，用户配置、协议及全局规范未改变。

最终按共享头影响范围重建 `cnode`、全部测试目标和 `cnode_traffic_journal` 成功；全量并行 CTest **1,083/1,083** 通过，其中 209 项 unit、874 项 E2E，用时 62.49 秒，覆盖真实进程网络互通、迁移、配置与停机生命周期。实际运行 `cnode --version` 返回 `release:20261107T204636Z`。验证范围为当前 Linux musl Release/LTO 环境，未据此作跨平台或 sanitizer 证明；未提交、推送或部署，保留既有用户改动。

## 2026-11-07：分配器扩展移动与安全重定位

`RingDeque::shrink_to_fit()` 用普通移动的 noexcept trait 选路径，却实际通过 polymorphic_allocator 调用分配器扩展构造；后者可能重新分配载荷并抛出异常。缩容循环已逐项析构旧槽位，catch 后既未回滚旧前缀，也未归还新数组。增长使用同样不匹配的构造方式，分配失败后虽然回收候选数组，却会留下被清空的已排队载荷。

公开接口使用合法的 allocator-aware、只能移动的项及真实 PMR 分配失败复现：允许前三次分配后，增长抛出 bad_alloc，原队列首载荷长度已变零；允许两次分配的缩容在隔离子进程中检测到泄漏，避免继续解引用已结束生命周期的旧项。下面是同一次修复前缩容调用内的资源计数，不是 RSS 或跨版本性能基准：

|时点|活动字节|
|---|---:|
|调用缩容前|2112|
|缩容失败返回后|3136|

统一增长、预留及缩容的存量元素构造为 `ConstructRelocatedAt`：普通移动确实 noexcept 时，直接移动完整元素并保留其内部分配器，匹配缩容破坏性迁移的异常保证；否则保持原有 move_if_noexcept 与分配器感知构造。新插入元素及复制仍走原 `ConstructAt`，使用目标资源，不能把重定位优化扩大成跨资源插入时绕过分配器。数组迁移已有外层资源 pin，快路径不再逐项重复取得它；不新增队列状态、策略对象或运行期分派。

永久回归覆盖增长前及部分迁移处的分配失败、首尾回绕后的缩容、FIFO 载荷完整性、清空后活动块和字节归零，以及跨资源新插入仍归属目标资源。缩容故障用 GoogleTest 隔离子进程保护失败前验证，未用退出绕过修复后的资源收束。分配器全契约、嵌套移动及本轮三项边界合计五项均通过。

构建目录的独立 C++ 消费程序用固定 musl Clang、`-O3 -DNDEBUG -flto=thin`、静态 mimalloc 实际验证零预算增长失败后原载荷保真、有限预算增长与缩容、FIFO 和资源归还，输出 `growth_allocations=2 shrink_allocations=1 FIFO=55..70 live_bytes_after_clear=0`。这些计数仅描述该消费场景，不代表吞吐、CPU 或 RSS 收益。临时源码与二进制已清理；用户配置及协议不变，README 与 AGENTS 不变。

相关构造差异也见 [LWG 2461](https://cplusplus.github.io/LWG/issue2461)：分配器 construct 的实际构造与异常不必等同于值类型的普通移动。该条目当前为 New，仅作风险背景，不作为已经通过的标准修订或向外部分配器施加新限制。

最终按共享头影响范围增量重建 `cnode`、全部测试目标及 `cnode_traffic_journal` 成功；全量并行 CTest **1,086/1,086** 通过，其中 212 项 unit、874 项 E2E，用时 62.52 秒。实际运行 `cnode --version` 返回 `release:20261107T204636Z`。验证范围为当前 Linux musl Release/LTO 与真实进程网络回归，未作跨平台或 sanitizer 证明；未提交、推送或部署，保留既有用户改动。

## 2026-11-07：Hysteria UDP 帧预算与 Shadowsocks 短域名边界

Hysteria 下行原先按固定 1100 字节载荷切片，没有计入协议头或对端 `max_datagram_frame_size`；HY2 续片还省略地址。长来源地址使完整 DATAGRAM 无法装入 QUIC 包，或超过协商的帧上限，导致下行队头停滞或关闭物理连接。[RFC 9221 §3–5](https://www.rfc-editor.org/rfc/rfc9221.html#section-3) 明确帧上限包含类型、长度及数据，DATAGRAM 本身不能跨 QUIC 包分片；[HY2 UDPMessage 规格](https://v2.hysteria.network/docs/developers/Protocol/) 在每片中定义地址字段。[上游分片实现](https://github.com/HyNetworks/hysteria/blob/master/core/internal/frag/frag.go) 同样扣除完整头长并保留各片地址，此处只作为互操作参考。

独立 QUIC/TLS/HTTP3 对端经真实 cnode HY2 入站、Shadowsocks AEAD UDP 出站和可控原生 UDP 对端，回送 253 字节来源域名与 3200 字节二进制载荷。修复前，对端声明帧上限 65535、512、273 字节的三项均在 5.03 秒等待下行超时；已先收到并解密校验上行，排除仅验证握手或配置的情况。失败现场分别保留在 `build/musl/e2e-artifacts/cnode-e2e-pdIHgA`、`cnode-e2e-eIfHhA`、`cnode-e2e-joHHiA`。

发送前按完整 HY 报文的本地 1100 字节预算和对端帧上限取交集，扣除 DATAGRAM 类型及实际 LEN 宽度，再扣除对应代际的 HY 头长。共用 `UdpMessageHeaderSize` 与编码器的地址格式化、端口和变长整数计长；计长不构造临时编码容器，IPv4/IPv6 文本沿用栈上 `AddressText`。每个原始报文只构造一次消息元数据，各片保留完整地址。协议片数、零载荷空间及现有队列准入均在入队前检查，不新增连接定时器、队列或轮询；接收端对旧式无地址续片的既有容忍不变。

真实 HY2 链路覆盖以下预算边界；独立对端逐片检查来源地址、分片标识并重组二进制载荷，不复用生产编码器作回声断言：

|对端帧上限（字节）|验证边界|
|---:|---|
|65535|本地完整报文预算、长域名与 IPv6 来源、多片及空报文|
|512|低于本地预算的协商上限、长域名与 IPv6 来源|
|273|长域名后仅余一字节载荷；拒绝需要 257 片的回复|
|272|长域名头恰好占满数据空间，空载荷成功、非空回复失败|
|18|一字节域名来源与单字节 LEN 的最小空间边界|

后三项还在不可表示的回复后新建同连接的独立 UDP 会话，确认无残留片、无队头阻塞且物理连接继续可用。失败只结束相应请求，不扩大为整条 QUIC 连接退役。

18 字节场景同时暴露 Shadowsocks 的独立边界缺陷：多个 AEAD/2022 解码入口把最短 SOCKS5 地址当成 IPv4 的七字节，提前拒绝合法的一、二字符域名及空载荷。[RFC 1928 §5](https://www.rfc-editor.org/rfc/rfc1928.html#section-5) 的域名地址采用长度字节、不含 NUL，最短非空地址实际为五字节；[SIP022 §3.2、§4.1](https://shadowsocks.org/doc/sip022.html#_3-2-udp) 沿用该地址格式。统一六处最低长度预检，包括经典 AEAD 双向入口、2022 AES/EIH 与 ChaCha 请求及响应；实际地址解析、AEAD、时间戳、客户端会话 ID 和重放检查均保留。

修复前，短域名空报文单测失败，经典、2022 AES 和 2022 ChaCha 三种真实原生 UDP 链路均在 4.93 秒超时，现场保留为 `cnode-e2e-aDaaOC`、`cnode-e2e-CplNPC`、`cnode-e2e-DDlNaC`。永久回归经公开编解码契约覆盖一、二字符域名与空/单字节载荷、经典三种密码套件、2022 AES/ChaCha 及 AES EIH；真实链路验证空/非空/空往返、身份隔离、坏认证拒绝、源端点稳定及正常停机。修复后上述 HY2 五项、短域名三项 E2E 与既有协议/数据报单测合计 **21/21** 通过，用时 1.49 秒。

本轮没有新增项目脚本或临时验证程序；README 同步当前下行分片和失败隔离行为，AGENTS 不变。未量化吞吐、CPU 或 RSS 收益，亦未把可控对端验证等同于本轮重新运行官方客户端。

最终增量重建 `cnode`、全部测试目标及 `cnode_traffic_journal` 成功；全量并行 CTest **1,095/1,095** 通过，其中 213 项 unit、882 项 E2E，用时 62.49 秒。实际执行 `cnode --version` 返回 `release:20261107T204636Z`。验证环境为当前 Linux x86-64 musl Release/LTO，未作跨平台或 sanitizer 证明；未提交、推送或部署，保留用户既有改动。

## 2026-11-07：连续缓冲的不可表示容量与失败后复用

`ContiguousWriteBuffer::TryPrepare()` 声明 noexcept，却只捕获 bad_alloc；当容量超过内部 vector 的 max_size 时，resize 抛出的 length_error 穿透 noexcept，直接终止进程。先通过隔离子进程的公开接口回归复现：传入 SIZE_MAX，实际收到 SIGABRT，诊断为 `std::length_error: vector::_M_default_append`。已检查 Shadowsocks 与 VLESS Encryption 的现有调用点；未证明外部网络输入能够直接触发该极端容量，不将内部接口缺陷表述为已证实的远程攻击。

在 TryPrepare 的分配入口直接使用内部容器的 max_size 拒绝不可表示容量，归还既有池内块或堆缓冲并返回 nullptr；不构造异常对象，不复制载荷，不新增状态或自定资源预算。合法容量仍走原 Prepare 和 bad_alloc 失败路径，抛异常版本 Prepare 的契约不变。

永久回归分别从池内与堆缓冲开始，验证拒绝后为空、域内分配归零，再重新准备另一种存储规模，经 TryAppendTo 交给 MultiBuffer 消费并逐字节验证载荷，最后确认资源归还。隔离子进程仅防止旧实现的进程终止破坏整套测试，不用退出跳过修复后的析构。缓冲所有权六项回归 **6/6** 通过。

独立 C++ 消费程序使用当前固定 musl Clang、`-O3 -DNDEBUG -flto=thin`、静态 mimalloc，在池内和堆初态各自验证 max_size+1 与 SIZE_MAX 两个拒绝边界；随后完成跨块载荷消费和域生命周期收束，实际输出 `rejected=4 recovered_payload_bytes=34232 outstanding_after_scope=0`。该计数是功能及所有权证据，不是吞吐、CPU 或 RSS 基准；临时源码与二进制已清理。仅更新本审查记录，README 与 AGENTS 不变，未改变用户配置或协议。

按公共头影响范围增量重建 `cnode`、全部测试目标及 `cnode_traffic_journal` 成功；全量并行 CTest **1,096/1,096** 通过，其中 214 项 unit、882 项 E2E，用时 62.47 秒。实际运行 `cnode --version` 返回 `release:20261107T204636Z`，产物为 x86-64 静态链接 ELF。验证限于当前 Linux musl Release/LTO 环境，未作跨平台或 sanitizer 证明；未提交、推送或部署，保留用户既有改动。

## 2026-11-07：DNS 零 TTL 与高位 TTL 的缓存边界

DNS 回包把 TTL 直接当作 uint32_t 参与最小值归并，最高位置位的值可能变成长缓存期；全一值还撞上“尚未取得 TTL”的哨兵而被改成 60 秒。此外，缓存把成功地址的零 TTL 抬高到 minTTL，使随后请求继续连接旧地址。[RFC 2181 §8](https://www.rfc-editor.org/rfc/rfc2181.html#section-8) 要求接收端把最高位置位的 TTL 整体按零处理，而不是屏蔽该位、截成最大正值或拒绝地址；[RFC 1035 §3.2.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-3.2.1) 规定零 TTL 数据仅用于当前事务，不应缓存。

先通过五种线面 TTL、缓存所有权单测及真实进程链路复现：原始值为 0、0x80000000、0xffffffff 时，第二个请求均未重新查询 DNS，实际 TCP 目标仍是 127.0.0.1，而不是对端更新后的 127.0.0.2；三项分别保留现场为 `build/musl/e2e-artifacts/cnode-e2e-EMNDPb`、`cnode-e2e-KjEPdb`、`cnode-e2e-HJngeb`。新增十一项修复前七项失败、四项正常 TTL 对照通过；缓存单测还观测到零 TTL 替换后旧条目仍可命中且继续持有地址存储。

解析器复用 LoadU32BE，在每条记录进入 A / AAAA / CNAME 的 TTL 归并前执行高位归零，避免在全局取最小值后才处理而遗漏混合记录。成功的零 TTL 结果不构建候选缓存容器；若已有同名条目，先按既有诊断契约报告恢复，再摘除索引、归还节点及地址存储，并同步过期负记录计数。负结果的零 TTL 同样不受本地下限延长，仍只保留既有有界恢复元数据。非零 TTL 的配置范围、查询合并、上游采样、取消与失败策略不变，不新增缓存、轮询或计时器。

永久回归覆盖零值、60、0x7fffffff、0x80000000、0xffffffff，以及仅 A 或仅 AAAA 使用高位 TTL 而另一类正常的混合归并；逐项校验完整地址集合、TTL、缓存标记及真实 UDP 查询次数。缓存消费覆盖旧正答案失效、新零 TTL 不保留、过期负元数据转成功时计数不下溢、地址存储立即归还，以及随后正常答案仍可缓存。域内分配恢复到空缓存的预留索引基线，缓存析构后归零；这不是 RSS 或吞吐测量。

真实链路使用两数据 Worker 的 cnode 进程，经 VLESS 认证、分发、DNSWorker 与 direct 出站访问 TCP 对端；对端在两次请求之间把 DNS 答案从 127.0.0.1 改为 127.0.0.2，并由实际接受连接的本地地址标识目的端点。零 TTL 三项重新查询并连接新地址，正常 TTL 两项仍复用旧答案；五项均正常停机。DNS 缓存、数据报、在途取消及地址 E2E 定向回归 **29/29** 通过，其中 18 项 E2E、11 项 unit，用时 1.88 秒。

README 同步零 TTL 的当前行为，AGENTS 不变；没有新增临时程序或脚本，未声称吞吐、CPU 或 RSS 收益。验证使用可控真实 UDP / TCP 对端，不等同于公共递归 DNS 或跨平台互操作证明。

最终增量重建 `cnode`、全部测试目标及 `cnode_traffic_journal` 成功；全量并行 CTest **1,108/1,109** 通过，用时 62.48 秒。222 项 unit 全部通过，887 项 E2E 中 886 项通过；本轮新增十三项全部通过。唯一失败为 `PanelIntegrity.InvalidRuleCandidateNeverAdmitsOrPartiallyReplacesCommittedRules`：无效候选拒绝后，`Listening(node)` 返回真。其夹具已释放默认回环地址的端口预约；日志记录了候选拒绝，但没有记录探测时监听者的归属，不能据此认定是产品准入错误或断言端口竞争已获证明。现场保留在 `build/musl/e2e-artifacts/cnode-e2e-eACFfF`，未重跑掩盖失败，未修改面板实现或该用例。

另实际运行 `cnode --version` 返回 `release:20261107T204636Z`，产物为 x86-64 静态链接 ELF。验证限于当前 Linux musl Release/LTO；未作跨平台或 sanitizer 证明，未提交、推送或部署，保留用户既有改动。

## 2026-11-07：面板准入断言的监听归属隔离

承接上一轮的 `InvalidRuleCandidateNeverAdmitsOrPartiallyReplacesCommittedRules` 失败，不直接重跑碰运气。该用例先释放 127.0.0.1 的端口预约，再只用 TCP 连接成功判断 cnode 是否错误准入，无法区分同端口的其他监听。为取得确定性证据，先让夹具自己的真实监听在首次非法候选拒绝期间保持存活；未改变生产程序，旧断言在 4.38 秒用例中确定失败，trace 标明该端口仍由夹具持有。现场保留为 `build/musl/e2e-artifacts/cnode-e2e-OAAnPO`。这证明旧探测存在归属缺口，不追认上一轮现场中未记录的监听者身份。

复用原有运行时退出用例的 RuntimePortReservation，将其唯一实现移至现有 config_panel_common.hpp，两个退出场景与面板场景共用。默认回环地址的 TCP/UDP 守卫始终持有端口；实际受测入站配置为端口确定的 127.1.x.y 别名，在启动前仅释放该别名的预约。公共 Listening / Echo 及等待入口显式接受入站地址，保留单一探测与协议交互实现，不复制 VLESS 收发或增加测试串行锁。非法候选阶段同时验证默认地址监听仍存活、隔离地址没有入站；正常发布后的真实认证和转发证明隔离探测并非无条件返回否。

原有验收全部保留：初始非法规则不确认验证器；合法 blocked 规则放行与拒绝不同目标；随后非法更新保留旧规则和验证器，不部分应用候选前缀；有效恢复解除拒绝；停机后隔离端点关闭而无关守卫继续存活。两次进程分别写 child.log 与 committed.log，避免后一次启动覆盖初始拒绝证据。未放宽断言、增加重试或关闭并行验证，也未改变生产准入、路由或配置语义。

定向真实进程验证 **3/3** 通过，用时 4.44 秒，包含上述面板场景、启动失败后的 TCP/UDP 监听回滚，以及 SIGTERM 收束在途 TCP/UDP 和挂起面板请求。无临时脚本或验证程序；README 与 AGENTS 不变，仅追加审查证据，不声称生产吞吐、CPU 或 RSS 收益。

最终增量构建 `cnode`、全部测试目标及 `cnode_traffic_journal` 成功；全量并行 CTest **1,109/1,109** 通过，其中 222 项 unit、887 项 E2E，用时 62.71 秒，先前失败的面板用例在同次全量运行中通过。实际运行 `cnode --version` 返回 `release:20261107T204636Z`。验证限于当前 Linux x86-64 musl Release/LTO，未作跨平台或 sanitizer 证明；未提交、推送或部署，保留用户既有改动。

## 2026-11-07：UoT 目标所有权与无用分配

`PacketReader` 无论是否 connect 都保存请求目标，每个报文开始时再复制一次；非 connect 帧随后用自身地址覆盖该副本，长域名由此跨稳态驻留并逐包无用分配。connect 模式也先复制固定目标、再复制到报文元数据。[SagerNet UoT 规格](https://sing-box.sagernet.org/configuration/shared/udp-over-tcp/) 明确非 connect 与 v1 每帧携带地址，connect 才使用请求固定目标；此轮只调整内部所有权，不改变线面格式、路由或认证语义。

先经公开接口预置完整 IPv4 数据报，构造含 189 字节无用请求域名的非 connect reader，再拒绝后续默认 PMR 分配。旧实现实际仍持有 190 个请求字节，读取已完整到达的 IP 数据报抛出 bad_alloc。永久回归覆盖直接构造与 PreparedRequest 构造，修复后均不保留无用域名，分配受限时仍返回正确端点 192.0.2.7:5353 和完整载荷，作用域结束后所观察资源归零。

非 connect reader 构造时立即舍弃无用请求目标，FramedEndpoint 同步避免为该 reader 构造目标副本；会话上下文和 writer 的真实目标所有权保持不变。逐包解析只在非 connect 时持有帧内目标，connect 在完成分帧后直接从稳定成员生成拥有型报文元数据，不再先复制到协程局部。未新增状态、缓存或抽象，也未为真实域名解析和报文元数据分配提供静默失败旁路。

独立 C++ 消费程序使用同一固定 musl Clang、`-O3 -DNDEBUG -flto=thin`、静态 mimalloc 与对应生产 archive，固定 189 字节请求域名、每组 256 个三字节载荷、同样的完整输入与端点校验。保留修复前后独立静态二进制，按前／后／后／前交错运行，两次各自计数一致：

|模式|实现|读循环前持有的 PMR 请求字节|256 包分配次数|累计 PMR 请求字节|PMR 请求字节峰值|
|---|---|---:|---:|---:|---:|
|非 connect，帧内 IPv4|修复前|190|256|48640|380|
|非 connect，帧内 IPv4|修复后|0|0|0|0|
|connect，固定域名|修复前|190|512|97280|570|
|connect，固定域名|修复后|190|256|48640|380|

以上仅计入自定义默认 PMR 观察到的分配请求，不包含直接向 Worker 池取得的数据块、协程帧、尺寸类取整、池驻留或 RSS；不能表述为整条链路零分配或吞吐收益。两版本每组均逐包校验 768 字节总载荷、目标及 EOF，结束后观察资源归零。临时源码和两个二进制已清理。

UoT 编解码、分段、空报文、截断及新资源压力单测，加上真实双节点 Shadowsocks UoT v1/v2、AnyTLS connect 与 Trojan 对照链路，合计 **16/16** 通过，其中 12 项 unit、4 项 E2E，用时 1.43 秒。真实链路覆盖空／非空／空、跨块大报文、非对称回复、UDP 源端点稳定及双方正常停机；没有向真实进程注入系统级 OOM，不把接口故障注入等同于该场景。README 与 AGENTS 不变。

最终增量重建 `cnode`、全部测试目标和 `cnode_traffic_journal` 成功；全量并行 CTest **1,110/1,110** 通过，其中 223 项 unit、887 项 E2E，用时 62.50 秒。实际运行 `cnode --version` 返回 `release:20261107T204636Z`。验证范围为当前 Linux x86-64 musl Release/LTO；未作跨平台或 sanitizer 证明，未提交、推送或部署，保留用户既有改动。

## 2026-11-08：连续缓冲视图的编译期借用边界

`ContiguousBufferView` 的单块路径借用源 Buffer，多块路径持有合并后的字节，但原接口同时允许临时 MultiBuffer 构造视图，以及从临时视图调用 Bytes()。前者可在源容器已析构后留下借用，后者可在合并存储已归还后留下 span；存储模式取决于运行期分片数量，不能把临时宿主一概视为安全。

先运行独立 musl C++ 消费程序，不解引用已回收的区间，只观察公开类型约束、span 长度与分配域所有权：修复前临时源和临时视图均可用，源容器结束后仍留下四字节 span，临时视图结束后仍留下六字节 span，两处对应域内活动分配均已为零。程序据此返回失败，证明接口允许借用超过宿主生命周期，而不是依赖未定义的悬垂读取来复现。

删除 const MultiBuffer&& 构造入口，统一拒绝普通和 const 右值源；Bytes() 只对 const 左值宿主开放，并删除 const&& 提取入口。保留接收按值 span 的描述符序列构造，因为描述符本身不拥有载荷，临时 span 与临时拥有型容器的寿命义务不同。不增加运行期分支、复制或分配。现有 Shadowsocks / VMess 生产调用均已使用具名源和具名视图，无需兼容重载或调用链旁路；未在这些现有调用点观测到悬垂访问，不声称本轮复现了线上 UAF。

在现有 GoogleTest 源中增加普通／const 左值可用、普通／const 右值拒绝的编译期断言；行为回归分别覆盖 MultiBuffer 与描述符序列的单块借用、多块合并、二进制零字节、源字节变化可见性、合并后源存储归还、描述符替换不破坏载荷，以及视图释放后的域内资源归零。单块路径继续验证零拷贝指针身份；分片路径验证拥有型副本不受源清空或覆盖影响，未用源码文本或异常措辞作为测试契约。

同一独立消费程序在修复后将两项临时借用能力均报告为拒绝，并走通合法左值的单块及分片消费，最终域内活动分配为零。临时源码和二进制已清理。缓冲、Shadowsocks / VMess 数据报及真实 UDP 转发矩阵定向回归 **45/45** 通过，其中 8 项 unit、37 项 E2E，用时 19.46 秒；覆盖认证、空报文、短域名、多用户、被动接管、取消及正常关闭。

README 与 AGENTS 不变，协议和用户配置未改变；本轮为借用生命周期的类型约束修复，不声称吞吐、CPU 或 RSS 收益，也不把现有真实链路回归等同于 sanitizer 证明。

最终增量重建 `cnode`、全部测试目标及 `cnode_traffic_journal` 成功；全量并行 CTest **1,112/1,112** 通过，其中 225 项 unit、887 项 E2E，用时 62.47 秒。实际运行 `cnode --version` 返回 `release:20261107T204636Z`，产物为 x86-64 静态链接 ELF。验证限于当前 Linux musl Release/LTO；未作跨平台或 sanitizer 证明，未提交、推送或部署，保留用户既有改动。

## 2026-11-08：代理协议最长绝对域名的接收边界

VLESS、VMess、Trojan 请求头及 Trojan UDP 分帧曾把原始域名字节限制为253，误拒绝253字节主机名附加根点后的合法254字节表示。依据 [RFC 1035 §3.1、§5.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-3.1)，标签上限63字节、含长度与根标签的DNS线上名称上限255字节，文本绝对域名可达254字节；这与代理地址中的单字节长度不是同一层限制。[RFC 1928 §5](https://www.rfc-editor.org/rfc/rfc1928.html#section-5)及其被 [Trojan](https://trojan-gfw.github.io/trojan/protocol.html)采用的地址格式，以单字节表示随后域名字节数；[VMess](https://www.v2fly.org/developer/protocols/vmess.html)同样使用该长度字段，[VLESS](https://xtls.github.io/development/protocols/vless.html)沿用其指令和地址结构。

修复前先运行新增回归：16项公开消费者边界测试中，253字节无根点、255字节超长及64字节标签共12项控制用例通过，四类消费者的合法254字节用例均失败。VMess 用例经真实 AuthID、AEAD 认证和服务端解密，而非访问私有明文解析器；VLESS、Trojan TLS 两项真实进程测试均在分段发送时报告 Broken pipe，后端连接等待超时。

删除 `AddressDecodeOptions.max_domain_len` 和所有调用点的重复设置，原始长度由单字节线面字段约束，主机名语义统一交给现有 `TargetAddress` 校验与规范化。保留空域名要求、元数据开关、端口和既有缓冲上限；删除将254字节一律判为非法的旧测试断言。不修改发送端的规范化表示，不新增状态、缓冲或分配机制；本轮没有性能或RSS测量，不声称吞吐或内存收益。

新增永久 GoogleTest 检查规范化域名、端口、尾随二进制载荷及下一UDP帧的字节归属，同时保持超长名称与标签拒绝。真实进程用独立客户端手工构造原始254字节大写带根点域名，逐字节发送，经认证、受控DNS、隔离回环后端传递不同请求和响应，验证双向EOF与正常停机；另走通253字节无根点表示，DNS只收到规范化253字节名称。没有借助会提前去掉根点的cnode出站生成测试请求。

增量构建 `cnode`、全部测试目标及 `cnode_traffic_journal` 成功；定向边界与地址回归 **36/36** 通过，其中16项unit、20项真实进程E2E，用时1.21秒。README 与 AGENTS 不变。

首次全量回归为1,129/1,130通过，唯一失败来自旧 Trojan UDP Contract 将仅有254/255长度前缀视为非法的断言。删除这两项过时前缀断言，保留空域名的立即拒绝；完整255字节超长名称与64字节标签的拒绝由新增公开消费者测试覆盖。修改后重建对应测试目标，协议域名与既有Trojan分帧定向单测 **18/18** 通过，用时0.07秒，未通过恢复旧接收限制来迎合断言。

最终全量并行 CTest **1,130/1,130** 通过，其中241项unit、889项E2E，用时62.12秒。实际运行 `cnode --version` 返回 `release:20261108T001936Z`，产物为x86-64静态链接ELF。验证限于当前Linux musl Release/LTO；未作跨平台或sanitizer证明，未提交、推送或部署，保留用户既有改动。

## 2026-11-08：AGENTS 定向整改——分配域、缓冲准备与握手凭据

本次按热路径内存归属、实际容量与异步所有权定向审查，确认并整改三处；不把 `shared_ptr` 或容器文本命中直接当作违例，也不声称已穷尽全仓审查。

### 流缓冲按实际入队增长

`AppendCoalescedStreamInput` 原先按字节数和半块大小估算槽数并提前 reserve；八个完整8 KiB块本可直接移入八个内联槽，却触发元数据分配。公开消费者回归在旧实现实际抛出 `bad_alloc`。删除推测性预留，保留既有小片合并策略，由实际入队按需几何扩容；必要扩容仍可失败，拥有型 packet stream 必须清空并进入 failed 状态，不能复用半提交输入。

独立 musl C++ 消费程序实际移交65,536字节，逐块检查原地址和内容；随后按8 KiB输入块解析65,535字节载荷，逐字节核对边界与EOF。后者观察到一次必要元数据分配，作用域结束后所观察分配字节为零。该计数仅覆盖自定义默认PMR资源，不代表整个Worker池或RSS。

### Hysteria UDP 编码归属 Worker 分配域

旧 `EncodeUdpMessage` 逐片构造默认分配器vector，随后把完整结果复制进已有PMR数据报队列。唯一编码器现在直接产出 `memory::ByteVector` 并移动入队；沿用物理连接分配域、原帧预算、准入与失败回滚，不新增协议私有池或平行编码器。标量写入在已有标准vector握手响应与Worker字节容器两种真实使用之间共享，UDP编码不额外清零随后必然覆盖的整片存储。

独立旧／新编码器采用相同固定musl Clang、`-O3 -DNDEBUG -flto=thin`、全静态BoringSSL和mimalloc，依次旧／新／新／旧运行。每轮覆盖V1/V2、IPv4/IPv6/253字节域名、0/37/4096字节载荷，共18种组合；预热相同尺寸后同时校验解码目标、标识与完整载荷，各次计数一致：

|每个编码／解码组合的观测|旧实现|整改后|
|---|---:|---:|
|全局 `new` 调用次数|1|0|
|拒绝全局 `new` 后完成往返|0|1|

这只证明该范围不再依赖全局 `new`，不是整个链路零分配，也未测吞吐、CPU、总RSS或系统分配器锁争用；生产程序原本已有mimalloc全局覆盖，不能把默认vector分配直接描述为已证明的系统锁争用。

### VLESS 握手密钥副本不跨 relay

完整ticket快照及其64字节PFS密钥限定在 `SendVlessHandshake` 子协程，获取、握手和按身份条件发布结束后随子协程销毁。记录层不再借用完整缓存，只借用禁止拷贝移动的窄拒绝信号；宿主先于读端构造、晚于读端销毁。跨执行域的缓存读取与发布传递拥有型值，不能让另一执行域读写调用协程的局部快照。缓存身份比较使用常量时间操作，旧延迟拒绝不能清除新发布的ticket，Handler的健康长期缓存仍可复用。

单测覆盖取消恢复、认证成功后EOF、首响应缺失、截断及认证失败；新增真实双cnode、单Worker的native/xorpub/random三模式链路，保持首条完整握手连接处于relay，同时验证后续恢复、旧拒绝保护新ticket、连接取消及再次恢复。桥只观察首响应前字节数，不记录凭据，不实现或模拟加密。密钥提前销毁的结论来自具名子协程和RAII所有权边界；没有增加生产观察钩子或运行时擦除计数，不能把链路成功冒充该计数证据。外部Xray依赖未配置，其扩展场景未执行。

当前配置的主程序、测试目标及journal构建成功；首轮定向 **75/75** 通过，其中44项unit、31项真实进程E2E，用时16.47秒。随后全量为 **1,137/1,138** 通过：唯一失败是旧AnyTLS夹具要求恰好128字节的元数据分配失败的实现形态断言，原诊断明确未发生该分配且实际载荷已交付。删除这一过时场景及只服务它的故障标志，不把断言改钉到另一个分配大小；实际需要扩容时的失败退役由新增公开packet stream回归覆盖。未修改AGENTS或用户配置。

## 2026-11-08：CI QUIC 流控、发送调度与正常关闭

[CI 42430155192](https://github.com/grrhuipp/cnode/actions/runs/42430155192) 的编译已成功，测试为 **1,129/1,130**：唯一失败是 `NormalFinKeepsConnectionReusableBeyondItsInitialWindow`，10.05秒后等待超时，连接发送额度仍为15,008,790字节。原日志没有流终止原因，不能据此认定连接窗口耗尽，也不能将某个本地机制断言为该次历史失败的唯一原因。保留下载的失败日志及进程现场，没有通过重试、延长超时、降低负载或改CI并发数掩盖失败。

### 接收窗口与有界写背压

依照 [RFC 9000 §4.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1)，接收方只通告自己准备接收的额度，消费后再归还。初始流接收窗口及自动调节上限统一为实际输入队列的512KiB，连接窗口仍为16MiB；512KiB是本地资源预算，不是协议常数。合法发送方在DNS或转发尚未就绪时受到流控，而不是发送了已获许可的字节后被本地输入预算重置。

输出仍保留至ACK后归还，512KiB队列满时挂起生产者，不再立即报资源耗尽。ACK广播唤醒后重新查找流并校验容量；取消、重置及关闭也唤醒等待者，但不冒充可写成功。等待节点只在实际挂起时从Worker分配域构造，最后一个等待者退出即归还；没有增加空闲流常驻节点或定时器。

### 物理发送与正常退役

发送按稳定流ID轮转，流额度不足只阻塞该流，后续额度事件解锁；原生回调前结束迭代器借用，回调后按ID重新查找。HTTP/3按库契约执行block/unblock及写端关闭。每轮受send quantum和最多64包限制，最后更新发送时间再发布expiry，避免遗漏ngtcp2的pacing通知。

`accepted == -1`只表示发出了ACK等控制帧，不得提交应用FIN；仅在实际接受STREAM后更新偏移及FIN状态，HTTP/3的零字节FIN也提交写偏移。RESET与本地读停止不等于真正的stream_close，不能提前释放ngtcp2仍借用的输出。HTTP/3收到读终止时通知其读端，不擅自终止仍可发送的响应；`stream_stop_sending`表示本地提前停止读取，不能误读为收到对端STOP_SENDING。

relay在双向传输及shutdown全部join后，成功仅执行健康Close；失败仍执行Cancel与abortive close。QUIC门面只有在收到FIN、输入已读尽且本地写端已shutdown时允许健康退出，物理连接继续持有待发送/待ACK的数据及FIN。单向未完成、未读尾部或显式取消仍中止，错误码为0的RESET也不冒充正常FIN。

### 受控前后对照

使用相同的新C++ QUIC对端和真实cnode进程，对照保留的背压/调度修复前本地二进制：暂停一个流的16KiB接收额度时，另一控制流在5.07秒超时；DNS挂起时发送768KiB，请求流在39毫秒被RESET，仍有3,555,081字节流发送额度。修复后的对应场景均通过，恢复额度或DNS后逐字节验证完整载荷及正常FIN，同一连接的控制流和后续新流保持可用。

首轮调度/退役修复后定向 **26/26** 通过，含22项unit、4项真实进程E2E，四并行用时18.38秒。覆盖输出2MiB背压、输入40×768KiB背压、272轮客户端重置、正常FIN累计18MiB、等待者取消与关闭、relay半关闭和收束。AnyTLS过时分配形态断言删除后的生命周期场景也已通过。该证据不等于GitHub托管环境已重新变绿，也不构成吞吐或总RSS优化结论。

整连接关闭遵守同一借用边界：立即取消应用任务并归还输入，但输出由Core保留至任务收束及监听I/O drain之后；先销毁ngtcp2，再销毁其借用的HTTP/3输出宿主，最后释放TLS。不能在Close中移走并提前析构整张流记录表，也不能先销毁HTTP/3再让QUIC结束借用。

最终Linux x86-64 musl静态构建通过。补齐写阻塞期间的远端重置与进程停机场景：前者验证目标连接终止后，同一QUIC连接的控制流和新流仍可用；后者验证停机收束等待中的生产者，并让真实目标观察到EOF或复位。最终QUIC定向 **34/34** 通过（18项unit、16项E2E，16.48秒），随后四并行全量 **1,155/1,155** 通过（260项unit、895项真实进程E2E，205.75秒）。`build/musl/cnode --version`输出`release:20261108T001936Z`，`file`确认x86-64静态ELF。可选Xray场景补全其编译定义后通过同一musl工具链的`-fsyntax-only`检查，但未执行外部Xray互操作；不能将语法检查记作E2E。临时分配探针、旧源码快照及对照二进制已删除，原CI失败现场保留在`build/musl/ci-42430155192/`。未提交或推送本轮改动，GitHub新CI及其他平台未验证。

## 2026-11-08：AGENTS 定向整改——错误终态与 UDP 借用边界

上节记录的是验证结束时的交付边界；上一轮随后已单独以 [`886bf48`](https://github.com/grrhuipp/cnode/commit/886bf48) 推送至main。本节为后续独立整改，不将新增故障回归混入上一轮提交。

### Shadowsocks 失败写入不得复用

通过公开`WriteTCPRequest`/`WriteTCPResponse`取得writer，复现部分写失败后承载流仍开放，后续写入继续增加线上字节，shutdown也能成功。修复区分无进度拒绝、已推进加密nonce、已开始底层写入以及正常写端关闭：有进度的分配失败、I/O异常和挂起后取消使writer与承载流退役；写前取消或尚无加密/发送进度的分配拒绝允许恢复。原始错误继续传播。

成功shutdown或底层明确拒绝未开始的写入进入finished，后续写在加密前抛`WriteClosed`，不能为了停止写端而丢弃仍可读取的反向数据。响应writer既有成功初始化路径已经清除主密钥及请求salt；本轮补齐Finish/Retire终态在初始化未完成时的清除，不将既有行为记作新增优化。安全恢复的初始化前分配拒绝仍保留重试所需凭据，不添加私有擦除观察钩子。

### VMess 真实错误锁存到同一终态

公开`ClientSession.DecodeResponse`在认证失败后再次提供合法响应，旧逻辑能恢复明文；`BodyDecoder.Read`在部分记录后遇到真实I/O错误，再给出余段，也能继续解码。响应头和正文现在共享decoder的active/finished/failed状态。认证、格式、截断或非取消I/O错误释放密文、记录缓冲及未交付明文，并使后续读取拒绝；`operation_aborted`仍保留已验证偏移、mask/长度密码状态及合法的取消恢复契约。

回归使用真实AEAD响应与回环TCP流覆盖响应头认证、截断及分段取消；另以受控读取故障验证TCP/UDP正文和未交付批次，失败后未消费的后续密文仍保持原字节。断言不固定读取次数、close方法调用次数或内部容器容量。

### UDP 信息只可借用左值宿主

`InspectUdpDatagram`返回借用目标地址和Buffer的指针，却允许传入临时`MultiBuffer`。编译探针中“右值调用必须被拒绝”的两条断言修复前失败。按已有连续视图约定删除`const MultiBuffer&&`重载后，同一探针通过；永久编译断言同时保留普通/const左值可用、普通/const右值不可用。已检查全部实际调用，均使用拥有型左值，无须兼容入口、额外拷贝或运行时分配。该项证明编译期借用边界，不声称已复现生产UAF。

### 验证

永久写入故障回归由可控传输接受真实前缀后，明确抛出I/O、挂起取消或分配错误；不要求固定内联容量下某次reserve必然分配。删除新增夹具中依赖这种分配形态的场景，不将阈值改钉到别处。写前取消的恢复由下一条记录的真实解密、nonce及完整明文验证，失败退役由传输状态、后续操作拒绝及线上字节不再变化验证。

Linux x86-64 musl静态构建与主程序CLI smoke通过。最终定向unit **15/15** 通过；真实进程协议矩阵及最终四并行全量 **1,161/1,161** 通过，含266项unit与895项E2E，全量用时207.39秒。覆盖正常转发、空UDP、读取取消恢复、写失败退役、正常半关闭、反向读取、认证失败及截断；未测吞吐或总RSS，不宣称对应增益。临时编译探针已删除。按用户要求新增的交付纪律维护在AGENTS.md，上一轮与本轮分开提交。

## 2026-11-08：AGENTS 定向整改——加密写生命周期与显式所有权

### VMess 请求头与正文共用写终态

失败前公开回归确认：请求头发送失败后仍能重试，而构建后的请求key/IV已经擦除；正文写失败或EOF之后仍可发布记录；相同MultiBuffer作为输入和输出也没有拒绝。非法目标导致构建拒绝时，原实现还会过早擦除尚未提交的密钥，纠正输入后无法完成正常认证。

请求头仅在构建成功后清除临时材料；已开始的写失败通过同一BodyEncoder终态阻止重新发布头和正文。codec维护active/finished/failed，输入拒绝在推进nonce、mask或输出之前完成；别名拒绝不污染下一条合法记录。正常EOF只编码一次，后续数据写报WriteClosed；底层明确拒绝未开始写也只结束写方向，不能牺牲可继续消费的反向数据。

追加回归还确认两处准入边界：关闭Asio自动取消抛出后，预先取消的VMess调用仍会消耗编码状态；已失败的ClientSession若换入一条健康传输，原错误清理会连带关闭新传输。写终态检查和显式取消检查现在位于进度清理区间之外；仅对本次已推进的编码或发送执行退役，写前取消不触碰密钥和nonce。回归通过独立对端解密、完整正文、反向读取与新传输的可用状态验证，不依赖方法调用次数或私有状态。

### VLESS record writer 与物理资源owner分离

失败前回归确认部分密文写出后异常、挂起取消、底层WriteClosed和正常shutdown后仍可重用writer；另确认关闭Asio自动取消抛出后，预先取消的调用仍会发布记录。写端现在区分active/finished/failed：Seal、rekey、XOR或已开始的发送失败终结方向，写前取消保留无进度恢复；成功shutdown或未开始的WriteClosed进入finished。record writer只借用MultiBufferWriter，物理流仍由既有owner/relay负责收束和abort，不增加dynamic_cast、代理层或第二套控制通道。

编译探针另确认writer原先可移动，而挂起协程会借用this。禁止拷贝/移动后同一探针通过，实际宿主和测试均在稳定地址原地构造；未通过移动在途对象触发未定义行为来“验证”风险。

### 借用只限左值，完整提取显式消费右值

编译探针修复前有七条边界断言失败：MultiBuffer的PrefixSpan/FrontSpan、descriptor builder的Span和AppendMultiBuffer、InitialPayload的span/PrefixSpan可借用临时宿主，完整提取又允许直接消费左值。按已有视图约定拒绝右值借用，并将MoveToMultiBuffer限定为&&；全部现有提取调用迁移为显式std::move，没有保留兼容入口。

相同探针修复后通过，永久编译断言覆盖普通/const左值与右值。仅修改调用资格，不增加复制、分配或运行时检查；已有分配失败后重试、空UDP、inline/spill及首包顺序回归继续验证实际所有权行为。

### 验证与现场隔离

当前工作区另有并行认证改动：RateLimitConfig的旧封禁字段已删除，而ban_tracking_contract_test仍引用旧字段；随后FingerprintCredential新增必填参数，但多个入站尚未迁移，两次现场构建分别被这些编译错误阻断。未覆盖、回退或提交这些改动，也未把旧测试二进制当作新源码的验证。

以508c3b8为基线建立独立原生Git worktree，仅应用本轮补丁；复用已安装依赖，关闭依赖自动安装，保持Linux x86-64 musl Release、LTO和四并行测试设置。cnode、cnode_tests与cnode_traffic_journal全部构建成功，全量 **1,174/1,174** 通过，其中279项unit与895项真实进程E2E，用时210.50秒；包含新增的13项写端回归、所有权转移、空UDP、首包顺序、加密转发、半关闭及取消。主程序--version成功，file确认为x86-64静态ELF。

本轮验证不包含并行认证改动的联合行为；未测吞吐或总RSS，不宣称性能或内存数值收益。编译期防线不引入运行时借用检查、复制或分配。临时编译探针已删除，独立验证目录在交付前移除；文档和提交仅包含本轮整改。

## 2026-11-08：AGENTS 定向整改——UDP 分帧 EOF 终态

### 失败前证据与状态边界

LengthPrefixedPacketBuffer、VLESS与Trojan的Finish原本只校验当前残留，不记录结束状态；截断报错既不终结输入，也不立即释放残留。新增八项公开行为回归在38239c4基线上全部失败：截断的长度、地址或正文可以在EOF报错后继续补齐并产出数据报；正常EOF后仍接受新输入；真实回环TCP还确认同一分帧器结束后会消费另一条传输的字节。

分帧现在使用active/finished/failed三态。截断EOF立即进入failed并释放待解析字节，Trojan同时释放已解析但尚未交付的目标；普通Feed/Append不能恢复终态。公共长度分帧器仅经显式Reset重新启用，旧Clear入口删除，XUDP现有独立场景迁移为显式重置。正常Finish可重复调用，Pop明确区分Finished与NeedMore，后续读取不再等待或消费底层传输。

VLESS复用公共分帧器的唯一终态，删除外围重复的failed标记；非法packet address与空UDP目标分配失败也进入同一失败出口。Trojan将既有失败清理收敛至私有Fail，清退pending、目标与长度状态。两处分帧Next中没有继续迭代路径的空循环一并删除；不改变线上长度、地址格式、空UDP边界或无进度读取取消恢复契约。

### 验证

在38239c4隔离基线上先构建真实回环回归，八项新增测试全部失败；仅应用本轮修复后，分帧、XUDP、公共缓冲与域名边界定向 **36/36** 通过，四并行全量 **1,182/1,182** 通过，含287项unit与895项真实进程E2E，用时209.65秒。静态主程序--version成功，file确认为x86-64静态ELF。TCP回归验证EOF后新传输仍保有完整线上字节，不用调用计数或mock回声代替消费边界。

另在a379b30基线上独立复现空UDP拥有型Buffer分配失败后仍可跳帧继续的问题：额外一项回归修复前失败，修复后通过。VLESS分帧单测改为复用既有cnode_test_core故障注入变体，不新增生产故障入口或协议私有测试库，也不依赖vector内联容量、分配次数或阈值。

### CI 错误与编译警告

[CI 42440996145](https://github.com/grrhuipp/cnode/actions/runs/42440996145)在a379b30上仅ExpiredChildReturnsQuotaBeforeBlockedSiblingResumes失败，异常为unexpected EOF reading exact socket payload。保留现场确认：准入探针先取得最后一个连接槽，随后新的加密握手HTTP上传连接被MAX_CONNECTIONS拒绝；上传线程保存的EOF到最终join才传播。过期子流仍按时释放配额，正常链路转发字节完整，不能将这个失败归为配额泄漏或增加超时解决。

测试原先以“第一个TCP读取片段的HTTP上传完成”作为准入探针的屏障，错误地把TCP分段当成加密握手阶段。桥接器现在精确收集并提交native 1-RTT固定密钥交换飞行，暂存而不再上传后续padding，确保服务端真正进入加密响应写阶段并保持握手未完成。线面长度由IV、X25519 relay、AEAD长度、ML-KEM-768/X25519公钥及tag组成，不依赖一次recv读满。提交完成经release/acquire发布，再开始争用配额；停车线程由同一互斥锁保护的停止条件唤醒并join。保留16MiB洪泛、三连接上限、8秒握手截止期、截止前旁路准入、截止后配额回收、正常链路完整转发与物理PING全部原有断言；不重试失败上传，不忽略EOF。

同一CI原始构建日志确认inbound_process_errors_test.cpp两处-Wmissing-designated-field-initializers，根因是RateLimitConfig::ip_ban缺少显式成员初始化。在定义处补{}，保持AuthFailureLimitConfig既有缺省语义，不在各调用方复制默认值。相同musl编译器以-Werror=missing-designated-field-initializers通过临时聚合初始化探针，后续联合构建没有编译警告；没有屏蔽或降低诊断级别。

CI失败场景修复后通过真实双进程、ML-KEM/X25519加密和回环对端验证，用时9.09秒；此前a379b30联合快照全量1,215项通过只能说明本地当次时序成立，不能替代上述竞争边界的确定性约束。

最终在a379b30基线上合并本轮分帧整改、编译警告修复和CI协议屏障，cnode、cnode_tests与cnode_traffic_journal构建成功；四并行全量 **1,215/1,215** 通过，含299项unit与916项真实进程E2E，用时207.79秒。主程序--version及静态ELF检查通过。原始CI失败现场保留于build/musl/ci-42440996145；临时探针、补丁、独立验证worktree与构建目录交付前清理。未测吞吐或总RSS，不宣称对应数值收益。

### 后续 CI：AnyTLS 测试端口归属

[CI 42444589001](https://github.com/grrhuipp/cnode/actions/runs/42444589001)已通过上述HTTP2截止期用例，完整编译日志无编译警告，但AnyTLS的tcp-ipv6-fragmented在5秒后超时。保留现场的error日志明确报告127.0.0.1:39447绑定失败、Address in use；同一端口也是配置中的测试面板HTTP服务。测试Port()返回临时监听的端口后立即关闭，PanelNode随后创建的面板监听恰好复用该端口，代理无法启动，客户端却连接到HTTP面板并等待TLS。不是IPv6解析错误，也不是数据量或截止期不足。

删除返回裸空闲端口的Port()。Node与PanelNode持有实际监听socket，覆盖配置和对端监听的构造阶段，只在子进程启动前释放；原生与参考进程经同一Node::Start释放入口启动，清除两处绕过启动入口的赋值。未引入端口重选、失败重试或延长超时；子进程不支持继承监听，故启动前释放与子进程实际bind之间仍非跨进程原子交接，不声称消除任意外部进程抢占。

整改后musl增量构建成功且无编译警告；真实AnyTLS会话E2E **83/83** 通过，19.25秒，包含原失败的IPv6分段场景。四并行全量 **1,215/1,215** 通过，299项unit与916项E2E，207.01秒；静态主程序--version与ELF检查通过。原CI现场保留于build/musl/ci-42444589001。未修改生产AnyTLS协议实现，未降低负载、连接限制或断言，也不以本地通过代替后续实际CI结果。

## 2026-11-09：Pin-to-Origin（会话固定归属）与零跨 Worker 数据包转发架构重构

### 动机与边界收敛

旧设计为了支持运行期跨 Worker 会话合组与被动连接迁移，在原生 `asio::io_context` 之上叠加了虚拟执行域（`ExecutionDomain`）、Socket readiness 拆包层（`NativeSocketHandoff`）、双层定时器归属（`DomainTimeouts`）、内存池跨线程 `remote_frees_` 原子队列与执行域租约检查，以及出站连接池的跨域 `AttachExclusive` / `DetachExclusive` 转移。这些机制穿透了内存分配器、传输 I/O、超时调度、出站连接池和全部有状态协议，违反 Share-Nothing 同构执行器与单线程内存池闭环回收原则。

本轮按 `AGENTS.md` 将多 Worker 架构统一收敛为 **Pin-to-Origin（会话固定归属 + 入口流量归集）**：

1. **主控协调器与同构数据 Worker**：`GroupCoordinator` 运行在主控事件循环（`main_ctx`）上，通过 `execution_context::service` 在各 Worker 原生 `io_context` 注册固定路由与 `worker_id`。所有数据 Worker 完全同构、对等，不再将全局协调器寄生在 `Worker 0` 上。
2. **纯单线程 Worker 内存池**：删除 `worker_memory::remote_frees_`、`QueueRemote`、`DrainRemoteFrees`、`ReclaimRemoteBatch`、`SetLeaseGroup` 与 `memory::OnRemoteFree` 计数。`AllocationDomain` 在构造时绑定所属线程标识，跨线程分配、释放或借用直接 `std::terminate()`，所有容器、Buffer 与会话对象在所属 Worker 线程闭环借还。
3. **原生 Socket I/O 与单层超时调度**：删除 `src/transport/internet/native_socket_handoff.hpp` 及 `ExecutionDomain`。`TcpStream` 与 `DatagramSocket` 直接持有原生 `asio::ip::tcp::socket` / `udp::socket`；`TimeoutScheduler` 仅维护每 Worker 本地最小堆，`AsyncDelay` 与 `AsyncWriteGate` 直接绑定所属 Worker `io_context`。
4. **QUIC 入站内核态 cBPF 归集**：服务端签发的 16 字节 SCID 在首 3 字节编码魔数与 `worker_id`；`SO_REUSEPORT` 监听组挂载 15 条指令的 `SO_ATTACH_REUSEPORT_CBPF` 过滤器，Short Header 与带服务端 CID 的 Long Header 包按 DCID 在内核态直达原 Worker，客户端 Initial 握手包按 `payload[6..9]`（随机 DCID 前缀）均匀哈希分流。客户端路径迁移后数据包在内核态直达原 Worker，由原 Worker 完成 RFC 9000 路径验证并经独立 `ngtcp2_path_storage` 与本地监听 socket 回包，出站连接与子流全程留在原 Worker。
5. **XHTTP 分离上行静止边界裸 `fd` 移交**：下行 `GET` 所在的原 Worker 唯一拥有完整 `XHttpPacketUpSession`、路由、出站与 Relay。当同 `session_id` 的 HTTP/1.1 `stream-up` 或 `packet-up` 落到其他 Worker 时，收包 Worker 在读完首个 HTTP 请求头的静止边界（无在途 I/O、无出站、无定时器）调用 `DetachForHandoff` 提取裸 `fd`、TLS `SSL*` 与明文/密文预读前缀，经 `co_spawn` 移交原 Worker `RestoreFromHandoff` 重建流并直接处理该请求及后续 keep-alive 请求，零跨线程 `MultiBuffer` 转发，且不跨 Worker 合组运行中的 HTTP/2 会话。
6. **原生 UDP 与出站连接池 Worker-local 独占**：原生 UDP 入站关联、`UdpHandoffDirectory`（SS2022 会话隔离与防重放 tombstone）、AnyTLS `OutboundPoolHost` 与 VLESS 0-RTT 票据状态均由所属 Worker 本地管理，消除跨 Worker 关联搬迁与出站池连接转移。未启动 `RuntimeState::Start` 的 Worker 在启动失败回滚采样中直接返回空流量/在线设备快照，避免空指针访问。

### 验证与性能/内存实证

在 Linux x86-64 musl Release（Clang 23.1.3、LTO、全局 mimalloc）环境下完成全量构建与四并行测试：**1,254/1,254** 全部通过（328 项 unit、926 项真实进程 E2E，含官方 Hysteria2 v2.13.0 参考客户端跨路径往返测试，总用时 233.56 秒）。静态主程序 `build/musl/cnode --version` 与静态 ELF 检查通过；主程序体积由 `bb393dc` 基线的 115,341,112 字节降至 107,490,952 字节（减少 7,850,160 字节 / 7.49 MiB）。

以 `bb393dc`（HEAD）为可复现基线，在同一环境与固定负载下对新旧实现执行 A/B/A/B 交错对照：

- **TCP 接收微基准（`cnode_tcp_receive_benchmark`）**：消除 `NativeSocketHandoff::Wait` 与 `ExecutionDomain` 二级调度后，1 B 突发耗时由 11,366.7 ns 降至 9,905.7 ns（-12.9%，CPU -15.5%）；8 KiB 突发耗时由 15,484.6 ns 降至 14,541.0 ns（-6.1%，CPU -7.2%）；64 KiB 突发耗时由 77,406.4 ns 降至 67,845.2 ns（-12.4%，CPU -12.8%）。
- **分配器与容器微基准（`cnode_allocator_append_benchmark`）**：移除 `remote_frees_` 排空与跨域租约检查后，`multibuffer-transfer` 1/8/9/16 块耗时由 125.3 / 407.4 / 566.2 / 845.2 ns 降至 118.5 / 397.1 / 524.5 / 759.1 ns（最多 -10.2%）；`ring-deque` 1/8/64 批耗时由 58.4 / 134.8 / 540.3 ns 降至 58.3 / 132.2 / 514.3 ns，池映射与空闲字节保持不变。
- **运行时统计采样（`cnode_runtime_sampling_benchmark`）**：消除每连接 `ExecutionDomain::LocalLease` 与跨域延迟采样后，64 活跃会话（256 轮，含资源统计）单次采样耗时由 2,001.8 ns（p50 1,913 ns / p95 1,944 ns）降至 389.9 ns（p50 351 ns / p95 370 ns，-80.5%），匿名 RSS 由 7,749,632 B 降至 7,602,176 B（-144 KiB），峰值 RSS 由 14,581,760 B 降至 14,069,760 B（-500 KiB）。
- **VLESS/TLS 真实进程吞吐与内存（`cnode_tls_throughput_benchmark`）**：单流上传吞吐由 672.20 / 688.66 MiB/s 提升至 756.82 / 778.92 MiB/s（CPU 由 0.0294 / 0.0293s 降至 0.0267 / 0.0255s），8 流上传吞吐由 579.75 / 581.97 MiB/s 升至 579.79 / 605.48 MiB/s；8 流预热/活跃匿名内存由 6,545,408 / 6,549,504 B 降至 6,492,160 / 6,500,352 B，进程峰值 RSS（HWM）由 14.96 MiB 降至 14.37 MiB（减少约 595 KiB）。
- **Hysteria2 四 Worker 真实进程基准（`cnode_hysteria_throughput_benchmark`）**：256 连接单流上传/下载的活跃匿名内存由 33.80 / 33.90 MiB 降至 32.45 / 32.45 MiB（减少 1.28 / 1.38 MiB），负载峰值 RSS 减少 1.75 / 1.81 MiB，守护进程 CPU 减少 4.2% / 6.5%；16 连接 × 64 流（1,024 并发流）上传/下载的建连耗时由 1.153 / 1.115s 降至 1.101 / 1.065s，活跃匿名内存由 45.76 / 44.34 MiB 降至 43.03 / 43.32 MiB（减少 2.61 / 0.96 MiB），负载峰值 RSS 减少 3.40 / 3.97 MiB。临时基线构建目录在验证后清理。

## 2026-11-09：Worker-Local 单层运行时收敛与 QUIC 收发路径精简

### 双层迁移遗留结构清理

在 Pin-to-Origin 架构落地后，继续清除原为支撑跨 Worker 会话迁移而保留的连接级克隆与中转层：

1. **删除 `PhysicalSessionCapabilities`、`PhysicalSessionRegistry`、`LazyProtocol` 与 `DomainTrafficSnapshot`**：
   - 原实现为每条 TCP、QUIC 和原生 UDP 会话单独创建 `PhysicalSessionCapabilities` 与 `PhysicalSessionRecord`，在单连接内部重复实例化 `proxyman::inbound::Handler`（`LazyProtocol`）、`proxyman::outbound::HandlerLookup`、`dispatcher::DefaultDispatcher`、`dns::DNS`、`SessionTrackingState` 与 `StatsShard`，并在采样或关闭时遍历 `runtime_->connections` 全表归并。
   - 收敛后，每个数据 Worker 仅维护唯一一套 `inbound_handlers`、`outbound_handlers`（`HandlerLookup`）、`DefaultDispatcher`、`dns::DNS`、`SessionTrackingState` 与 `StatsShard`；`ProtocolRuntime` 直接暴露本协议唯一的 `OnlineTracker()`。所有 TCP、QUIC 与原生 UDP 会话直接复用所属 Worker 的组件；`CollectRuntimeStats` 由 $O(\text{活跃连接数})$ 降为 $O(1)$，`SnapshotTraffic` / `CommitTraffic` / `RollbackTraffic` / `GetOnlineDevices` 直接读取 Worker 唯一状态，删除 `src/app/session_capabilities.cpp` 及 `SessionTrackingState::ExtractAvailableTraffic` / `MergeCompletedTraffic`。
2. **`OutboundConfiguration` 单线程化**：移除每个 Worker 私有 `OutboundConfiguration` 中的 `publication_mutex_`、`std::atomic<std::shared_ptr<const Snapshot>>` 与原子代际计数，改为所属 Worker 线程内的直接读写。
3. **删除原生 UDP `UdpReplyFence` 死代码**：移除无调用方的 `UdpReplyFence::AsyncDrain` 及每个 UDP 关联/回包上的 `UdpReplyFence::Lease` 引用计数。
4. **Hysteria2 (QUIC) 内联 `inbox` 批量 `Flush` 与非阻塞直发**：
   - 删除 `QuicListener::inboxes` 哈希表与每包 `AllocateShared<Inbox>()` / `inboxes.erase()`，将 `inbox`（`RingDeque`，空态 0 字节分配）内联至 `Connection::Core`；`Pump` 排空当前批次全部输入包后仅执行一次 `Flush()`。
   - `QuicListener::Queue` 在输出队列为空时优先执行非阻塞 `send_to`，直接发送成功时省去 `ByteVector` 分配拷贝、`socket.output` 入队、`SignalChannel` 通知与 `SendLoop` 协程切换；删除 `QuicListener::Drain` 与 `SocketState::sending` / `drained`。
5. **`QuicMemory` 直连 `ThreadMemoryPool()`**：移除 `Connection` 的 `AllocationDomain` 包装，`QuicMemory` 直接向所属 Worker 的 `ThreadMemoryPool()` 分配与归还块，消除每次 `ngtcp2` / `nghttp3` 内存操作的 `ScopedAllocationDomain` 与 `domain_memory_resource` 虚调用开销。
6. **本地构建默认关闭 LTO**：更新 `AGENTS.md`、`CMakeLists.txt`、`mise.toml`、`.github/workflows/ci.yml` 与 `README.md`，本地开发与测试默认 `CNODE_ENABLE_LTO=OFF`，仅 CI 开启 `-DCNODE_ENABLE_LTO=ON`。

### 验证与性能/内存实证

全量 **1,254/1,254** 测试通过（328 项 unit、926 项 E2E）。在相同 LTO Release 编译选项下与 `b2a3d63` 及 `bb393dc` 基线对照：

- **运行时统计采样（`cnode_runtime_sampling_benchmark`，64 活跃 VLESS 会话，256 轮）**：
  - 单次采样耗时由 `bb393dc` 的 2,001.8 ns（p50 1,913 ns）、`b2a3d63` 的 389.9 ns（p50 351 ns）进一步降至 **222.5 ns（p50 111.0 ns / p95 130.0 ns，较基线 -88.9% / p50 快 17.2 倍，$O(1)$ 恒定时间）**。
  - 64 条活跃会话的内存池占用（`settled_pool_bytes`）由 `438,272 B` 降至 **`303,104 B`**（减少 `135,168 B`，**每条连接减少 `2,112 B` / `2.06 KiB`**）；匿名 RSS 由 `7,749,632 B` 降至 `7,462,912 B`（-280 KiB），进程峰值 RSS 由 `14,581,760 B` 降至 `13,869,056 B`（-696 KiB）。
- **Hysteria2 四 Worker 真实进程基准（`cnode_hysteria_throughput_benchmark`，256 物理连接）**：
  - **上传（Upload 256）**：建连耗时由 `0.547s`（`bb393dc`）/ `0.535s`（`b2a3d63`）降至 **`0.507s`**；守护进程总 CPU 由 `1.790s` / `1.714s` 降至 **`1.664s`（-7.0%）**；256 连接就绪匿名内存由 `33.80 MiB` / `32.45 MiB` 降至 **`31.61 MiB`**（较基线减少 **2.09 MiB**）；负载峰值 RSS 由 `43.16 MiB` 降至 **`40.82 MiB`**（减少 **2.23 MiB**）。
  - **下载（Download 256）**：建连耗时由 `0.564s` / `0.544s` 降至 **`0.502s`（-11.0%）**；守护进程总 CPU 由 `2.061s` / `1.927s` 降至 **`1.829s`（-11.3%）**；256 连接就绪匿名内存由 `33.90 MiB` / `32.45 MiB` 降至 **`31.71 MiB`**（较基线减少 **2.09 MiB**）；负载峰值 RSS 由 `104.05 MiB` 降至 **`100.65 MiB`**（减少 **3.24 MiB**）。

### 远端 CI 42603174265 修复：XHTTP 跨 Worker 移交禁止捕获原 Worker `stream_handler`

- **问题根因**：[CI 42603174265](https://github.com/grrhuipp/cnode/actions/runs/42603174265) 在 `e2e.http2_worker_migration`（`FourWorkersTcpTls/Http2WorkerMigration.SourceIndependentSessionsMergeAndDetachWithActiveReads/(true, "packet-up")`）中因守护进程触发 `terminate called without an active exception` 退出而失败。`DoXHttp1ServerHandshake` 在将跨 Worker 的 `packet-up` / `stream-up` 连接通过 `net::co_spawn(*owner_reactor, ...)` 移交至目标 Worker 时，闭包按值捕获了原接收 Worker 通过 `memory::AllocateShared` 在本线程 `ThreadMemoryPool` 上分配的 `stream_handler`（`LogicalTransportStreamSink`）。`asio::detail::co_spawn_entry_point` 在目标 Worker 线程上先向原 Worker 派发完成通知，随后才在目标 Worker 线程销毁 `co_spawn_state` 及其闭包参数；当原 Worker 先一步从 `ProcessAcceptedTCP` 返回并释放 `metadata_owner` 时，目标 Worker 成为 `stream_handler` 的最后一个 `shared_ptr` 持有者并在目标 Worker 线程上调用原 Worker 内存池的 `Deallocate`，触发 `worker_memory::Deallocate` 的跨线程检查 `std::terminate()`。同时 `XHttpSessionDirectory::Acquire` 原先在协调器线程构造含 `RingDeque` 的 `SignalChannel` 交由等待 Worker 跨线程 `close()` / 析构。
- **修复方案**：
  1. `DoXHttp1ServerHandshake` 跨 Worker 移交闭包不再捕获原 Worker 的 `stream_handler`，仅提取纯值超时参数（`handshake_timeout`、`idle_timeout`），并在目标 Worker 线程本地按需构造和销毁窄 `UploadTransportStreamHandler`；同连接后续 keep-alive 请求同样支持在请求头静止边界按目标会话归属移交。
  2. `XHttpSessionDirectory::Acquire` 将跨线程等待通知由 `SignalChannel` 替换为绑定等待方 `io_context` 的 `OwnerWaiter`（`steady_timer` + 原子通知标记 + `net::post` 同线程取消），消除跨线程 `RingDeque` / channel 访问与释放。
  3. `xhttp_session_lifecycle_test` 新增双 Worker 线程 + 协调器线程回归测试，使用析构即校验所属线程的 `OriginBoundSink` 覆盖上行先到等待与跨 Worker 移交。
  4. 修复 `e2e.quic_udp` 全矩阵测试中 Shadowsocks 跳点仅预留 TCP 端口未同步预留 UDP 端口导致的并发 `Address in use`，并在 `anytls_padding` 系列测试中确保客户端 `Roundtrip` 收完响应与 EOF 后再发送 `kCmdAlert`（`ForceReconnect`），消除高并发下 `HeartResponse` 先于下行转发完成触发的提前断连竞态。

## 2026-11-09：移除 `AllocationDomain` 租约体系与全栈单线程化/碎片层精简

### 架构与设计精简内容

1. **清除 `AllocationDomain` / `domain_memory_resource` 执行域租约遗留体系与容器瘦身**：
   - 移除 `ExecutionDomain` 与 `PhysicalSessionCapabilities` 后，生产代码已不再实例化 `memory::AllocationDomain`（`detail::current_allocation_domain` 恒为 `nullptr`），但 `include/common/allocator.hpp` 与 `include/common/buf/multi_buffer.hpp` 仍保留了完整的域租约检查与弱引用跟踪。
   - 删除 `AllocationDomain`、`domain_memory_resource`、`ScopedAllocationDomain`、`ScopedWorkerAllocation`、`CurrentAllocationDomain`、`RetainResource`、`TrackResourceLifetime`、`RequireAllocationLease`、`AdoptPmr`、`worker_memory::DomainOf` / `SetDomain`、生产零调用的 `request_memory`、`buf::Buffer::RequireLease()`（14 个热路径访问器）及 `Buffer::Adopt()` / `MultiBuffer::Adopt()`；在 `worker_memory` 上直接提供 $O(1)$ 的 `OutstandingAllocations()`。
   - 移除 `ThreadLocalAllocator<T>` 与 `RingDeque<T>` 中的 `std::weak_ptr<void>` 生命周期跟踪字段，将 `sizeof(ThreadLocalAllocator<T>)` 从 32 字节缩减为 8 字节（单指针），每个 `session::Context` 实例减少 312 字节；删除 `session::SessionPoolResource()` 冗余静态包装与全仓 19 处 `ScopedWorkerAllocation` 调用。
2. **修复动态出站退役毒化 Worker XHTTP 出站任务组 & 精简 `proxyman/outbound`**：
   - 移除 `OutboundPoolHost::AsyncJoin()` 中误对所属 Worker `io_context_` 调用的 `JoinXHttpClientTasks(reactor_)`（仅由 `Worker::StopRuntimeTask()` 在 Worker 停机排空阶段统一调用一次），防止单个出站动态退役后将该 Worker 的 `XHttpClientTaskOwner::joining_` 永久置为 `true` 导致后续 XHTTP 出站流报 `operation_aborted`。
   - 删除生产零调用的 `PreparedOutboundCreator::StatelessCreateFn` 分支。
3. **XHTTP 跨 Worker 边界收敛、H1 上行单次 Coordinator 往返与取消源去重**：
   - `GetXHttpPacketSession` 在 `claim.owner != &io_context` 时直接返回 `nullptr`（Fail-Closed），禁止跨 Worker `co_spawn` 共享单线程 PMR 对象 `XHttpPacketUpSession`。
   - 扩展 `XHttpSessionOwnerResolution` 在归属当前 `io_context` 时直接从本地 `XHttpSessionTable` 解析并返回 `session`，使 `DoXHttp1ServerHandshake` 省去第二次 `GetXHttpPacketSession` 协调器往返。
   - `XHttpPacketUpSession::AwaitDownlink` 改用栈上局部 `SignalChannel` 等待，不再向 `TimeoutScheduler` 最小堆插入 `max()` 定时事件。
   - 删除 `XHttpPacketUpServerStream` 与 `XHttpSplitOutboundStreamBase` 中遮蔽基类 `AsyncStream::cancellation_` 的重复成员，修复 `XHttpPacketUpServerStream::Close()` 与 `OnCancellation` 通知不同取消源的问题。
4. **Hysteria2 (QUIC) 连接所有权内联与 $O(1)$ CID 解绑 / $O(N)$ 超时扫描**：
   - 删除 `struct QuicOwnership` 堆分配包装，将 `retired_` 与 `expiry_` 内联至 `Connection`。
   - `QuicListener::DissociateAll` 改为按 `connection.connection_ids_` 定向擦除（由全表 $O(\text{总 CID 数})$ 降为 $O(\text{本连接 CID 数})$）；`ArmExpiry()` 与 `ExpiryLoop()` 改为直接遍历唯一连接表 `sessions`，消除 `ExpiryLoop()` 中的 `std::find` $O(N^2)$ 去重。
5. **原生 UDP 与策略/协调器单线程化及碎片文件清理**：
   - `UdpResourceBudget`、`InboundDatagramAssociation`（`claimed`、`protected_until_`）与 `UdpHandoffDirectory` 移除跨线程迁移时代遗留的原子操作与系统默认分配器穿透，统一使用单线程算术与 `ThreadLocalUnorderedMap`；删除死虚函数 `Inbound::AdoptWorkerStateFrom` 与 `UdpIngress::ProcessDecoded` 的死参数 `response`。
   - `rule::DetectRulePolicy` 移除 `std::mutex`、原子代际计数、CoW 整表复制与 `thread_local LocalCache`，改为 Worker 本地单线程直读直写；删除死重载 `Worker::UpdateRule(std::string_view, std::vector<DetectRule>)`。
   - `GroupCoordinator` 删除无生产调用的 `WorkerTarget`、`WorkerRoute` 链表、`FindWorker`、`FindWorkerId` 及 `RegisterWorker` 的多余 `executor` 参数；统一 `UserOnlineTracker::TryConnectSession` 与 `proxy::AdmitAuthenticatedInbound` 为单一入口，删除 `ConnectionLimiter::Coordinator()` 与 `DatagramSessionEnvironment::coordinator`。
   - `AnyTLS` 出站 `SessionPool` 移除恒为 `0` 的 `worker` 字段与 `PaddingState` 中多余的 `net::dispatch`；合并 `SsUotVersion` 至 `proxy::uot::Version`；删除 `freedom_outbound.cpp` 中不可达的 `!target.IsDomain()` 死分支；`Http2ServerSubStreamState` 的 `owner_signal_` 与 `credit_signal_` 改为 `std::optional<SignalChannel>` 惰性构造；删除 `StreamSettings::flags` 冗余位掩码、遗留头 `include/common.hpp`、死错误码 `TLS_CERT_INVALID` 及 8 个单函数碎片文件（`bootstrap_inbounds.hpp/.cpp`、`bootstrap_panels.hpp/.cpp`、`bootstrap_shutdown.hpp/.cpp`、`http2_settings.cpp`、`http2_initial_window.cpp`）。

### 验证与性能/内存实证

全量 **1,251/1,251** 测试通过（325 项 unit、926 项真实进程 E2E，用时 233.09 秒），静态 ELF 主程序验证通过，主程序体积由 137 MiB 降至 134 MiB。在同一环境、固定负载与相同编译选项（`CNODE_ENABLE_LTO=OFF`、Release）下执行 A/B/A/B 交错重复基准对照：

- **容器与缓冲微基准（`cnode_allocator_append_benchmark`）**：
  - `multibuffer-transfer` 1/8/9/16 块耗时由 `132.1~132.4` / `458.8~467.7` / `610.7~615.6` / `923.1~943.2 ns` 降至 **`90.3~91.5` / `313.4~315.8` / `415.0~426.1` / `647.5~651.6 ns`（耗时减少 30.4% ~ 32.1%）**。
  - `buffer-span (multibuffer)` 1/8/9/16 块耗时由 `8.96~15.20` / `22.23~70.75` / `115.28~158.80` / `152.51~225.70 ns` 降至 **`5.46~5.52` / `14.65~14.66` / `92.93~93.29` / `105.91~110.31 ns`（耗时减少 19% ~ 79%）**。
- **活跃会话内存池与采样基准（`cnode_runtime_sampling_benchmark`）**：
  - **64 活跃 VLESS 会话**：内存池映射（`settled_pool_bytes`）由 `303,104 B` 降至 **`233,472 B`（减少 `69,632 B` / -23.0%，每条连接再省 `1,088 B`）**；稳态匿名 RSS 由 `7,573,504 / 9,670,656 B` 降至 **`7,413,760 / 7,417,856 B`（至少减少 156 KiB）**；单次采样耗时 p50 稳定在 **`100.0 ns`**（p95 `101.0 ns`）。
  - **512 活跃 VLESS 会话**：内存池映射（`settled_pool_bytes`）由 `1,126,400 B` 降至 **`946,176 B`（减少 `180,224 B` / -16.0%）**；稳态匿名 RSS 由 `20,627,456 B` 降至 **`19,980,288 B`（减少 632 KiB）**；进程峰值 RSS 由 `28,356,608 B` 降至 **`27,664,384 B`（减少 676 KiB）**；单次采样耗时由 `174.6 ns`（p50 `130 ns`）降至 **`142.1 ns`（p50 `101 ns`，-18.6%）**。
- **VLESS/TLS 真实进程基准（`cnode_tls_throughput_benchmark`）**：
  - 8 流上传吞吐由 `206.84 / 552.08 MiB/s` 升至 **`587.66 / 609.22 MiB/s`**，守护进程 CPU 由 `0.3069 / 0.1844s` 降至 **`0.1708 / 0.1649s`**，活跃匿名内存由 `6,590,464 / 6,516,736 B` 降至 **`6,455,296 / 6,471,680 B`**，峰值 RSS 由 `14,643,200 / 14,626,816 B` 降至 **`14,610,432 / 14,462,976 B`**。
- **Hysteria2 四 Worker 真实进程基准（`cnode_hysteria_throughput_benchmark`）**：
  - **256 连接单流上传/下载**：上传守护进程总 CPU 由 `4.284 / 1.706s` 降至 **`1.409 / 1.437s`（-15.8% ~ -17.4%）**，活跃匿名内存由 `32.10 / 32.34 MiB` 降至 **`31.45 / 31.44 MiB`（减少 632 ~ 876 KiB）**，负载峰值 RSS 由 `40.28 / 40.78 MiB` 降至 **`39.82 / 39.63 MiB`（最高减少 1.09 MiB）**；下载守护进程总 CPU 由 `1.820 / 1.821s` 降至 **`1.545 / 1.621s`（-11.0% ~ -15.1%）**，256 连接就绪匿名内存由 `30.67 / 31.65 MiB` 降至 **`30.61 / 30.68 MiB`**。
  - **16 连接 × 64 流（1,024 并发流）**：上传守护进程总 CPU 由 `4.879 / 4.343s` 降至 **`4.337 / 3.949s`（-9.1%）**，吞吐升至 **`56.41 / 57.00 MiB/s`**；下载守护进程总 CPU 由 `5.146 / 4.316s` 降至 **`3.933 / 4.005s`（-7.2% ~ -23.6%）**。

## 2026-11-09（续）：Worker 统计/采样去协程化、Outbound 构造即就绪与入站准入/传输层收敛

### 架构与流程精简内容

1. **Worker 统计、流量采样与在线设备查询去协程化（消除伪协程与双层协程帧分配）**：
   - 将 `Worker::SnapshotTraffic`、`CommitTraffic`、`RollbackTraffic`、`GetOnlineDevices` 从无挂起点的 `net::awaitable<...>` 改为直接同步方法（参数由 `std::string` 按值拷贝改为 `std::string_view` 只读借用），并将 `CollectRuntimeStats` 与 `CollectNativeRuntimeStats` 合并为唯一的同步方法 `Worker::CollectRuntimeStats(bool include_resources) const`；`UserTrafficSnapshot` 简化为 `UserTrafficCounters` 类型别名。
   - `Controller::Impl::collectTraffic`、`GetOnlineSnapshot` 与 `CollectWorkerRuntimeStats` 统一改用 `worker->PostCall(...)` 直接调用同步方法，省去每次统计/流量采样在每个 Worker 上额外分配内层 `awaitable` 协程帧的开销。
2. **`OutboundConfiguration` 构造即就绪（RAII），删除 `BindHosts` 二次快照重建**：
   - `OutboundConfiguration` 构造函数直接接收可选的 `net::io_context* reactor`（及 `net::io_context&` 重载），在构造期一次性创建 `Hosts` 与 `Snapshot`，删除 `BindHosts` 及 `Worker::RuntimeState::Start` 启动时对全部出站快照的二次全量复制重建。
3. **WebSocket `AcquireWrite` 消除竞争时 `co_spawn` 与 `SslContext` 冗余指针清理**：
   - `AsyncWriteGate::Acquire` 支持传入可选 `net::cancellation_slot custom_cancellation`；`BaseWsStream::AcquireWrite` 在写竞争时直接 `co_await write_gate_.Acquire(false, wait.Slot())`，省去每次写竞争的 `net::co_spawn` 协程帧分配与额外调度。
   - 删除 `SslContext::ctx_` 冗余裸指针成员，`Native()` 直接返回 `native_owner_.get()`。
4. **原生 UDP `UdpHandoffIdentity` 内存池化与统一入站凭据校验 / `MakeUserProfile` 收敛**：
   - `UdpHandoffIdentity` 的 `listener` 与 `tag` 由 `std::string` 改为 `memory::ThreadLocalString`，消除新 UDP 关联向系统默认分配器的穿透。
   - 在 `src/proxy/inbound_admission.hpp` 中提取 `VerifyInboundCredential` 与 `MakeUserProfile`，收敛 `anytls`、`trojan`、`vless`、`hysteria` 四处重复的 `CredentialRevision` + `FingerprintCredential` + `CheckInboundCredential` 频控检查样板及 6 个入站协议的 `UserProfile` 构建代码。
   - 另对 `QuicListener::ReceiveLoop` 进行了同步直通 `Feed` 实验：实测表明在 16×64（1,024 并发流）单连接 256 KiB 满窗口突发下，若收包循环不经 `Enqueue` + `Pump` 让出事件循环，会阻塞队列中已被唤醒的 `QuicStreamState::ReadMultiBuffer()` 消费者协程排空流前缀，且同步执行 TLS/QUIC `Flush()` 会拖慢 UDP 套接字取包导致 256 连接并发握手重传（建连耗时由 0.51s 增至 2.16s）；因此保留 `Enqueue` + `Pump` 的收包与批量 `Flush` 解耦设计。

### 验证与性能/内存实证

全量 **1,251/1,251** 测试通过（325 项 unit、926 项 E2E，用时 231.81 秒）。在同一环境与编译选项下执行 A/B/A/B 交错重复基准对照：

- **运行时统计采样基准（`cnode_runtime_sampling_benchmark`，64 活跃 VLESS 会话，256 轮）**：
  - **不含资源遍历（`resources=0`）**：单次采样耗时由 `125.26 / 122.56 ns`（`p50 = 90.0 ns` / `p95 = 91.0 ns`）降至 **`78.38 / 78.54 ns`（`p50 = 40.0 ns` / `p95 = 50.0 ns`，耗时再降 -37.1%，p50 延迟再降 -55.6%，较初始 `bb393dc` 基线的 1,913 ns 快 47.8 倍）**；进程峰值 RSS 由 `15,101,952 / 15,167,488 B` 降至 **`14,647,296 / 14,704,640 B`（减少 452 KiB）**。
  - **含资源遍历（`resources=1`）**：单次采样耗时由 `132.77 / 177.74 ns`（`p50 = 100.0 / 140.0 ns`）降至 **`86.25 / 85.97 ns`（`p50 = 50.0 ns` / `p95 = 60.0 ns`，耗时再降 -35.1% ~ -51.6%，p50 延迟减半 -50.0%）**；进程峰值 RSS 由 `15,503,360 / 15,556,608 B` 降至 **`15,036,416 / 15,089,664 B`（减少 456 KiB）**，内存池映射保持 `233,472 B`。
- **VLESS/TLS 与 Hysteria2 真实进程基准（`cnode_tls_throughput_benchmark` / `cnode_hysteria_throughput_benchmark`）**：
  - VLESS/TLS 8 流上传吞吐由 `580.65 / 259.62 MiB/s` 升至 **`602.35 / 609.21 MiB/s`**，守护进程 CPU 为 **`0.1692 / 0.1665s`**，峰值 RSS 由 `14,450,688 / 14,479,360 B` 降至 **`14,397,440 / 14,450,688 B`**。
  - Hysteria2 256 连接上传/下载守护进程 CPU 为 `1.451s / 1.558s`，传输完成活跃匿名内存由 `31,428,608 B` 降至 **`31,244,288 B`（减少 180 KiB）**，负载峰值 RSS 由 `39,608,320 / 39,493,632 B` 降至 **`39,350,272 B`（减少 140 ~ 252 KiB）**；16×64（1,024 流）上传就绪匿名内存由 `40.28 / 40.16 MiB` 降至 **`39.95 MiB`（减少 204 ~ 320 KiB）**，负载峰值 RSS 由 `48.82 / 48.68 MiB` 降至 **`48.57 MiB`**。

## 2026-11-09（再续）：主链路 `route_target` 零冗余拷贝、传输/协议层去重与控制面单层化

### 架构与流程精简内容

1. **主链路 `route_target` 零冗余拷贝与消除 `DetectRulePolicy::Blocked` 二次正则扫描**：
   - `src/proxy/inbound_admission.hpp` (`BindInboundRequestTarget`)：初始绑定时将 `ctx.outbound.route_target` 置为空 `{}`（仅在 `ApplySniffOverride` 的 `sniffing.route_only` 分支才填充 `route_target`），消除每次域名请求在嗅探前多做一次 `TargetAddress` 字符串分配与拷贝，并修复 DNS 路由填充 `target.resolved_addr` 后 `DetectRulePolicy::Blocked` 因 `original_target.resolved_addr` 为空而对同一 `host:port` 将全部审计正则规则重跑第二遍的问题。
   - `src/proxy/freedom/freedom_outbound.cpp`：删除路由已结束后的 `ctx.outbound.route_target` 死写入，并复用 `infra::ParseOptionalOutboundBind` 统一 `sendThrough` / `sendThroughStrategy` 校验。
2. **传输层 `WaitSocket` / `SendMultiBuffer` 收敛、WebSocket 类树扁平化与 REALITY 冗余清理**：
   - `src/transport/internet/connection_timeouts.hpp`、`tcp_stream.cpp`、`datagram_socket.cpp`：提取泛型 `detail::WaitSocket` 统一 TCP 与 UDP 套接字 readiness 等待（`TcpStream::Impl::Wait` 与 `DatagramSocket::Impl::Wait` 直接返回 `awaitable` 省去一层协程包装）；`DatagramSocket::Impl::SendMultiBuffer` 经 `ConstBufferSpanBuilder` 直接委托给 `SendBuffers`，删除 `MultiBufferSequence` 与 40 行重复发送循环。
   - `include/transport/internet/ws_stream.hpp`、`src/transport/internet/ws_stream.cpp`：将 `BaseWsStream` 标记为 `final`，移除稳态转发期从不读取的 8 字节 `conn_id_` 常驻字段（改为 `Handshake` 参数传入），删除空壳派生类 `WsServerStream` 与 `WsClientStream`。
   - `src/transport/internet/reality_tls.hpp/.cpp`：提取 `ComputeRealityTranscriptHmac` 复用客户端与服务端 Transcript HMAC 计算，删除恒为 `true` 的 `RealityServerConnState::authenticated` 字段，并在 `VerifyRealityClientHelloHandshake` 中原地掩码/恢复 `session_id` 消除额外 `aad` 整包拷贝。
3. **协议层 Protobuf Varint 权威实现、VLESS 0-RTT 内存池化与 `VlessEncryptedIo` 零堆分配**：
   - `include/common/byte_reader.hpp`、`src/transport/internet/grpc_hunk.cpp`、`src/proxy/vless/vless_codec.cpp`：在 `ByteReader` 中提供权威 `ReadVarintU64()`，消除 `grpc_hunk.cpp` 与 `vless_codec.cpp` 的重复 Varint 实现；在 `ParseHeaderAddons` 内闭环校验非空 `flow`，移除 `vless::RequestHeader::addons_len` 与 `mux::FrameHeader::has_global_id` 冗余字段。
   - `src/proxy/vless/vless_ticket_service.cpp`：改用 `memory::ThreadLocalString` 与带透明查找的 `memory::ThreadLocalUnorderedMap`，消除 0-RTT Ticket 查询/签发向系统全局分配器的穿透；`vless_inbound.cpp` 与 `vless_outbound.cpp` 将 `VlessEncryptedIo` 改为协程帧内 `std::optional` 原地构造，并移除单字段包装 `UdpIoState`。
   - `src/proxy/vless/udp_framing.cpp`、`src/proxy/trojan/udp_framing.cpp`：`WriteUdpDatagram(MultiBuffer)` 委托给 `span<const_buffer>` 重载；内联并删除微型碎片文件 `src/proxy/trojan/credentials.cpp` 与 `src/transport/internet/reality_server_name.cpp`；移除 VMess 出站无读者且未擦除的 `MemoryAccount::uuid` 字段与 `ServerSession` 双参数转发重载。
4. **控制面与 V2Board 客户端单层化、流量日志去锁去红黑树与 `NodeSnapshot::rules` 零拷贝共享**：
   - `include/api/api.hpp`、`src/api/v2board/v2board.cpp`、`http_response.hpp`、`online_report.cpp`：合并删除 `include/api/panel_factory.hpp`，消除 `APIClient::Impl` 双层 Pimpl 与纯转发虚函数，提取 `FetchConditionalResource` 复用条件 GET 逻辑；`http_response.hpp` 改用 `buffer.data()` 块拷贝替代 `std::istreambuf_iterator<char>` 逐字节流迭代；`BuildOnlineReportPayload` 改用单次排序去重线性构造替代 `std::map<int64_t, std::set<std::string>>` 红黑树。
   - `src/service/controller/*`：`TrafficJournal` 移除无并发争用的 `std::mutex` 与 `Append` 中的 `std::map` 二次聚合；`NodeSnapshot::rules` 与 `NodeRuntime::UpdateRules` 改为 `std::shared_ptr<const std::vector<rule::DetectRule>>` 消除 304 刷新与规则发布时的两次 `std::vector<std::regex>` 深拷贝；合并删除微型碎片头文件 `tls_policy.hpp` 与 `panel_schedule.hpp`；清理 `infra/json`、`infra/log`、`runtime_config_types` 中的零调用死函数/死宏。

### 验证与性能/内存实证

全量 **1,251/1,251** 测试通过（325 项 unit、926 项 E2E）。在同一环境与编译选项下执行 A/B/A/B 交错重复基准对照：

- **TCP 接收与发送基准（`cnode_tcp_receive_benchmark` / `cnode_tcp_send_benchmark`）**：
  - `tcp-receive 8192B`：单次 burst 墙钟耗时由 `15,702.0 / 15,723.7 ns` 降至 **`14,213.2 / 14,291.8 ns`（稳定下降 -9.1% ~ -9.5%）**，CPU 耗时由 `13,100.4 / 13,146.9 ns` 降至 **`11,905.7 / 11,984.1 ns`（-8.8% ~ -9.1%）**；`1B` burst 墙钟耗时由 `11,777.3 / 11,504.2 ns` 降至 **`10,383.8 / 11,230.2 ns`（最高 -11.8%）**。
  - `tcp-send 65536B (16 pieces)`：单次 burst 墙钟耗时由 `47,772.7 / 46,866.1 ns` 降至 **`46,123.8 / 44,497.0 ns`（-3.5% ~ -5.1%）**。
- **运行时统计采样与真实进程基准（`cnode_runtime_sampling_benchmark` / `cnode_tls_throughput_benchmark` / `cnode_hysteria_throughput_benchmark`）**：
  - 64 活跃会话统计采样保持 **`68.49 / 68.33 ns`**（`resources=0`，`p50 = 30.0 ns`）与 **`85.91 / 86.03 ns`**（`resources=1`，`p50 = 50.0 ns`），0 次堆分配，内存池 `settled_pool_bytes = 233,472 B`。
  - VLESS/TLS 启动驻留 RSS（`server_started`）由 `13,082,624 / 13,086,720 B` 降至 **`13,021,184 / 13,017,088 B`（减少 60 ~ 68 KiB）**，8 流上传吞吐达 **`597.92 / 674.52 MiB/s`**。
  - Hysteria2 256 连接下载负载峰值 RSS 由 `98,988,032 / 98,164,736 B` 降至 **`97,865,728 / 97,308,672 B`（减少 836 KiB ~ 1.07 MiB）**；16×64（1,024 流）下载守护进程 CPU 由 `4.002 / 3.960s` 降至 **`3.886 / 3.911s`**。

## 2026-11-09（第四轮）：VMess 写状态机收敛、单包 AEAD 统一、入站 UoT 去重与控制面 `users` 零拷贝

### 架构与流程精简内容

1. **单包无状态 AEAD 加解密辅助收敛**：
   - `src/proxy/aead.hpp`、`src/proxy/shadowsocks/ss_udp.cpp`、`src/proxy/vmess/aead/encrypt.cpp`：在 `src/proxy/aead.hpp` 中提取栈上 RAII 守卫 `ScopedAeadCtx` 与单包无状态辅助函数 `SealOneShotAead`、`SealScatterOneShotAead`、`OpenOneShotAead`，统一 Shadowsocks UDP 与 VMess AEAD 头/长度加解密，消除重复的 `EVP_AEAD_CTX` 初始化、cleanup 与 `OPENSSL_cleanse` 样板代码。
2. **VMess 客户端与服务端 Body 写出状态机收敛与移除死接口 `BodyEncoder::EncodeEnd`**：
   - `src/proxy/vmess/encoding/body.hpp/.cpp`、`client.cpp`、`server.cpp`、`tests/vmess_udp_datagram_test.cpp`：在 `BodyEncoder` 上提供统一的 `WriteMultiBuffer`、`WriteBuffers`、`WriteEOF` 异步流写出方法，统一处理可写性检查、协程取消状态检查、固定 UDP 目标校验、首包响应头合并写出以及 `WriteClosed` / 异常流中止状态机；`ClientSession` 与 `ResponseBodyWriter` 简化为单行委托调用并删除 `ResponseBodyWriter::Flush`，消除约 110 行重复代码；移除零生产调用的 `BodyEncoder::EncodeEnd(buf::MultiBuffer&)`。
3. **入站 UoT（UDP-over-TCP）接入与分发编排收敛**：
   - `src/proxy/uot/uot.hpp/.cpp`、`src/proxy/anytls/inbound/anytls_inbound.cpp`、`src/proxy/shadowsocks/inbound/ss_inbound.cpp`：提取 `proxy::uot::DispatchPreparedUotRequest` 统一完成 `BindInboundRequestTarget`、`InitialPayload` 提取、`PacketReader`/`PacketWriter` 构造与 `dispatcher.Dispatch` 调用，消除 AnyTLS 与 Shadowsocks 入站 UoT 分发重复样板。
4. **控制面 `NodeSnapshot::users` 零拷贝共享、在线设备上报快速路径与微型头文件合并**：
   - `src/service/controller/node_state.hpp`、`controller.cpp`、`online_snapshot.cpp`、`src/api/v2board/online_report.cpp`、`node_info_json.hpp/.cpp`、`v2board.cpp`：将 `NodeSnapshot::users` 改为 `std::shared_ptr<const std::vector<api::UserInfo>>`，消除 304 刷新时对全量用户的深拷贝；`BuildOnlineSnapshot` 先 `std::erase_if` 剔除无效项再排序去重，且 `BuildOnlineReportPayload` 对已排序去重的规范输入直接在 `std::span` 上零分配、零二次排序分段构造 `alive_body`；将 `ExtractBlockDetectRules` 归位至 `node_info_json`。
   - `include/infra/inbound_field_rules.hpp`：合并并删除单用途微型头文件 `include/infra/proxy_protocol_config.hpp` 与 `src/infra/http2_initial_window.hpp`。

### 验证与性能/内存实证

全量 **1,251/1,251** 测试通过（325 项 unit、926 项 E2E，用时 232.25 秒）。在同一环境与编译选项下执行 A/B/A/B 交错重复基准对照：

- **TCP 接收与发送基准（`cnode_tcp_receive_benchmark` / `cnode_tcp_send_benchmark`）**：
  - `tcp-send 65536B (1 piece)`：单次 burst 墙钟耗时由 `46,274.8 / 44,953.8 ns` 降至 **`44,411.0 / 43,840.3 ns`（-2.5% ~ -4.0%）**，CPU 耗时由 `42,423.5 / 41,111.8 ns` 降至 **`40,700.8 / 40,165.4 ns`**。
  - `tcp-send 65536B (8 pieces)`：单次 burst 墙钟耗时由 `47,616.9 / 45,397.3 ns` 降至 **`44,816.9 / 44,164.9 ns`（-2.7% ~ -5.9%）**。
  - `tcp-send 65536B (16 pieces)`：单次 burst 墙钟耗时由 `48,258.1 / 46,723.0 ns` 降至 **`45,557.4 / 45,581.7 ns`（-2.4% ~ -5.6%）**。
  - `tcp-receive 8192B`：单次 burst 墙钟耗时保持 **`14,321.1 ns`**（CPU 耗时 **`11,994.7 ns`**）。
- **运行时统计采样与真实进程基准（`cnode_runtime_sampling_benchmark` / `cnode_tls_throughput_benchmark` / `cnode_hysteria_throughput_benchmark`）**：
  - 64 活跃会话统计采样保持 **`68.41 / 68.29 ns`**（`resources=0`，`p50 = 30.0 ns`，`max = 40.0 ns`）与 **`86.38 / 86.02 ns`**（`resources=1`，`p50 = 50.0 ns`），0 次堆分配，峰值 RSS 由 `14,819,328 / 14,852,096 B` 降至 **`14,794,752 / 14,835,712 B`**。
  - VLESS/TLS 8 流上传吞吐（`Upload8`）由 `582.78 / 588.81 MiB/s` 升至 **`738.30 / 747.91 MiB/s`（+26.7% ~ +27.0%）**；8 流下载吞吐（`Download8`）由 `556.95 / 613.16 MiB/s` 升至 **`591.31 / 619.09 MiB/s`**；启动驻留 RSS 保持 `13,017,088 B`。
  - Hysteria2 256 连接上传守护进程总 CPU 由 `1.397 / 1.398s` 降至 **`1.395 / 1.387s`**，建连耗时由 `0.529 / 0.529s` 降至 **`0.505 / 0.523s`**；16×64（1,024 流）上传守护进程总 CPU 由 `4.058 / 4.004s` 降至 **`4.055 / 3.960s`**，下载吞吐保持 **`35.48 MiB/s`**。

## 2026-11-09（第五轮）：`session::Context` 与 `UserOnlineSessionGuard` 瘦身、路由/GeoData 按需化及传输/协议深度去重

### 架构与流程精简内容

1. **`session::Context` 消除热路径 `NowMicros()` 系统调用与 `UserOnlineSessionGuard` 瘦身 72 字节**：
   - `include/common/session.hpp`、`src/common/session.cpp`、`src/app/proxyman/inbound/handler.cpp`：删除全仓零读取的死字段 `session::Context::accept_time_us`（消除每条连接与子流创建时的 `std::chrono::system_clock::now()` 系统调用）；将 `session::Inbound::client_ip_source` 从 32B `memory::ThreadLocalString` 替换为 1B `enum class ClientIpSource : uint8_t { Socket, ProxyProtocol, HttpHeader }`（消除子流派生时的 PMR 字符串拷贝与准入字符串比较）；在 `MakeReceiverSettings` 中过滤主标签并删除 `ReceiverSettings::has_route_inbound_tags`。
   - `include/common/sharded_user_stats.hpp`、`src/common/sharded_user_stats.cpp`：消除 `UserOnlineSessionGuard` 的 `std::shared_ptr<void>` 类型擦除及与 `DeviceReturn` 重复的 `tag_`、`user_id_`、`client_ip_` 拷贝字段，使 `sizeof(UserOnlineSessionGuard)` 从 **96 字节降至 24 字节**；提取泛型 `ReleaseDeviceCount` 合并 `DeviceQuota::Release` 与 `UserOnlineTracker::OnUserDisconnected` 的 25 行重复代码。
2. **`DomainRuleSet::Match` 写时转小写、`GeoDatabase::LoadCategories` 零冗余分配与 `Router::Route` 精简**：
   - `src/geo/geodata.cpp`：`DomainRuleSet::Match` 对已全小写的规范化域名直接零拷贝借用（仅含大写字符时写时转换）；`LoadCategories` 先用大小写不敏感二分查找过滤 `wanted`，消除扫描未命中分类时的 ~1,750 次 `std::string` 堆分配；`ProtoReader` 直接组合复用 `ByteReader`。
   - `src/app/router/router.cpp`：删除单字段包装类 `GeoSiteCondition` / `GeoIPCondition` 与 6 个冗余 `has_*_condition` 布尔字段，并在 `Router::Route` 入口单次提取 `target_domain`、`target_addr`、`target_port`。
   - `include/common/byte_reader.hpp`、`address_codec.hpp`、`mux_codec.cpp`、`dns.cpp`、`datagram_exchange.hpp`：补充权威 `VarintU64Size` 与 `ByteWriter::WriteVarintU64`，复用 `ForwardedMetadata::FromView` 与 `LoadU16BE` / `StoreU16BE`。
3. **`UserStore` 泛型化与控制面碎片内联 / `PanelLogContext` 预存复用**：
   - `include/app/proxyman/inbound/user_store.hpp`、`src/app/proxyman/inbound/user_store.cpp`、`prepared_config.hpp`：补齐 `~PreparedVmessUser()` 对 `uuid` 的 `SecureZeroMemory` 擦除；删除零外部调用的 `UserStore::VlessUsersView` / `VlessUsers()`（消除 `FindVlessUser` 双倍 `shared_ptr` 原子引用计数开销）；用 `using` 类型别名与 `BuildKeyedUsers` / `FindKeyedUser` 模板统一 4 类协议用户快照构建与查找。
   - `src/service/controller/*`、`src/api/v2board/v2board.cpp`：将 `node_transition.cpp` 与 `online_snapshot.cpp` 内联入对应头文件并删除原 `.cpp`；在 `PanelRuntime` 与 `APIClient` 中预存 `log_context` 与 `node_id`，消除 13 处重复构造 `PanelLogContext` 样板。
4. **AnyTLS、Mux、Trojan 与 HTTP/1、HTTP/2、XHTTP、Dialer 深度去重**：
   - `src/proxy/anytls/*`：移除 `LogicalEndpoint::ReadMultiBuffer()` 中被外层 `uot::FramedEndpoint` 立即擦除的 `SetUDP` 循环与死成员；将每次发包的 3 次 `PaddingScheme::RecordFor` 二分查找收敛为 1 次；删除未文档化的 `"key"` 别名；合并 `anytls_inbound.cpp` 连续 3 个 `DiscardFramePayload` 分支；将 `anytls::PasswordHash` 内联入 `credentials.hpp` 并删除 `src/proxy/anytls/credentials.cpp`。
   - `src/proxy/mux/inbound/mux_inbound.cpp`、`src/proxy/trojan/*`：删除死方法 `ReplyQueueState::TotalBytes()` 与 75 行重复的 `TcpSubState::WriteBuffers`，合并 `ProcessInboundImpl` 与 `ProcessInbound`（消除一层 10 参数协程帧）；移除 `trojan::EncodeRequestTo` 未使用的 `payload` 参数与重复的 `OPENSSL_cleanse`。
   - `src/transport/internet/*`：删除死函数 `SanitizeForLog`；删除 `Http2ServerSession::grpc_request_path_` 32B 常驻字段、`LowercaseAscii` 临时字符串分配、多余 `ReadEofAction()` override 及 60 行重复 `WriteMultiBuffer`；`GetXHttpPacketSession` 一行委托给 `ResolveXHttpSessionOwner`；`OutboundTransportTarget` 新增 `Candidates()` 视图，`XHttpSplitOutboundStreamBase` 提取 `DialAndBuildUploadRequest` 消除 45 行重复代码；`outbound_target_builder` 删除死字段 `inbound_source_port` 并统一 `SelectOrderedBind`。

### 验证与性能/内存实证

全量 **1,251/1,251** 测试通过（325 项 unit、926 项 E2E，用时 238.97 秒）。在同一环境与编译选项下执行 A/B/A/B 交错重复基准对照：

- **64 活跃 VLESS 会话内存占用与统计采样（`cnode_runtime_sampling_benchmark`）**：
  - **`resources=0`**：64 活跃会话匿名内存（`anonymous_rss_bytes` / `settled_anonymous_rss_bytes`）由 `7,581,696 / 7,577,600 B` 降至 **`7,393,280 / 7,397,376 B`（稳定减少 180 ~ 188 KiB，每活跃会话减少约 2.9 KiB）**；进程峰值 RSS 由 `14,811,136 / 14,848,000 B` 降至 **`14,741,504 / 14,761,984 B`（减少 68 ~ 84 KiB）**。
  - **`resources=1`**：64 活跃会话匿名内存由 `7,790,592 / 7,786,496 B` 降至 **`7,643,136 / 7,643,136 B`（稳定减少 144 ~ 148 KiB）**；进程峰值 RSS 由 `15,220,736 / 15,253,504 B` 降至 **`15,192,064 / 15,204,352 B`**，采样耗时保持 **`85.99 / 86.06 ns`**（`p50 = 50.0 ns`，`p95 = 60.0 ns`）。
- **TCP 接收与发送基准（`cnode_tcp_receive_benchmark` / `cnode_tcp_send_benchmark`）**：
  - `tcp-send 65536B (1 piece)`：墙钟耗时由 `45,457.4 / 43,779.0 ns` 降至 **`43,182.7 / 42,723.9 ns`（-2.4% ~ -5.0%）**；`8 pieces` 由 `45,741.4 / 45,589.9 ns` 降至 **`44,212.9 / 43,150.9 ns`（-3.3% ~ -5.4%）**；`16 pieces` 由 `47,649.7 / 46,486.4 ns` 降至 **`44,650.6 / 44,295.1 ns`（-4.7% ~ -6.3%）**。
  - `tcp-receive 1B`：墙钟耗时由 `10,127.1 / 9,884.0 ns` 降至 **`9,784.4 / 9,995.1 ns`**。
- **VLESS/TLS 与 Hysteria2 真实进程基准（`cnode_tls_throughput_benchmark` / `cnode_hysteria_throughput_benchmark`）**：
  - VLESS/TLS 8 流上传吞吐达 **`683.86 MiB/s`**，守护进程 CPU 由 `0.1561 / 0.1555s` 降至 **`0.1635 / 0.1488s`**。
  - Hysteria2 256 连接上传就绪匿名内存由 `30,711,808 / 30,613,504 B` 降至 **`30,547,968 / 30,515,200 B`（减少 96 ~ 160 KiB）**，传输完成活跃匿名内存由 `31,395,840 / 31,227,904 B` 降至 **`31,121,408 / 31,195,136 B`（最高减少 268 KiB）**，吞吐升至 **`69.45 / 69.11 MiB/s`**；256 连接下载传输完成活跃匿名内存由 `90,656,768 / 89,927,680 B` 降至 **`90,308,608 / 88,809,472 B`（减少 340 KiB ~ 1.07 MiB）**，峰值 RSS 降至 **`98,627,584 / 97,124,352 B`（最高减少 1.01 MiB）**。

## 2026-11-09（第六轮）：移除 `OutboundPoolHost` 二次分派、Mux 子流多态直接分派、Trojan UDP 端点合一与入站注册去重

### 架构与流程精简内容

1. **移除 `proxyman::outbound::OutboundPoolHost` 二次协程分派、`net::detached` 与死配置位**：
   - `include/app/proxyman/outbound/handler.hpp`、`src/app/proxyman/outbound/handler.cpp`、`include/app/proxyman/outbound/prepared_config.hpp`、`src/app/worker.cpp`、`src/proxy/anytls/outbound/anytls_outbound.cpp`、`src/proxy/vless/outbound/vless_outbound.cpp`：删除 `OutboundPoolHost` 及其 `Process()` 协程包装器、`Borrow` 引用计数守卫、`CancelIfIdle` 中的 `net::co_spawn(..., net::detached)` 静默分离协程、`join_waiters_` 矢量与 `OutboundConfiguration::Hosts` / `AsyncJoinHosts` / `PreparedOutboundCreator::persistent_state` 死字段。
   - `Handler` 直接持有按需懒分配的 `AwaitableTaskGroup tasks_`（仅在首次 `Spawn` 时分配内部状态）与 `std::unique_ptr<proxy::Outbound> proxy_`，`Handler::Dispatch(...)` 直接单次调用 `co_return co_await proxy_->Process(...)`，消除每次出站请求的一层多余协程帧分配与二次分派，且所有活跃请求由 `HandlerLookup::Get` 返回的 `std::shared_ptr<Handler>` 自然保活并在最后一条请求结束时触发 `proxy_` 析构退役；Worker 停机在排空入站与重置 `outbound_handlers` 后统一取消并 `AsyncJoin()` `outbound_tasks`。
2. **Mux 入站子流去除 `std::variant` 二次分发与 Trojan 双向 UDP 帧端点合一**：
   - `src/proxy/mux/inbound/mux_inbound.cpp`：在 `MuxSubSession` 基类中新增 `IsUdp()` 与虚函数 `PushClientFramePayload(...)`，由 `TcpSubState` 与 `UdpSubState` 各自实现；将 `sub_sessions` 从 `std::variant<TcpSubInfo, UdpSubInfo>` 改为 `std::unique_ptr<MuxSubSession>`，消除每帧查找后的 `std::visit` / `std::get_if` 二次分发，合并 `SessionStatus::NEW` 的 TCP/UDP 分支并统一收口 `SessionStatus::KEEP` / `END` / `EOF` 分派路径。
   - `src/proxy/trojan/udp_framing.hpp`、`src/proxy/trojan/inbound/trojan_inbound.cpp`、`src/proxy/trojan/outbound/trojan_outbound.cpp`：在 `udp_framing.hpp` 中定义统一的 `trojan::UdpStreamEndpoint`（继承 `proxy::OutboundStreamEndpointBase`，支持可配置的 `ReadEofAction`、附带 `fallback_target` 的首包发送与 `ShutdownPeerWrite`），同时替代并删除入站 `TrojanUdpReader` / `TrojanUdpWriter`（45 行）与出站 `TrojanUdpOutboundEndpoint`（55 行）。
3. **入站协议注册去重、异步流取消去重与公共基础库清理**：
   - `src/proxy/inbound_admission.hpp`、`trojan_inbound.cpp`、`anytls_inbound.cpp`、`hysteria_inbound.cpp`、`ss_inbound.cpp`：提取 `proxy::CreateUserOnlineProtocolRuntime` 与泛型 `proxy::BuildHashedInboundUsers<PreparedUser>`，消除 4 个协议重复的 `OnlineTracker` 构造 lambda 与哈希用户构建循环；用基类虚函数 `runtime.OnlineTracker()` 替代 `trojan_inbound.cpp` 与 `anytls_inbound.cpp` 中的 `dynamic_cast<UserOnlineProtocolRuntime*>(&runtime)`。
   - `include/transport/async_stream.hpp`、`src/transport/internet/xhttp_session.cpp`、`src/transport/internet/transport_dialer.cpp`：将 `AsyncStream` 默认 `NotifyCancellation` / `NotifyClosed` 的 `ErrorCode` 默认参数设为 `ErrorCode::CANCELLED`，删除派生类中重复转发的 override。
   - `src/common/rule.cpp`、`src/common/session.cpp`、`include/common/ip_utils.hpp`、`src/api/v2board/v2board.cpp`、`src/app/bootstrap.cpp`：将 `DetectRulePolicy` 的全局 `std::unordered_map<std::string, ...>` 替换为支持 `std::string_view` 透明查找的 `memory::ThreadLocalUnorderedMap`（消除每次规则匹配的临时 `std::string` 分配与全局分配器旁路）；`FormatAccessLog` 用 `append` + `std::to_chars` 替代 `std::format_to(std::back_inserter(...))`；内联单调用方的 `FormatHttpHostHeader`；将 `bootstrap_cli.cpp` 合入 `bootstrap.cpp` 并删除 `include/app/bootstrap_cli.hpp` 与 `src/app/bootstrap_cli.cpp`（净减 2 个文件）。

### 验证与性能/内存实证

全量 **1,251/1,251** 测试通过（325 项 unit、926 项 E2E）。在同一环境与编译选项下执行 A/B/A/B 交错重复基准对照：

- **启动期与运行期驻留内存（`cnode_tls_throughput_benchmark` / `cnode_runtime_sampling_benchmark` / `cnode_hysteria_throughput_benchmark`）**：
  - **VLESS/TLS 真实进程基准**：守护进程启动驻留 RSS（`server_started`）由 `13,410,304 / 13,410,304 B` 稳定降至 **`13,021,184 / 13,021,184 B`（稳定减少 380 KiB / -2.9%）**；8 流上传（`Upload8`）峰值 RSS 由 `14,561,280 / 14,585,856 B` 稳定降至 **`14,397,440 / 14,360,576 B`（稳定减少 160 ~ 220 KiB）**，守护进程总 CPU 由 `0.1596 / 0.1468s` 降至 **`0.1481 / 0.1446s`（最高 -7.2%）**，上传吞吐峰值达 **`675.03 MiB/s`（+24.9%）**；8 流下载（`Download8`）峰值 RSS 由 `14,794,752 / 14,761,984 B` 稳定降至 **`14,581,760 / 14,569,472 B`（稳定减少 188 ~ 208 KiB）**。
  - **64 活跃 VLESS 会话采样（`cnode_runtime_sampling_benchmark`）**：`resources=0` 进程峰值 RSS 由 `14,741,504 / 14,766,080 B` 降至 **`14,700,544 / 14,716,928 B`（减少 40 ~ 48 KiB）**；`resources=1` 进程峰值 RSS 由 `15,183,872 / 15,204,352 B` 降至 **`15,147,008 / 15,159,296 B`（减少 36 ~ 44 KiB）**，0 次堆分配，采样延迟 **`68.38 ns`**（`p50 = 30.0 ns`，`p95 = 40.0 ns`）。
  - **Hysteria2 四 Worker 真实进程基准**：守护进程启动驻留 RSS 由 `14,487,552 / 14,532,608 B` 稳定降至 **`14,176,256 / 14,159,872 B`（稳定减少 304 ~ 364 KiB）**；256 连接上传峰值 RSS 由 `39,366,656 / 39,292,928 B` 降至 **`38,912,000 / 39,137,280 B`（减少 152 ~ 444 KiB）**，吞吐升至 **`69.67 MiB/s`**；16×64（1,024 流）上传峰值 RSS 由 `49,418,240 / 49,127,424 B` 降至 **`48,324,608 / 48,693,248 B`（减少 424 KiB ~ 1.04 MiB）**；16×64（1,024 流）下载峰值 RSS 由 `360,611,840 / 358,948,864 B` 降至 **`358,383,616 / 359,448,576 B`（最高减少 2.13 MiB）**。
- **TCP 接收与发送基准（`cnode_tcp_receive_benchmark` / `cnode_tcp_send_benchmark`）**：
  - `tcp-receive 1B`：单次 burst 墙钟耗时由 `9,999.3 / 9,900.3 ns` 降至 **`9,888.2 / 9,786.8 ns`（-1.1%）**，CPU 耗时由 `7,682.5 / 7,574.1 ns` 降至 **`7,602.5 / 7,493.2 ns`**。
  - `tcp-send 1B`：单次 burst 墙钟耗时由 `6,310.0 / 6,276.2 ns` 降至 **`6,276.0 / 6,260.8 ns`**；`8192B (1 piece)` 由 `10,355.0 / 10,192.8 ns` 降至 **`10,251.1 / 10,137.5 ns`**；`8192B (16 pieces)` 由 `11,372.3 / 11,228.2 ns` 降至 **`11,190.3 / 11,220.7 ns`**。

## 2026-11-09（第七轮）：跨线程内存/借用防线加固、QUIC/REALITY/VLESS/SS 热路径瘦身、`ConnectionLimiter` 短路与 37 个碎片文件内聚

### 架构与流程精简内容

1. **跨线程内存池与借用安全防线加固 + `ConnectionLimiter` 默认零限额热路径短路**：
   - `src/proxy/vless/vless_encryption_runtime.cpp`（合入原 `vless_ticket_service.cpp`）：将跨线程投递至主控线程 `coordinator->Services()` 的 `StoreKey::tag` 与 `TicketDirectoryService::stores_` 从 Worker 专属的 `memory::ThreadLocalString` / `ThreadLocalUnorderedMap` 修正为 `std::string` / `std::unordered_map`（消除长标签跨线程释放触发 `worker_memory::Deallocate` 终止隐患），并删除全仓仅此一处调用的 `GroupCoordinator::WorkerIdForContext`。
   - `src/transport/internet/xhttp_session.cpp`：`ResolveXHttpSessionOwner` 在 `access != XHttpSessionAccess::Open` 时优先同步查询本 Worker 的 `XHttpSessionTable`（命中则零跨线程 `PostCall` 直接返回），需要跨线程调用 `coordinator->PostCall` 时将 `session_namespace` 与 `session_id` 转为 `std::string` 按值捕获，消除协程取消时悬垂 `std::string_view`。
   - `include/app/rate_limiter.hpp`：当默认配置未启用全局连接限额/单 IP 限额及封禁检查时，`ReservePhysical` 与 `Reserve` 直接零分配、零跨线程 `PostCall`、零断开时 `eventfd` 回收返回 `Admission{RejectReason::NONE, {}}`；`Family` 仅在 `TracksGlobalConnections()` 为真时分配。
2. **Hysteria/QUIC、REALITY、WebSocket 与嗅探层热路径瘦身及编解码统一**：
   - `src/transport/internet/hysteria/*`：`QuicMemory` 内联并提供进程级静态 `QuicMemory::Ngtcp2()` / `QuicMemory::Nghttp3()`，删除每条 `Connection::Core` 上的 80B `memory` 成员；`Connection::core_` 由 `std::unique_ptr<Core>` 改为原位 `std::optional<Core>`（消除每条 QUIC 连接的额外堆分配与二次指针解引用）；删除 `Connection::reactor_`、`Executor()` 与零生产调用的 `EncodeV2TcpResponse`；`V1ClientHello::auth`、`EncodeV1ServerHello`、`EncodeV1Response` 改用 Worker PMR 分配器；`StartRawStream` 优先使用 `input.PrefixSpan` 零拷贝解析；`QuicStreamState` 提取 `Abort(bool)` 并补齐 `input_.ReleaseIfIdle()`。
   - `src/transport/internet/reality_*`、`tls_stream.*`、`ws_stream.*`、`tcp_stream.*`：`RealityClientHelloReader::TakeHello()` 按值移动 `handshake` 进入 `VerifyRealityClientHello`（消除每次 REALITY 入站握手的整包二次分配与拷贝）；删除 `RealityClientState::server_public`（32B）、`server_name`（32B）、`DetachedTlsState::handshake_done`、`DetachedTcpState::nonblocking`、`TcpStream::PrepareTlsIo()`、`DatagramSocket::NativeHandle()` 与 `TimeoutEvent::ScheduleAfter(delay, context)`；`BaseWsStream` 提取 `ConsumePayloadBytes` 并收敛 `AcquireWrite()`。
   - `include/common/byte_reader.hpp`、`src/sniff/*`：新增 `LoadU24BE`、`StoreU24BE`、`QuicVarintSize`、`ByteReader::ReadU24BE()`、`ReadU64BE()`、`ReadQuicVarint()`；统一 `tls_sniffer`（提取 `ReadRecordHeader`）、`quic_sniffer`、`http_sniffer`（复用公开的 `TargetAddress::ParsePort`）、`hysteria_protocol`、`http2_session`（`GrpcHunkPrefix`）与 `vless_codec` 的大端整数与 Varint 编解码。
3. **VLESS、VMess、Shadowsocks、UoT 核心去重与瘦身**：
   - `src/proxy/vless/*`：`VlessEncryptionWriter::WriteBuffers` 直接将多段输入拼入 `frame_buffer` 的明文偏移区并原地 `SealVlessEncryptionRecord`（消除 8KB `Buffer::New()` 中转借用、`memcpy` 与 `OPENSSL_cleanse`）；握手协程在派生读写密钥后立即释放 1.2KB PFS 状态；在 `udp_framing.hpp` 中提取统一的 `vless::UdpStreamEndpoint` 替代 `VlessUdpReader` / `VlessUdpWriter`；`VisionReader`/`VisionWriter` 补齐析构密钥擦除并避免非 TLS 流逐字节扫描。
   - `src/proxy/vmess/*`、`src/proxy/inbound_admission.hpp`：移除无状态空类 `TimedUserValidator` 与单调用方模板 `InboundTrackerRuntime`，统一 `vmess`/`vless`/`ss` 入站 `create_runtime` 与 `runtime.OnlineTracker()`（消除全部 4 处 `dynamic_cast`）；修复 `FindByAuthIDForTag` 热点缓存回退重复解密并在 `Touch` 前保存局部指针防自别名覆盖。
   - `src/proxy/shadowsocks/*`、`src/proxy/uot/uot.cpp`：统一 `ss::KeyBytes` 与 `PreparedKeyBytes`，删除 `PreparedShadowsocksUser::key_size` / `salt_size`（每 SS 用户减少 16B 常驻内存）；合并 `RequestBodyWriter` 与 `ResponseBodyWriter` 重复的 `WriteMultiBuffer` / `WriteBuffers` / `FirstChunkView` 实现；`uot::PacketReader::ReadMultiBuffer` 消除跨 `co_await` 的 780B `header_bytes` 栈数组。
4. **37 个单用途碎片文件内聚与启动期静态用户释放**：
   - 内联并删除 37 个冗余碎片 `.cpp` / `.hpp` 文件（含 `bootstrap_setup/runtime/monitor`、`startup_inbounds`、`controller/control.cpp`、`controller_impl.hpp`、`journal_executor.hpp`、`node_runtime.*`、`panel_node_ids.*`、`outbound_source_config.cpp`、`routing_ip_network.cpp`、`config_validation.cpp`、`sniffer.cpp`、`tls_server_name.cpp`、`reality_short_id.cpp`、`reality_client_version.cpp`、`reality_key_share.cpp`、`quic_memory.cpp`、`vless/credentials.cpp`、`vless_ticket_service.cpp`、`vmess/account.cpp`、`vmess/types.hpp`、`vmess/aead/*`、`ss_outbound_uot.*`、`ss_outbound_credentials.*`、`anytls_outbound_settings.*`）；在启动期 `UserStore::CommitSnapshot` 后立即释放静态入站 `PreparedInbound::users`。

### 验证与性能/内存实证

全量 **1,251/1,251** 测试通过（325 项 unit、926 项 E2E）。在同一环境与编译选项下执行 A/B/A/B 交错重复基准对照：

- **64 活跃 VLESS 会话内存占用与统计采样（`cnode_runtime_sampling_benchmark`）**：
  - **`resources=0`**：进程峰值 RSS（`process_peak_rss_bytes`）由 `14,716,928 / 16,809,984 B` 稳定降至 **`14,635,008 / 14,639,104 B`（减少 80 KiB ~ 2.07 MiB）**，采样延迟由 `68.68 / 83.09 ns` 降至 **`68.29 / 68.37 ns`**（`p50 = 30.0 ns`，`p95 = 40.0 ns`），0 次堆分配。
  - **`resources=1`**：进程峰值 RSS 由 `15,163,392 / 17,252,352 B` 稳定降至 **`15,122,432 / 15,130,624 B`（减少 40 KiB ~ 2.02 MiB）**，活跃会话匿名内存由 `7,651,328 / 9,740,288 B` 降至 **`7,626,752 / 7,634,944 B`（减少 16 ~ 24 KiB）**。
- **VLESS/TLS 真实进程基准（`cnode_tls_throughput_benchmark`）**：
  - **`Download1` / `Download8`**：`Download1` 传输完成峰值 RSS 由 `14,143,488 / 14,168,064 B` 稳定降至 **`14,082,048 / 14,073,856 B`（减少 60 ~ 92 KiB）**；`Download8` 传输完成峰值 RSS 由 `14,581,760 / 14,561,280 B` 稳定降至 **`14,553,088 / 14,512,128 B`（减少 28 ~ 48 KiB）**，守护进程总 CPU 降至 **`0.1488 / 0.1415s`**。
  - **`Upload1` / `Upload8`**：`Upload1` 传输完成峰值 RSS 由 `14,135,296 / 14,139,392 B` 稳定降至 **`14,065,664 / 14,073,856 B`（减少 64 ~ 68 KiB）**，单流上传吞吐升至 **`812.92 MiB/s`（+3.0%）**；`Upload8` 传输完成峰值 RSS 由 `14,376,960 / 14,376,960 B` 稳定降至 **`14,315,520 / 14,303,232 B`（减少 60 ~ 72 KiB）**，守护进程总 CPU 由 `0.1575 / 0.1576s` 稳定降至 **`0.1468 / 0.1525s`（-3.2% ~ -6.8%）**，上传吞吐达 **`701.13 / 665.77 MiB/s`**。
- **Hysteria2 四 Worker 真实进程基准（`cnode_hysteria_throughput_benchmark`）**：
  - **256 连接下载**：建连耗时由 `0.524 / 0.513s` 稳定降至 **`0.508 / 0.506s`**；全部连接空闲回收后驻留匿名内存由 `11,554,816 / 11,509,760 B` 稳定降至 **`11,386,880 / 11,239,424 B`（减少 164 ~ 264 KiB）**，吞吐升至 **`64.79 MiB/s`**。
  - **16×64（1,024 流）上传与下载**：上传吞吐由 `56.53 / 55.83 MiB/s` 稳定升至 **`57.19 / 57.07 MiB/s`（+1.2% ~ +2.2%）**，守护进程 CPU 由 `3.792 / 4.035s` 降至 **`3.808 / 3.777s`**，进程高水位峰值（`vm_hwm_bytes`）由 `47,689,728 / 47,689,728 B` 稳定降至 **`46,972,928 / 46,968,832 B`（减少 700 ~ 704 KiB）**；下载吞吐由 `34.58 / 35.59 MiB/s` 升至 **`35.94 / 35.25 MiB/s`**，进程高水位峰值由 `359,636,992 / 357,539,840 B` 降至 **`358,789,120 / 357,216,256 B`（减少 316 ~ 828 KiB）**。
- **TCP 接收与发送基准（`cnode_tcp_receive_benchmark` / `cnode_tcp_send_benchmark`）**：
  - `tcp-send 1B`：单次 burst 墙钟耗时由 `6,298.4 / 6,306.5 ns` 稳定降至 **`6,259.3 / 6,266.1 ns`**，CPU 耗时由 `4,141.0 / 4,134.0 ns` 稳定降至 **`4,082.8 / 4,085.0 ns`（-1.2% ~ -1.4%）**；`65536B (16 pieces)` 第 2 轮墙钟耗时由 `47,243.4 ns` 降至 **`43,166.8 ns`（-8.6%）**。
  - `tcp-receive 8192B`：第 1 轮墙钟耗时由 `11,334.5 ns` 降至 **`11,120.3 ns`（-1.9%）**。

## 2026-11-09（第八轮）：`RequestLoadState` 去共享原子化、VMess/SS 入站零堆分配、`SslContext`/`HysteriaIngress` 去包装与 28 个碎片文件内聚

### 架构与流程精简内容

1. **`app::RequestLoadState` 下沉为纯 Worker 本地非原子状态 + 消除 Pimpl / 多余堆分配包装**：
   - `include/app/request_load_state.hpp`、`src/app/worker.cpp`、`src/app/bootstrap.cpp`：删除旧跨 Worker 迁移遗留的 `RequestLoadState::Acquire` 与 `RequestLoadState::Service`，将 `physical_connections_` 与 `active_dispatches_` 从跨核争用的 `std::atomic<uint32_t>` 改为纯单线程 `uint32_t`，由 `Worker::RuntimeState` 直接按值持有，`ComputePressureThreshold` 按单 Worker 均分阈值。
   - `include/app/session_capabilities.hpp`、`include/app/proxyman/inbound/handler.hpp`、`src/app/proxyman/inbound/handler.cpp`、`src/app/worker.cpp`：删除 `DatagramSessionEnvironment::receiver`、`Handler::SharedReceiverSettings()` 与 `Worker::ListenerSlot::prepared`，将 `Handler::receiver_` 从 `std::shared_ptr<const ReceiverSettings>` 改为值成员；在 `Worker::UnregisterListenerTask` 中重置 `datagram_environment`；在 `Worker::ListenerState` 中提取 `HasBindingConflict` 与 `OpenAndBindUdpSocket` 消除 ~75 行重复代码。
   - `include/common/sharded_user_stats.hpp`、`src/common/sharded_user_stats.cpp`、`src/transport/internet/hysteria/*`、`src/proxy/anytls/outbound/*`：内联 `UserOnlineTracker::Impl`（消除单成员 Pimpl 堆分配）并提取泛型 `AcquireDeviceCount<Map>`；将 `QuicListener` 直接合并入 `HysteriaIngress`（消除 `std::unique_ptr<QuicListener>` 纯转发包装）并删除 `Connection::retired_` / `Retired()` / `Authenticated()`；合并 `anytls::outbound::Handler::SessionPool` 与 `SessionPool::State`。
2. **VMess / Shadowsocks TCP 入站零堆分配化与协议热路径零拷贝**：
   - `src/proxy/vmess/encoding/server.hpp/.cpp`、`src/proxy/vmess/inbound/vmess_inbound.cpp`：公开具体类 `RequestBodyReader` 与 `ResponseBodyWriter`（仅在 `Command::UDP` 时拷贝 `udp_target_`），使 `DecodeRequestBody` 与 `EncodeResponseBodyWithHeader` 返回 `std::optional` 在协程栈上原位构造（消除每条 VMess 入站连接的 2 次 `std::make_unique` 堆分配），并将 `ParseHandshake` 的 `header_buf` 改为定长 `std::array`。
   - `src/proxy/shadowsocks/stream_crypto.hpp`、`server.hpp/.cpp`、`inbound/ss_inbound.cpp`：公开支持移动的 `ResponseBodyWriter` 并使 `detail::BodyReader` 支持移动，`ReadTCPSessionResult::body_reader` 与 `WriteTCPResponse` 改为按值返回並在 `ss_inbound.cpp` 栈上直接持有（消除每条 SS TCP 入站连接的 2 次 `std::make_unique` 堆分配）；删除 Legacy 分支冗余的 `request_salt` 拷贝与 8 处重复的 `KeyBytes` 手动擦除。
   - `src/proxy/vless/*`、`src/proxy/vmess/outbound/*`、`src/proxy/trojan/*`、`src/proxy/mux/inbound/mux_inbound.cpp`：将 1-RTT PFS 握手定长缓冲改为 `std::array`；`VMessOutboundEndpoint`、`VlessOutboundEndpoint`、`VlessMuxUdpEndpoint`、`trojan::UdpStreamEndpoint` 改为借用 `const TargetAddress&` 与 `ForwardedMetadataView`；合并 `vmess_outbound` / `vless_outbound` 中 `vnext` 与扁平配置的重复解析；删除 `MuxReply::payload_size` 与 `frame_buf_bytes`。
3. **`SslContext` 双重 `ex_data` 与非自签握手原子争用消除 + `inbound_field_rules` 跨层解耦 + 28 个碎片文件合并**：
   - `include/transport/internet/tls_stream.hpp`、`src/transport/internet/tls_stream.cpp`、`tls_client_context.cpp`、`reality_tls.cpp`：删除虚基类 `SslContext::ContextState`、`SslContext::SharedState` 与 `shared_state_`（消除 `CreateClient` 无意义的堆分配与 REALITY 双重 `SSL_CTX_set_ex_data`）；`TlsStream::Impl` 优先使用 `context.Native()` 裸指针，消除非自签 TLS/REALITY 握手跨 Worker 拷贝 `shared_ptr<SSL_CTX>` 的原子争用。
   - 新建公开契约头 `include/proxy/anytls_padding.hpp` 替代 `src/proxy/anytls/padding.hpp`，彻底消除 `src/infra/inbound_field_rules.cpp` 对 `../proxy/anytls/` 的跨层反向依赖。
   - 内联并删除 28 个碎片文件（`vless_ticket_service.hpp`、`vless_encryption_{crypto,record,xor,handshake}.{hpp,cpp}`、`autosign_context.{hpp,cpp}`、`xhttp_{packet_session_key,upload_stream_slot,packet_queue}.hpp`、`reality_server_name.hpp`、`http2_settings.hpp`、`http_path_match.hpp`、`grpc_hunk.cpp`、`src/common/error.cpp`、`src/common/awaitable_batch.cpp`、`src/app/stats.cpp`、`include/common/online_device.hpp`、`src/infra/runtime_failure.cpp`、`src/infra/config_loader.cpp`、`src/infra/config_semantics.{hpp,cpp}`、`src/infra/json_field.cpp`）。

### 验证与性能/内存实证

全量 **1,251/1,251** 测试通过（325 项 unit、926 项 E2E）。在同一环境与编译选项下执行 A/B/A/B 交错重复基准对照：

- **VLESS/TLS 真实进程基准（`cnode_tls_throughput_benchmark`）**：
  - **守护进程启动驻留内存（`server_started` RSS）**：4 项测试（`Download1`、`Download8`、`Upload1`、`Upload8`）的启动 RSS 均由 `13,148,160 ~ 13,156,352 B` 稳定降至 **`13,021,184 ~ 13,037,568 B`（稳定减少 112 ~ 132 KiB）**。
  - **上传吞吐与耗时**：`Upload8` 8 流上传吞吐由 `672.22 / 663.53 MiB/s` 升至 **`790.79 / 659.23 MiB/s`（峰值 +17.6%，128 MiB 传输耗时仅 `0.1619s`）**；`Upload1` 单流上传吞吐由 `779.04 / 781.27 MiB/s` 升至 **`773.54 / 791.36 MiB/s`**，整进程墙钟耗时由 `226 / 174 ms` 降至 **`176 / 124 ms`**。
  - **下载守护进程 CPU**：`Download1` 守护进程总 CPU 由 `0.0290 / 0.0291s` 稳定降至 **`0.0273 / 0.0284s`（最高 -5.8%）**；`Download8` 守护进程总 CPU 由 `0.1429 / 0.1414s` 降至 **`0.1415 / 0.1418s`**。
- **Hysteria2 四 Worker 真实进程基准（`cnode_hysteria_throughput_benchmark`）**：
  - **守护进程启动驻留内存（`startup` RSS）**：256 连接上传/下载与 16×64 下载的启动 RSS 均由 `14,368,768 ~ 14,405,632 B` 稳定降至 **`14,258,176 ~ 14,274,560 B`（稳定减少 104 ~ 136 KiB）**。
  - **256 连接上传与下载**：256 连接上传就绪 RSS（`all_sessions_and_tcp_targets_ready`）由 `38,678,528 / 38,735,872 B` 稳定降至 **`38,637,568 / 38,617,088 B`（减少 40 ~ 116 KiB）**，建连耗时由 `0.515 / 0.517s` 稳定降至 **`0.513 / 0.506s`**；256 连接下载建连耗时由 `0.497 / 0.496s` 进一步稳定降至 **`0.492 / 0.492s`**，下载吞吐达 **`64.84 / 65.61 MiB/s`**。
  - **16×64（1,024 流）上传与下载**：16×64 上传吞吐峰值由 `55.27 / 56.15 MiB/s` 升至 **`57.35 / 55.69 MiB/s`（峰值 +3.8%）**，守护进程总 CPU 最低降至 **`3.667s`**，建连耗时最低降至 **`0.130s`**；16×64 下载 1,024 流就绪 RSS 由 `47,886,336 / 47,677,440 B` 降至 **`46,927,872 / 47,693,824 B`（最高减少 936 KiB）**，空闲回收后驻留 RSS 最低降至 **`23,449,600 B`**。
- **64 活跃会话统计采样与 TCP 收发基准（`cnode_runtime_sampling_benchmark` / `cnode_tcp_receive_benchmark` / `cnode_tcp_send_benchmark`）**：
  - `cnode_runtime_sampling_benchmark`：`resources=0` 采样延迟保持 **`68.25 / 68.34 ns`**（`p50 = 30.0 ns`，`max = 41.0 ns`），`resources=1` 采样延迟由 `87.16 / 86.18 ns` 降至 **`86.03 / 86.02 ns`**，0 次堆分配。
  - `tcp-receive 65536B`：单次 burst 墙钟耗时由 `50,777.6 / 51,694.0 ns` 稳定降至 **`49,723.2 / 49,029.1 ns`（-2.1% ~ -5.2%）**，CPU 耗时由 `46,939.0 / 47,646.9 ns` 稳定降至 **`45,851.9 / 45,184.7 ns`（-2.3% ~ -5.2%）**。
  - `tcp-send 8192B (1 piece)`：单次 burst 墙钟耗时由 `10,394.9 / 10,306.9 ns` 稳定降至 **`10,212.2 / 10,221.7 ns`（-0.8% ~ -1.8%）**，CPU 耗时由 `8,138.3 / 8,063.8 ns` 稳定降至 **`7,996.5 / 7,996.9 ns`**。

## 2026-11-09（第九轮）：路由同步快路径、UDP 入站逐包零拷贝、出站 Handler 自注册去双实现、零拷贝预读前置与 47 个碎片文件内聚

### 架构与流程精简内容

1. **分发路由同步快路径与原生 UDP 逐包零原子争用**：
   - `src/app/dispatcher/default_dispatcher.cpp`：在 `DispatchPreparedLink` 中优先执行同步路由 `RouteSync`（仅在命中 `IPIfNonMatch` / `IPOnDemand` 需异步 DNS 解析时才回退 `RouteAsync`），消除普通请求分发热路径无条件挂起 `RouteAsync` 协程帧的分配与调度开销。
   - `include/proxy/inbound_datagram.hpp`、`src/app/worker/udp_ingress.cpp`、`src/proxy/shadowsocks/inbound/ss_inbound.cpp`、`src/proxy/inbound_admission.hpp`：移除 `InboundDatagramResult` 中 3 个死字段（`user_owner`、`tracker`、`limiter`）与 `ClientSession::Impl::RequestData::tracker_owner`；消除 `UdpIngress::ProcessDatagram` 中重复调用的 `buf::SetUdpTarget`；将 `AdmitNativeAssociation` 统一为 `if (tracker) tracker->Acquire(...)`，同步淘汰 4 个无调用的 UDP 虚函数，消除 SS UDP 入站每包跨核拷贝 `shared_ptr<const UserProfile>` 的原子引用计数争用。
   - `src/app/dns/dns.cpp`、`src/app/dns/inflight_resolves.hpp`、`src/app/router/router.cpp`、`src/geo/geodata.cpp`：当 `DNSWorker` 收到 `resolve_ip_literals=false` 的直连域名请求时直接原位移动构造返回（省去多余拷贝）；`InflightResolves::Run` 在单等待者常见路径下直接移动返回结果；`Router::Impl` 与 `GeoDatabase::LoadCategories` 改用原位构造避免临时字符串拷贝。
2. **出站 Handler 构造与自注册去双实现、传输层零拷贝预读前置与 `DialResult` 瘦身**：
   - `src/service/controller/controller.cpp`、`src/proxy/{freedom,blackhole,trojan,vless,vmess}/outbound/*`、`src/app/proxyman/outbound/factory.cpp`：将 `BuildPanelAutoOutbound` 改为直接通过 `proxyman::outbound::PrepareOutboundConfig(infra::OutboundSourceConfig{...})` 统一构建面板自动 Freedom 出站，彻底消除控制面私有重复的 Freedom 出站构建逻辑，并将 8 个仅 20~35 行的协议出站自注册 `.cpp` 内联入 `proxyman/outbound/factory.cpp`。
   - `include/transport/async_stream.hpp`、`src/transport/async_stream.cpp`、`include/transport/internet/{tcp_stream,tls_stream}.hpp`、`src/transport/internet/{tcp_stream,tls_stream,http1_handshake,xhttp_session,transport_stack,transport_dialer}.cpp`：移除 `DialResult` 中两个只写不读死字段（`native_error_code`、`attempted_remote_addr`）及每次拨号失败无条件执行的 `attempted_remote_addr` 堆字符串格式化；新增虚方法 `PrependReadMultiBuffer(buf::MultiBuffer&& mb)` 并将 4 处逆序逐块拷贝的 `PrependReadData` 升级为零拷贝缓冲移交；`TlsStream::DetachForHandoff` 复用 `CopyPrefixTo` 消除逐块复制循环。
   - `include/transport/internet/http_headers.hpp`、`src/sniff/{http_sniffer,tls_sniffer}.cpp`、`src/transport/internet/http1_handshake.cpp`：提取公共 `ResolveConfiguredHttpHost` 与 `SplitAndValidateHttpHeaderLine` 统一 5 处重复的 HTTP Host/Authority 与 Header 行解析。
3. **47 个单调用方碎片头文件与实现文件合并内聚（两轮累计精简 75 个碎片文件）**：
   - 合并并删除 `app`、`common`、`transport`、`proxy`、`infra`、`service/controller`、`api/v2board` 下共 47 个单调用方小碎片文件（含 `tcp_listener.cpp`、`dns/config.hpp`、`dns/stats.hpp`、`dns/cache.cpp`、`outbound/registration.hpp`、`rule_types.hpp`、`contiguous_buffer_view.hpp`、`dial_target.hpp`、`proxy_protocol_mode.hpp`、`reality_short_id.hpp`、`reality_client_version.hpp`、`hysteria_settings.hpp`、`quic_handoff.hpp`、8 个协议 outbound `.hpp`、`trojan/credentials.hpp`、`trojan/udp_framing.hpp`、`vless/{credentials,udp_framing,vless_buffered_reader,vless_encryption_io}.hpp`、`vmess/{account,udp_datagram}.hpp`、`shadowsocks/shadowsocks_crypto.hpp`、`infra/{json_field,outbound_source_config}.hpp`、`controller/{node_state,node_transaction,node_transition,online_snapshot}.hpp`、`v2board/{request_task,node_info_json,user_list_json,online_report}.{hpp,cpp}` 等）。

### 验证与性能/内存实证

全量 **1,251/1,251** 测试通过（325 项 unit、926 项 E2E）。在同一环境与编译选项下执行 A/B/A/B 交错重复基准对照：

- **64 活跃 VLESS 会话内存占用与统计采样（`cnode_runtime_sampling_benchmark`）**：
  - **`resources=0`**：进程峰值 RSS（`process_peak_rss_bytes`）由 `14,721,024 / 14,712,832 B` 稳定降至 **`14,434,304 / 14,438,400 B`（稳定减少 268 ~ 280 KiB / -1.9%）**；活跃会话匿名内存（`anonymous_rss_bytes` / `settled_anonymous_rss_bytes`）由 `7,413,760 / 7,401,472 B` 稳定降至 **`7,344,128 / 7,344,128 B`（稳定减少 56 ~ 68 KiB）**；采样延迟保持 **`68.30 / 68.30 ns`**（`p50 = 30.0 ns`，`max = 41.0 ns`），0 次堆分配。
  - **`resources=1`**：进程峰值 RSS 由 `15,142,912 / 15,134,720 B` 稳定降至 **`14,946,304 / 14,942,208 B`（稳定减少 188 ~ 192 KiB）**；活跃会话匿名内存由 `7,634,944 / 7,626,752 B` 稳定降至 **`7,589,888 / 7,585,792 B`（稳定减少 40 ~ 44 KiB）**；采样延迟保持 **`85.99 / 86.02 ns`**（`p50 = 50.0 ns`），0 次堆分配。
- **VLESS/TLS 真实进程基准（`cnode_tls_throughput_benchmark`）**：
  - **8 流下载（`Download8`）内存与吞吐**：传输完成活跃匿名内存（`smaps_rollup_anonymous_bytes`）由 `6,692,864 / 6,656,000 B` 稳定降至 **`6,627,328 / 6,610,944 B`（减少 44 ~ 64 KiB）**，峰值 RSS 由 `14,811,136 / 14,774,272 B` 稳定降至 **`14,745,600 / 14,729,216 B`（稳定减少 44 ~ 64 KiB）**；8 流下载吞吐由 `596.03 / 596.67 MiB/s` 稳定升至 **`603.48 / 603.41 MiB/s`（+1.2%）**。
  - **单流与 8 流上传（`Upload1` / `Upload8`）**：`Upload1` 单流上传吞吐升至 **`817.50 MiB/s`**；`Upload8` 传输完成活跃匿名内存由 `6,447,104 / 6,455,296 B` 稳定降至 **`6,426,624 / 6,422,528 B`（减少 20 ~ 32 KiB）**，峰值 RSS 减少 **20 ~ 32 KiB**，上传吞吐由 `544.61 / 674.07 MiB/s` 升至 **`658.98 / 675.35 MiB/s`（首轮 +21.0%）**。
- **Hysteria2 四 Worker 真实进程基准（`cnode_hysteria_throughput_benchmark`）**：
  - **256 连接上传与下载**：256 条 QUIC 连接上传建连耗时由 `0.510 / 0.514s` 稳定降至 **`0.500 / 0.500s`**，空闲回收高水位（`vm_hwm_bytes`）由 `38,641,664 / 38,248,448 B` 降至 **`38,252,544 / 38,248,448 B`（最高减少 380 KiB）**，吞吐达 **`68.94 / 69.38 MiB/s`**；256 连接下载守护进程总 CPU 由 `1.482 / 1.514s` 稳定降至 **`1.480 / 1.474s`（最高 -2.6%）**。
  - **16×64（1,024 流）上传与下载**：1,024 流上传吞吐由 `54.60 / 55.42 MiB/s` 升至 **`55.39 / 57.70 MiB/s`（峰值 +4.1%）**，守护进程总 CPU 由 `4.005 / 3.990s` 稳定降至 **`3.912 / 3.720s`（-2.3% ~ -6.8%）**，首轮负载峰值匿名内存由 `40,353,792 B` 降至 **`39,071,744 B`（减少 1.22 MiB）**，空闲回收高水位减少 **1.50 MiB**；1,024 流下载建连耗时由 `0.125 / 0.153s` 稳定降至 **`0.116 / 0.123s`**。
- **TCP 接收与发送基准（`cnode_tcp_receive_benchmark` / `cnode_tcp_send_benchmark`）**：
  - `tcp-receive 1B`：单次 burst 墙钟耗时由 `9,891.5 / 9,756.7 ns` 稳定降至 **`9,773.5 / 9,689.8 ns`（-0.7% ~ -1.2%）**，CPU 耗时由 `7,598.5 / 7,459.7 ns` 稳定降至 **`7,522.4 / 7,411.4 ns`**；`65536B` 墙钟耗时由 `48,768.1 / 49,059.4 ns` 稳定降至 **`48,560.3 / 48,281.4 ns`（最高 -1.6%）**。
  - `tcp-send 8192B (16 pieces)`：单次 burst 墙钟耗时由 `11,313.1 / 11,285.2 ns` 稳定降至 **`10,990.7 / 11,281.5 ns`（最高 -2.9%）**。

## 2026-11-09（第十轮）：Hysteria QUIC 首包同步直喂、`ConnectionLimiter` 跨线程零字符串分配、UDP 会话去 Pimpl、Shadowsocks 零死表与 36 个碎片文件内聚

### 架构与流程精简内容

1. **Hysteria QUIC 新连接首包同步直喂与 `QuicSniffer` 首包零分配快路径**：
   - `src/transport/internet/hysteria/hysteria_ingress.cpp`、`src/transport/internet/hysteria/hysteria_ingress.hpp`：将 `Connection::Initialize(header)` 与 `listener.Associate` 移入 `Connection::Create` 同步完成（初始化失败直接返回 `nullptr`，无需 `co_spawn`），并允许 `HysteriaIngress::ReceiveLoop` 对 Long Header 握手包（`(packet[0] & 0x80) != 0`）直接同步调用 `connection->Feed(*socket, socket->remote, packet, true)`，使 100% 的新建 QUIC 连接首包在同一事件循环迭代内同步处理并写出 ServerHello，彻底消除新连接首包必触发的 `ThreadLocalVector<uint8_t>` 整包拷贝、`core_->inbox` 队列块分配与 `net::post(Pump)`。
   - `src/sniff/sniffer.cpp`（合并自 `tls_sniffer.cpp`、`http_sniffer.cpp`、`quic_sniffer.cpp`）：为 `AesGcmDecrypt` 增加栈上 `std::array<uint8_t, 1536>` 快路径；当 `QuicSniffer::Sniff` 首帧已完整包含整个 ClientHello 时直接调用内部 `ParseClientHelloServerName`，跳过 `crypto_` / `coverage_` 的 PMR 分配与逐字节位图循环。
2. **`ConnectionLimiter` 跨线程零字符串分配、内联 `UdpIngress::ClientSession::Impl` / `HandlerRegistry::Impl` 与消除单实现纯虚接口 `RequestPolicy`**：
   - `include/app/rate_limiter.hpp`：公开 `ConnectionLimiterCore::IpBanKey` / `ComputeIpBanKey` 并新增接收预计算 `AuthCredentialKey` 与 `ip_hash` 的 `CheckIPBan`、`TryAcceptIP`、`OnAuthFailTracked` 重载；在 `ConnectionLimiter` 的 `ReservePhysical`、`Reserve`、`IsBanned`、`OnAuthFailTracked` 中于发起 `coordinator_->PostCall` 前在当前 Worker 线程预计算定长栈值 `ban_key` 与 `ip_hash`，彻底消除跨线程闭包中的 `std::string(tag)` 与 `std::string(ip)` 堆分配。
   - `src/app/worker/udp_ingress.hpp/.cpp`、`include/common/target_address.hpp`、`include/app/proxyman/inbound/handler_registry.hpp`、`src/app/proxyman/inbound/handler.cpp`、`include/app/proxyman/outbound/handler.hpp/.cpp`：将 `UdpIngress::ClientSession::Impl` 直接内联入 `ClientSession`（每条 UDP 关联减少 1 次堆分配与所有数据包读写路径上的二次解引用），复用 `ProcessDatagram` 已归一化的客户端地址，并消除 `TargetAddress::SameEndpoint` 与 `formatter` 中重复的 `NormalizeAddress`；内联 `HandlerRegistry::Impl`；将 `outbound::Handler::dialer_` 改为直接值成员；消除 `ApplyHttpRealIp` / `ApplyProxyProtocolResult` 中对 `ctx.inbound.source_ip` 的移动掏空；删除单实现纯虚接口 `features::policy::RequestPolicy`，使 `DefaultDispatcher` 直接调用 `rule::DetectRulePolicy::Blocked`。
3. **Shadowsocks 入站 UDP 回包上下文去死重放表、`ResponseBodyWriter` 零分配首包加密与 37 个碎片文件合并（净减 36 个文件）**：
   - `src/proxy/shadowsocks/ss_udp.hpp/.cpp`、`src/proxy/shadowsocks/inbound/ss_inbound.hpp/.cpp`、`src/proxy/shadowsocks/shadowsocks_protocol.cpp`：从 `Ss2022UdpSessionState` 拆出不含 `receive_replay_cache` 的发送状态 `Ss2022UdpTxState`，并在 `ShadowsocksUdpResponseContext` 中用 `std::variant<ClassicState, ss::Ss2022UdpTxState>` 替代双份密钥成员与 `std::optional<Ss2022UdpSessionState>`，彻底消除每条入站 SS2022 UDP 关联中从不使用的 `Ss2022UdpReplayCache`（`ThreadLocalUnorderedMap`）；删除 `FirstChunk` / `FirstChunkView`（消除首包跨块时的 `ByteVector` 堆分配），将 `ResponseBodyWriter` 握手期 `master_key` 与 `request_salt` 收纳进 `std::optional<PendingHandshake>` 并在首包加密后立即释放；`ParseCipherMethod` 改用 `EqualsAsciiCI` 消除临时 `std::string` 分配。
   - 合并并删除 37 个单调用方碎片文件（新建合并后的 `src/sniff/sniffer.cpp`，净减 36 个文件，近四轮累计清理 **148 个冗余碎片文件**），并清理 `src/proxy/vmess/aead`、`src/proxy/freedom/outbound`、`include/features/policy` 3 个空目录。

### 验证与性能/内存实证

全量 **1,251/1,251** 测试通过（325 项 unit、926 项 E2E）。在同一环境与编译选项下执行 A/B/A/B 交错重复基准对照：

- **VLESS/TLS 真实进程基准（`cnode_tls_throughput_benchmark`）**：
  - **守护进程启动驻留内存（`server_started` RSS）**：4 项测试（`Download1`、`Download8`、`Upload1`、`Upload8`）的启动 RSS 均由 `13,406,208 ~ 13,418,496 B` 稳定降至 **`13,148,160 ~ 13,156,352 B`（稳定减少 250 ~ 260 KiB）**。
  - **传输完成峰值与常驻内存（`measured_transfer_complete_connections_open` RSS）**：`Download1` 由 `14,356,480 / 14,364,672 B` 稳定降至 **`14,139,392 / 14,143,488 B`（稳定减少 212 ~ 216 KiB）**；`Download8` 由 `14,700,544 / 14,757,888 B` 稳定降至 **`14,569,472 / 14,532,608 B`（稳定减少 128 ~ 220 KiB）**；`Upload1` 由 `14,336,000 / 16,412,672 B` 稳定降至 **`14,131,200 / 14,127,104 B`（减少 200 KiB ~ 2.18 MiB）**；`Upload8` 由 `14,553,088 / 14,544,896 B` 稳定降至 **`14,360,576 / 14,352,384 B`（两轮一致稳定减少 188 KiB）**。
  - **吞吐与守护进程 CPU**：`Upload8` 8 流上传吞吐由 `639.85 / 532.82 MiB/s` 提升至 **`711.20 / 642.82 MiB/s`（+11.2% ~ +20.6%）**；`Download1` 单流下载吞吐由 `549.22 / 536.62 MiB/s` 稳定升至 **`560.10 / 550.64 MiB/s`（+2.0% ~ +2.6%）**，守护进程总 CPU 由 `0.0293 / 0.0300s` 稳定降至 **`0.0270 / 0.0294s`（最高 -7.8%）**；`Download8` 守护进程总 CPU 由 `0.1412 / 0.1410s` 稳定降至 **`0.1397 / 0.1394s`**。
- **Hysteria2 四 Worker 真实进程基准（`cnode_hysteria_throughput_benchmark`）**：
  - **守护进程启动驻留内存（`startup` RSS）**：4 项测试的启动 RSS 均由 `14,647,296 ~ 14,663,680 B` 稳定降至 **`14,381,056 ~ 14,401,536 B`（稳定减少 248 ~ 260 KiB）**。
  - **256 连接上传（`Upload 256`）**：256 连接就绪匿名内存由 `30,359,552 / 30,400,512 B` 稳定降至 **`30,126,080 / 30,195,712 B`（稳定减少 200 ~ 228 KiB）**，就绪总 RSS 由 `38,739,968 / 38,780,928 B` 稳定降至 **`38,305,792 / 38,375,424 B`（稳定减少 396 ~ 424 KiB）**；负载峰值 RSS（`during_load_max_sampled_vm_rss_bytes`）由 `39,309,312 / 39,448,576 B` 稳定降至 **`38,854,656 / 39,022,592 B`（稳定减少 416 ~ 444 KiB）**；256 连接建连耗时由 `0.5158 / 0.5117s` 稳定降至 **`0.5060 / 0.5037s`**。
  - **256 连接下载（`Download 256`）**：256 连接就绪 RSS 由 `40,714,240 / 38,711,296 B` 稳定降至 **`38,416,384 / 38,653,952 B`（减少 56 KiB ~ 2.19 MiB）**；负载峰值 RSS 由 `99,299,328 / 98,430,976 B` 稳定降至 **`96,804,864 / 97,726,464 B`（稳定减少 688 KiB ~ 2.38 MiB）**；空闲回收后常驻 RSS 由 `22,315,008 / 20,164,608 B` 稳定降至 **`20,115,456 / 19,845,120 B`（稳定减少 312 KiB ~ 2.10 MiB）**。
  - **16×64（1,024 流）上传与下载**：16×64 上传负载峰值 RSS 由 `47,833,088 / 48,889,856 B` 稳定降至 **`47,767,552 / 48,443,392 B`（减少 64 ~ 436 KiB）**；16×64 下载第 2 轮 1,024 流就绪 RSS 减少 **1.03 MiB**，守护进程总 CPU 由 `3.768s` 降至 **`3.555s`（-5.7%）**。
- **64 活跃会话统计采样与 TCP 收发基准（`cnode_runtime_sampling_benchmark` / `cnode_tcp_send_benchmark`）**：
  - `cnode_runtime_sampling_benchmark`：`resources=1` 进程峰值 RSS 由 `14,938,112 / 14,942,208 B` 稳定降至 **`14,917,632 / 14,901,248 B`（稳定减少 20 ~ 40 KiB）**；`resources=0` 采样延迟保持 **`68.38 / 68.30 ns`**（`p50 = 30.0 ns`，0 次堆分配）。
  - `tcp-send 8192B (8 pieces)`：单次 burst 墙钟耗时由 `10,680.4 / 10,725.7 ns` 稳定降至 **`10,658.9 / 10,648.3 ns`**；`65536B (16 pieces)` 第 2 轮墙钟耗时由 `44,652.5 ns` 降至 **`43,379.5 ns`（-2.9%）**。

## 2026-11-09（第十一轮）：HTTP/1.1 预读零拷贝移交、HPACK 单遍流式归约、`UdpIngress::Impl` 内联与 32 个碎片文件合并

### 架构与流程精简内容

1. **HTTP/1.1 握手 `TakeReadAheadMultiBuffer()` 零拷贝回填与 HTTP/2 HPACK 单遍流式解码**：
   - `src/transport/internet/http1_handshake.hpp/.cpp`、`include/transport/internet/ws_stream.hpp`、`src/transport/internet/ws_stream.cpp`、`src/transport/internet/xhttp_session.cpp`：为 `Http1MessageHead` 新增消费型 `TakeReadAheadMultiBuffer()`，在常规单块 `storage` 情况下直接调整游标并零拷贝移交原 8 KiB `BufferGuard` 至 `buf::MultiBuffer`；为 `Http1BodyStream` 与 `BaseWsStream` 新增 `SetPendingMultiBuffer(buf::MultiBuffer&&)`，在 `ReadClientResponse`、`DoHttp1ServerHandshake`、`DoHttpUpgradeServerHandshake`、`DoHttpUpgradeClientHandshake`、`DoWsServerHandshake` 中彻底消除预读应用层首包回填时的二次 `Buffer::New()` 分配与 `memcpy`。
   - `src/transport/internet/http2_session.cpp`：将 `HpackDecoder::Decode` 改为接收回调的单遍流式归约，静态表命中、动态表命中及带索引名的字面量头字段直接以 `std::string_view` 透传给回调，仅在增量索引（`0x40`）时移动入 `dynamic_table_`，彻底消除每次 HTTP/2 / gRPC / XHTTP-over-H2 请求和响应解码時の `HeaderFields` 数组分配与静态表字符串拷贝。
2. **内联 `UdpIngress::Impl`、修复 `unsafe::ptr_cast` 对齐断言并清理死编译开关 `CNODE_MEMORY_STATS`**：
   - `src/app/worker/udp_ingress.hpp/.cpp`：将 `UdpIngress::Impl` 的成员直接内联为 `UdpIngress` 的私有成员，消除每 Worker 的 `std::unique_ptr<Impl>` 堆分配与所有 UDP 入站方法上的 `impl_->` 间接寻址。
   - `include/common/unsafe.hpp`、`CMakeLists.txt`：移除从不生效的遗留宏 `#ifdef ACPP_DEBUG` 包装，改用 `<cassert>` 的 `assert(...)` 使对齐检查在 Debug 与单元测试（`-UNDEBUG`）下真实生效；移除无任何消费者的 `CNODE_MEMORY_STATS` CMake 选项与宏定义。
3. **32 个单调用方碎片头文件与实现文件合并内聚（五轮累计清理 180 个冗余碎片文件）**：
   - 合并并删除 `common`、`app`、`transport`、`proxy`、`service/controller` 下共 32 个单调用方碎片文件（含 `memory_stats.hpp`、`multi_buffer_batch.hpp`、`auth_failure_limit.hpp`、`common/network.hpp`、`user_profile.hpp`、`relay_types.hpp`、`token_bucket.hpp`、`session_capabilities.hpp`、`request_load_state.hpp`、`worker_runtime_config.hpp`、`runtime_publication.{hpp,cpp}`、`udp_{client_session_key,resource_budget,handoff_directory,association_reclaimer}.{hpp,cpp}`、`link_error.hpp`、`quic_stream.{hpp,cpp}`、`panel_inbound.{hpp,cpp}`、`anytls/padding.cpp`、`trojan/udp_framing.{hpp,cpp}`、`vless/udp_framing.{hpp,cpp}`、`vmess/vmess_request.hpp`、`vmess/encoding/{client,server}.{hpp,cpp}`）。

### 验证与性能/内存实证

全量 **1,251/1,251** 测试通过（325 项 unit、926 项 E2E）。在同一环境与编译选项下执行 A/B/A/B 交错重复基准对照：

- **VLESS/TLS 真实进程基准（`cnode_tls_throughput_benchmark`）**：
  - **守护进程启动匿名内存（`server_started` `smaps_rollup_anonymous_bytes`）**：4 项测试由 `5,951,488 ~ 5,963,776 B` 稳定降至 **`5,943,296 ~ 5,951,488 B`（稳定减少 8 ~ 20 KiB）**。
  - **单流与 8 流上传（`Upload1` / `Upload8`）**：`Upload1` 第 2 轮单流上传吞吐由 `821.53 MiB/s` 升至 **`881.62 MiB/s`（+7.3%，16 MiB 传输仅耗时 `18.15 ms`）**，活跃匿名内存减少 **4 KiB**；`Upload8` 8 流上传活跃匿名内存由 `6,459,392 / 6,451,200 B` 两轮一致稳定降至 **`6,426,624 / 6,410,240 B`（稳定减少 32 ~ 40 KiB）**，第 2 轮吞吐升至 **`600.80 MiB/s`（+1.2%）**。
  - **8 流下载（`Download8`）**：首轮 8 流下载吞吐由 `587.94 MiB/s` 升至 **`613.70 MiB/s`（+4.4%）**，守护进程总 CPU 由 `0.1410s` 降至 **`0.1390s`**。
- **Hysteria2 四 Worker 真实进程基准（`cnode_hysteria_throughput_benchmark`）**：
  - **16×64（1,024 流）上传（`Upload 16×64`）**：1,024 流就绪匿名内存由 `39,702,528 / 39,706,624 B` 两轮一致稳定降至 **`39,149,568 / 39,546,880 B`（稳定减少 156 ~ 540 KiB）**，就绪总 RSS 减少 **152 ~ 536 KiB**；负载峰值 RSS（`during_load_max_sampled_vm_rss_bytes`）由 `48,308,224 / 48,119,808 B` 两轮一致稳定降至 **`47,898,624 / 47,992,832 B`（稳定减少 124 ~ 400 KiB）**；1,024 流上传吞吐由 `55.51 / 55.42 MiB/s` 两轮一致升至 **`56.54 / 56.57 MiB/s`（+1.9% ~ +2.1%）**，守护进程总 CPU 由 `3.918 / 3.804s` 两轮一致降至 **`3.783 / 3.782s`（最高 -3.5%）**。
  - **16×64（1,024 流）下载（`Download 16×64`）**：1,024 流就绪匿名内存由 `39,387,136 / 39,444,480 B` 两轮一致稳定降至 **`38,756,352 / 39,079,936 B`（稳定减少 356 ~ 616 KiB）**，就绪总 RSS 减少 **352 ~ 612 KiB**；第 2 轮下载吞吐由 `35.07 MiB/s` 升至 **`35.94 MiB/s`（+2.5%）**，守护进程总 CPU 由 `3.666s` 降至 **`3.574s`（-2.5%）**。
  - **256 连接上传与下载**：256 连接上传就绪匿名内存两轮一致稳定减少 **28 ~ 76 KiB**；256 连接下载首轮负载峰值 RSS 减少 **608 KiB**，守护进程总 CPU 由 `1.466 / 1.484s` 两轮一致稳定降至 **`1.455 / 1.451s`（最高 -2.2%）**。
- **64 活跃会话统计采样与 TCP 发送基准（`cnode_runtime_sampling_benchmark` / `cnode_tcp_send_benchmark`）**：
  - `cnode_runtime_sampling_benchmark`：`resources=0` 采样延迟由 `68.45 / 69.59 ns` 两轮一致稳定降至 **`68.30 / 68.34 ns`**（`p50 = 30.0 ns`，首轮 `max = 40.0 ns`）；`resources=1` 采样延迟由 `107.90 / 86.07 ns` 稳定降至 **`86.10 / 85.98 ns`**，第 2 轮活跃匿名内存减少 **8 KiB**，0 次堆分配。
  - `tcp-send 8192B (8 pieces)`：单次 burst 墙钟耗时由 `10,675.1 / 10,601.2 ns` 两轮一致稳定降至 **`10,556.3 / 10,583.9 ns`（最高 -1.1%）**；`65536B (16 pieces)` 第 2 轮墙钟耗时由 `44,311.5 ns` 降至 **`43,756.1 ns`（-1.3%）**。

## 2026-11-09（第十二轮）：`WorkerMailbox::PostCall` 零协程帧直通释放、XHTTP 移交零整头回塞、`Router::Impl` 内联与 22 个碎片文件合并

### 架构与流程精简内容

1. **`WorkerMailbox::PostCall` 零目标协程帧分配与 `ReleaseOnOwner()` 同线程直通释放**：
   - `include/app/worker_mailbox.hpp`：提取 `WorkerMailbox::ReleaseOnOwner() noexcept` 与 `Slot::ReleaseOnOwner() noexcept`；在 `RunHeld` 协程结束时通过栈上 `OwnerGuard` 直接调用 `slot.ReleaseOnOwner()`（消除同线程完成时的二次 `net::dispatch`）；将 `PostCall(Fn fn)` 从 `net::co_spawn(io_context_.get_executor(), CallHeld(...), net::use_awaitable)` 改为 `net::async_initiate` + `net::post(io_context_, ...)`，在目标线程同步执行 `fn` 后立即 `slot.ReleaseOnOwner()` 并恢复调用方，彻底删除 `CallHeld` 并消除每次跨线程同步调用（含每条新连接 `ConnectionLimiter` 准入）在目标线程额外分配一个协程帧的开销。
2. **XHTTP Split-HTTP 跨 Worker 移交消除整头回塞与二次解析 + `Http1BodyStream` Chunked 零拷贝快路径**：
   - `src/transport/internet/xhttp_session.cpp`：当 `DoXHttp1ServerHandshake` 识别出 `owner_reactor != &io_context` 时，调用 `DetachXHttpStream(*stream, head->ReadAhead())` 仅移交 `\r\n\r\n` 之后的预读 body 字节（不再将整个 HTTP/1 请求头拷入 `std::vector<uint8_t>` 塞回字节流），将已解析出的首请求元数据传入 `owner_reactor` 并按 `const HttpConfig&` / `const XHttpConfig&` 引用借用配置（消除两份配置聚合与 `std::map` 的深拷贝），在原 Worker 恢复流后直接调用 `ExecuteXHttp1UploadRequest` 消费请求体（消除原 Worker 上的二次 `ReadHttp1MessageHead` 与二次 HTTP 头解析），同时删除 `UploadTransportStreamHandler` 类及其 `AllocateShared` 堆分配；在 `ResolveXHttpSessionOwner` 与 `XHttpSessionDirectory::Acquire` 中改用 `std::string_view` 透明查找，消除已存在会话跨请求查找时的 2 次 `std::string` 堆分配。
   - `src/transport/internet/http1_handshake.cpp`：在 `Http1BodyStream::ReadMultiBuffer()` 的 `read_chunked_` 分支中增加 `pending_.byte_size() <= chunk_remaining_` 零拷贝快路径，直接 `co_return std::move(pending_);`。
3. **内联 `app::router::Router::Impl`、消除 `RuntimeState` 无共享 `shared_ptr` 并合并 22 个碎片文件（六轮累计清理 202 个冗余碎片文件）**：
   - `include/app/router/router.hpp`、`src/app/router/router.cpp`、`src/app/worker.cpp`：将 `detail::CompoundRoutingRule` 移入 `router.hpp`，让 `Router` 直接持有 `compound_rules_` 与 `domain_strategy_` 值成员，彻底删除 `Router::Impl` Pimpl 堆分配与每次路由匹配的指针解引用；将 `Worker::RuntimeState` 中的 `router` 与 `detect_rule_policy` 从 `std::shared_ptr` 收口为 `std::unique_ptr`。
   - 合并并删除 `app`、`common`、`api/v2board`、`transport`、`proxy`、`service/controller` 下共 22 个单调用方碎片文件（含 `inbound/handler_registry.hpp`、`inbound/factory.cpp`、`outbound/prepared_config.hpp`、`outbound/factory.cpp`、`dns/{cache_internal,datagram_exchange,inflight_resolves}.hpp`、`common/{monitor_loop,process_resources}.hpp`、`v2board/panel_json_compat.hpp`、`transport/internet/{tls_config,tls_server_name,grpc_hunk,autosign_cert}.hpp`、`controller/traffic_journal.{hpp,cpp}`、`proxy/outbound_server.hpp`、`shadowsocks/stream_crypto.hpp`、`vless/vless_vision.{hpp,cpp}`、`vmess/vmess_cipher.{hpp,cpp}`）。

### 验证与性能/内存实证

全量 **1,251/1,251** 测试通过（325 项 unit、926 项 E2E，E2E 累计耗时进一步降至 `786.51 sec*proc`）。在同一环境与编译选项下执行 A/B/A/B 交错重复基准对照：

- **64 活跃 VLESS 会话内存占用与统计采样（`cnode_runtime_sampling_benchmark`）**：
  - **`resources=0`**：进程峰值 RSS（`process_peak_rss_bytes` / `idle_rss_bytes` / `warm_rss_bytes`）由 `14,614,528 / 14,618,624 B` **两轮一致稳定降至 `14,422,016 / 14,422,016 B`（稳定减少 188 ~ 192 KiB / -1.3%）**；第 2 轮采样延迟保持 **`68.34 ns`**（`p50 = 30.0 ns`，0 次堆分配）。
  - **`resources=1`**：进程峰值 RSS 由 `15,060,992 / 15,060,992 B` **两轮一致稳定降至 `14,819,328 / 14,811,136 B`（稳定减少 236 ~ 244 KiB / -1.6%）**；采样延迟由 `86.11 / 87.36 ns` **两轮一致稳定降至 `86.02 / 86.02 ns`**（`p50 = 50.0 ns`，`p95 = 60.0 ns`，0 次堆分配）。
- **VLESS/TLS 真实进程基准（`cnode_tls_throughput_benchmark`）**：
  - **守护进程启动驻留内存（`server_started` RSS）**：常规启动 RSS 由 `13,271,040 ~ 13,283,328 B` 稳定降至 **`13,066,240 ~ 13,082,624 B`（稳定减少 196 ~ 212 KiB）**，启动匿名内存最低降至 **`5,931,008 B`（`5.66 MiB`）**。
  - **8 流上传与下载（`Upload8` / `Download8`）**：`Upload8` 8 流上传吞吐由 `540.23 / 640.10 MiB/s` **两轮一致大幅提升至 `629.93 / 762.60 MiB/s`（+16.6% ~ +19.1%，第 2 轮 128 MiB 传输仅耗时 `0.1678s`）**，第 2 轮活跃匿名内存降至 **`6,406,144 B`**；`Download8` 8 流下载吞吐由 `610.89 / 625.66 MiB/s` **两轮一致提升至 `620.00 / 638.32 MiB/s`（+1.5% ~ +2.0%）**。
  - **单流下载与上传（`Download1` / `Upload1`）**：首轮 `Download1` 吞吐由 `438.15 MiB/s` 升至 **`548.11 MiB/s`（+25.1%）**、守护进程 CPU -16.6%；首轮 `Upload1` 吞吐由 `639.17 MiB/s` 升至 **`802.37 MiB/s`（+25.5%）**、守护进程 CPU -5.9%。
- **Hysteria2 四 Worker 真实进程基准（`cnode_hysteria_throughput_benchmark`）**：
  - **守护进程启动驻留内存（`startup` RSS）**：4 项测试两轮共 8 次运行的启动 RSS 均由 `14,438,400 ~ 14,462,976 B` **100% 稳定降至 `14,385,152 ~ 14,397,440 B`（稳定减少 52 ~ 68 KiB）**。
  - **256 连接上传与下载**：256 连接上传首轮就绪 RSS 减少 **180 KiB**、负载峰值 RSS 减少 **200 KiB**；256 连接下载守护进程总 CPU 由 `1.462 / 1.459s` **两轮一致稳定降至 `1.454 / 1.451s`**，空闲回收后常驻 RSS 由 `19,976,192 / 19,914,752 B` **两轮一致稳定降至 `19,836,928 / 19,877,888 B`（减少 36 ~ 136 KiB）**。
  - **16×64（1,024 流）上传与下载**：16×64 上传吞吐由 `55.44 / 55.75 MiB/s` **两轮一致升至 `55.76 / 56.89 MiB/s`（第 2 轮 +2.0%）**，建连耗时由 `0.145 / 0.144s` **两轮一致降至 `0.135 / 0.140s`**，第 2 轮守护进程总 CPU 降至 **`3.752s`（-2.0%）**，首轮空闲回收高水位减少 **776 KiB**、回收常驻 RSS 减少 **540 KiB**；16×64 下载首轮建连耗时由 `0.139s` 降至 **`0.126s`（-9.1%）**，第 2 轮 1,024 流就绪 RSS 减少 **276 KiB**。

## 2026-11-09（第十三轮）：Hysteria QUIC $O(1)$ 惰性超时重武装、UDP 会话活跃时间与回包零二次查表、HTTP/2 双窗口更新合并与 21 个碎片文件内聚

### 架构与流程精简内容

1. **Hysteria QUIC $O(1)$ 惰性超时重武装与 `Connection::Core::inbox` 死代码清除**（`src/transport/internet/hysteria/hysteria_ingress.{hpp,cpp}`）：
   - 在 `HysteriaIngress` 中引入 `ngtcp2_tstamp armed_expiry`，将 `Connection::PublishExpiry()` 从每包无条件调用 `ArmExpiry()`（遍历全量活跃 `sessions` 并调用 `expiry.expires_at()` 取消/唤醒 `ExpiryLoop` 协程）改为 $O(1)$ 比较 `if (expiry_ < listener_->armed_expiry) listener_->ArmExpiryAt(expiry_);`，仅当新截止期严格早于已武装截止期时才重置定时器，其余正向推进的 PTO/idle 截止期在 `ExpiryLoop` 到期唤醒时统一归约；当 `sessions` 清空时立即取消 `expiry` 退出循环。
   - 删除在单线程 Pin-to-Origin 架构下恒不可达的 `Connection::Core::PendingInputPacket`、`inbox`、`inbox_bytes`、`pump_scheduled`、`HysteriaIngress::Enqueue` 与 `HysteriaIngress::Pump`（每条 QUIC 连接 `Core` 减少 48 B）。
2. **原生 UDP 入站 $O(1)$ `last_active` 更新与回包直传 `UdpIngress&` + `SocketPtr`**（`src/app/worker/udp_ingress.{hpp,cpp}`、`src/app/worker.cpp`）：
   - 将 `last_active` 移入 `UdpAssociationHook`，使 `UdpIngress::ProcessDatagram` 在命中已有 SS2022 UDP 会话时直接通过 `session->association_hook_->last_active = now` 原地更新活跃时间戳，消除每包 2 次哈希表查找（`client_sessions_.find(hook->socket_key)` + `outer->second.find(*hook->client_key)`）。
   - `UdpIngress::ReplyRoute` 持有 `UdpIngress* owner` 并在 `Send()` 中将 `*owner` 与 `SocketPtr` 直接传给 `Worker::ListenerState::EnqueueUdpReply`，消除每次 UDP 回包时的 `FindUdpIngress(socket_key)` 字符串切分 + 哈希查找与 `ingress.FindSocket(socket_key)` 二次哈希查找。
3. **`OutboundConfiguration` 零快照克隆、HTTP/2 客户端双 `WINDOW_UPDATE` 单次写出与 VMess 握手头栈缓冲**：
   - `include/app/proxyman/outbound/handler.hpp`、`src/app/proxyman/outbound/handler.cpp`：`OutboundConfiguration` 直接持有 `Snapshot entries_`（`std::vector<Entry>`）与 `Entries()`，消除构造、`Replace`、`Remove` 及 `HandlerLookup::Sync` 时的 `std::make_shared<Snapshot>` 堆分配与整表复制。
   - `src/transport/internet/http2_session.cpp`：`Http2ClientStream::TakeReceivedData()` 在 `!input_done_` 时将连接级（stream 0）与流级（`stream_id_`）两个 13 字节 `WINDOW_UPDATE` 帧编码进同一个 26 字节栈数组单次 `WriteBuffers` 写出，减半流控更新产生的 TLS record 与写调用次数。
   - `src/proxy/vmess/encoding/body.cpp`：`OpenRequestHeader` 用 327 字节栈定长数组 `std::array<uint8_t, kRequestHeaderMax> plain{}` 替代 `memory::ByteVector plain(header_len)`，消除每次 VMess 入站握手的临时堆分配。
4. **合并并删除 21 个单调用方与同职责碎片文件（七轮累计清理 223 个冗余碎片文件）**：
   - 合并并删除 `outbound/factory.hpp`、`inbound/{prepared_config,receiver_settings,factory}.hpp`、`worker/tcp_listener.hpp`、`common/ip_address.hpp`、`infra/{runtime_failure,panel_config,inbound_field_rules}.hpp`、`core/naming.hpp`、`features/routing/dispatch_policy.hpp`、`hysteria_protocol.{hpp,cpp}`、`reality_tls.cpp`、`proxy/inbound_datagram.hpp`、`proxy/udp_target.hpp`、`vmess/validator.{hpp,cpp}`、`anytls/inbound/anytls_inbound.hpp`、`anytls/outbound/anytls_outbound.hpp`、`mux/inbound/mux_inbound.hpp`。

### 验证与性能/内存实证

全量 **1,251/1,251** 测试通过（325 项 unit、926 项 E2E，零编译告警）。在同一环境与编译选项下执行 A/B/A/B 交错重复基准对照：

- **Hysteria2 四 Worker 真实进程基准（`cnode_hysteria_throughput_benchmark`）**：
  - **256 连接上传（`Upload 256`）**：守护进程总 CPU 由 `1.342s`（system `0.577s`）/ `1.365s`（system `0.589s`）**两轮一致显著降至 `1.277s`（system `0.531s`）/ `1.275s`（system `0.546s`）（总 CPU 降低 -4.8% ~ -6.6%，内核态 CPU 降低 -7.2% ~ -8.1%）**；吞吐由 `65.90 / 69.16 MiB/s` **两轮一致提升至 `69.45 / 69.28 MiB/s`（首轮 +5.4%）**；256 连接建连耗时由 `0.523 / 0.520s` **两轮一致缩短至 `0.502 / 0.516s`（最高 -4.0%）**；空闲回收后匿名内存由 `13,799,424 / 11,747,328 B` **两轮一致稳定降至 `11,202,560 / 11,231,232 B`（减少 516 KiB ~ 2.48 MiB）**，回收后常驻 RSS 由 `22,048,768 / 19,996,672 B` **两轮一致稳定降至 `19,714,048 / 19,742,720 B`（减少 254 KiB ~ 2.23 MiB）**，首轮负载峰值 RSS 减少 **1.79 MiB**。
  - **256 连接下载（`Download 256`）**：守护进程总 CPU 由 `1.459 / 1.451s` **两轮一致稳定降至 `1.427 / 1.420s`（-2.1% ~ -2.2%，第 2 轮内核态 CPU 降低 -11.3%）**；第 2 轮负载峰值匿名内存由 `90,157,056 B` 降至 **`89,346,048 B`（减少 792 KiB，RSS 减少 536 KiB，峰值 HWM 减少 776 KiB）**。
  - **16×64（1,024 流）下载与上传**：16×64 下载吞吐由 `34.90 / 35.05 MiB/s` **两轮一致稳定升至 `35.59 / 35.78 MiB/s`（+2.0% ~ +2.1%，传输墙钟耗时缩短 143 ~ 149 ms）**，第 2 轮守护进程总 CPU 由 `3.770s` 降至 **`3.552s`（-5.8%，内核态 CPU -6.2%）**、负载峰值匿名内存减少 **488 KiB**（RSS 减少 **232 ~ 276 KiB**）；16×64 上传建连耗时由 `0.144 / 0.146s` **两轮一致缩短至 `0.141 / 0.134s`（最高 -8.1%）**，第 2 轮回收高水位减少 **384 KiB**。
- **TCP 发送、统计采样与 VLESS/TLS 基准**：
  - **`cnode_tcp_send_benchmark`**：`8192B (1 piece)` 单次 burst 耗时由 `10,337.2 / 10,202.1 ns` **两轮一致降至 `10,155.4 / 10,190.8 ns`（最高 -1.8%）**；`8192B (8 pieces)` 由 `10,839.5 / 10,669.8 ns` **两轮一致降至 `10,657.9 / 10,664.0 ns`（最高 -1.7%）**；`8192B (16 pieces)` 由 `11,373.3 / 11,279.8 ns` **两轮一致降至 `11,115.2 / 11,056.7 ns`（-2.0% ~ -2.3%）**；`65536B (16 pieces)` 首轮耗时由 `44,115.7 ns` 降至 **`43,343.0 ns`（-1.8%）**。
  - **`cnode_runtime_sampling_benchmark`**：64 活跃会话 `resources=1` 采样延迟由 `86.03 / 144.65 ns` **两轮一致稳定降至 `85.95 / 86.10 ns`**（`p50 = 50.0 ns`，`p95 = 60.0 ns`，0 次堆分配）；`resources=0` 首轮 `max_ns` 降至 `41.0 ns`、第 2 轮 `p95` 降至 `40.0 ns`。
  - **`cnode_tls_throughput_benchmark`**：`server_started` 启动匿名内存稳定保持 `5,931,008 ~ 5,939,200 B`（`5.66 MiB`）；首轮 `Download8` 8 流下载吞吐由 `602.38 MiB/s` 升至 **`616.41 MiB/s`（+2.3%）**，第 2 轮 `Upload1` 单流上传吞吐由 `643.01 MiB/s` 升至 **`791.69 MiB/s`（+23.1%）**。

## 2026-11-10：会话驻留帧瘦身、空转协程与死状态清除（基线 `1be6301`）

### 架构与流程精简内容

1. **主链路：会话期常驻协程帧瘦身与空转协程清除**：
   - `include/common/initial_payload.hpp`：生产代码只以 `MultiBuffer` 构造首包、判空并一次性移交；删除 256 B 内联缓冲及仅测试调用的 `assign/append/span/PrefixSpan/CopyPrefixTo/size/IsContiguous`。`Dispatch` 与 `DispatchPreparedLink` 两个会话期常驻帧不再各自内嵌这块缓冲，也不再在每次构造/移动时清零并复制 256 B。
   - `src/common/awaitable_task_group.hpp`：同执行器路径由非协程 `Launch` 直接返回 `async_initiate` 的 awaitable，删除每个请求/会话任务组的 `RunOnExecutor` 包装帧；跨执行器入口语义不变。
   - `src/app/dispatcher/default_dispatcher.cpp`：`IPIfNonMatch` 下域名先同步选路，规则命中即完成，不再为其构造 `RouteAsync` 帧；`RouteAsync` 只在确需 DNS 时进入，删除两段不可达的前置分支与重复的 `DomainStrategy()` 虚调用；嗅探补读把 `cache_more` 并入 `read_more`（每次补读少一帧）。
   - `include/app/relay.hpp`：限速等待仅在令牌桶给出正延迟时才构造 `WaitFor` 协程（限速用户每包每方向少一帧）；删除只转发 `direction && direction` 的 `transfer` 帧（每条 relay 少一个常驻帧）。
   - `include/app/rate_limiter.hpp`、`src/app/proxyman/inbound/handler.cpp`、`src/proxy/inbound_admission.hpp`、`hysteria_ingress.cpp`：新增 `ConnectionLimiter::TracksAdmission()`；未配置连接配额与封禁（默认配置）时 7 处准入调用不再 `co_await` 一个立即返回的空协程（每 TCP 连接 2 帧、每逻辑流/子流 1 帧、每原生 UDP 关联 2 帧、每 QUIC 连接 1 帧，并省去逻辑流一次 `shared_ptr<Family>` 引用计数往返）。`CheckInboundIpBanned` 拆为同步的 `BeginInboundAuthentication`（清身份并判定是否需要查询）与仅在需要时进入的协程，5 个协议入口同步迁移；单调用方 `CheckInboundCredential` 并入 `VerifyInboundCredential`。
   - 删除只写不读的 `InboundTransportMetadata::real_ip_header`（每条 TCP 连接、每次 HTTP/1 握手与每个 h2 请求各一次 PMR 字符串赋值）及 `RealIpHeader()`。
2. **公共内存与统计**：
   - `include/common/buf/multi_buffer.hpp`：`ContiguousWriteBuffer` 超 8 KiB 的路径改为向构造时绑定的资源借未初始化块（原 `ByteVector::resize` 对每条 VLESS Encryption 满记录清零 8–16 KiB），与池化 `Buffer` 路径的语义一致；`Buffer::New` 删除重复的游标写入。
   - `include/common/allocator.hpp`：`Deallocate` 与 large-bin 扫描中的 `% alignment` 改为位掩码（对齐已校验为 2 的幂，每次 PMR 释放少一次 64 位除法）；删除无调用方的 `worker_memory::allocator()`。
   - `include/app/stats.hpp`：`StatsShard` 扁平化为单缓存行（128 → 64 B），删除无调用方的 `HotStatsShard`/`ColdStatsShard` 分层与 `AddBytesIn/Out` 转发。
3. **传输层**：
   - `tcp_stream.{hpp,cpp}`：`WriteMultiBuffer` 首次非阻塞发送遇 EAGAIN 后经 `WriteBuffersFrom(..., blocked)` 直接等待可写，不再紧接着重复一次 `send` 并重建 iovec；`Connect`/`ConnectWithBind`/`ConnectSocket` 合并为单一 `Connect(io, endpoint, bind_local, timeout)`。
   - `transport_dialer.cpp`：`DialSingleCandidate` 改为非协程转发；裸 TCP、无安全层的拨号成功后直接返回，不再为不会挂起的 `BuildOutboundTransport` 武装再解除握手期限；XHTTP 下载目标只在配置了 `downloadSettings` 时进入 `AttachXHttpDownloadTarget`；`AcquireUploadGate` 内联到三个调用点。
   - `ws_stream.{hpp,cpp}`、`http1_handshake.{hpp,cpp}`：`FillHeader` 内联，`AcquireWrite` 仅在写门争用时进入协程；chunked 读仅在块耗尽时调用 `EnsureChunkPayload`；删除生产无调用方的 `MakeHttp1BodyStream` span 重载与两处 `SetPendingData`。
   - `http2_session.cpp`、`xhttp_session.{hpp,cpp}`、`http_headers.hpp`：服务端 `ReceiveData` 改为同步返回 `DataFault`（每个 DATA 帧少一帧和一次 `H2Frame` 移动，各故障分支的记账与上报顺序不变）；`EnsureReadablePayload` 改为非协程分派，已有可读数据时同步判定；单个 `WINDOW_UPDATE` 以 13 字节单缓冲写出；`RunHttp2ServerSession` 不再保留一个连接期常驻转发帧；删除恒等冗余的 `H2Frame::length`、`QueuedPacket::bytes` 与三处恒真条件；`ResolveConfiguredHttpHost` 只在未显式配置 Host 时扫描 header；`Upload::Read` 内联 `ReadToMultiBufferTail`。
   - `hysteria_ingress.{hpp,cpp}`：`Connection::WriteStream` 改为同步的 `QueueStreamOutput`，`QuicStream` 读写直接返回状态对象的协程（每次流写 3 → 1 帧、读 2 → 1 帧）；`AckStreamData` 对按序 ACK 直接推进 `acknowledged`（不再为每次 ACK 分配并释放一个 map 节点，乱序仍走原合并路径）；`Queue` 按引用接收端点与连接，只在真正入队时取 `shared_from_this()`；`SendUdpMessage` 的目标文本与头长只计算一次并去掉 `TargetAddress` 拷贝；删除 `Feed` 恒真的 `flush` 参数、空回调 `PathValidationStarted`、`SocketState::key` 与两个无调用访问器。
4. **协议层**：
   - VLESS：`VlessEncryptionWriter::WritePlaintext` 并入 `WriteBuffers`（每条记录少一帧，去掉约 45 行重复的封记录代码）；`VlessBufferedReader::ReadBuffered` 同步消费已缓冲字节；`ReadMultiBufferOrThrowOnCancel` 包装协程内联后删除；Vision 头 arena 由 `std::deque` 改为 `ThreadLocalList`（每次带填充的写少 2 次分配）；XUDP 读在响应头完成后不再进入 `ReadVlessResponseHeader`；UDP 分帧直接组装 iovec。
   - Trojan：`UdpFramer::Next` 在前缀连续时零拷贝解码地址（去掉每数据报 485 B 的清零与复制）；`WriteUdpDatagram(MultiBuffer)` 直接组装 iovec。
   - Mux：TCP 子流仅在回包队列背压时等待输出窗口；NEW 帧的 `target`/`forwarded` 改为真正移动（原先对 `const` 引用 `std::move` 退化为深拷贝）；删除重复常量。
   - VMess：认证热缓存未命中时删除对全表每个用户最多 32 次的“已试”重扫；`WriteEncodedChunks` 只保留首包合并响应头的分支，稳态直写；删除只写不读的 `PreparedVmessUser::uuid` 明文副本。
   - Shadowsocks：入站 `ResponseBodyWriter` 与出站 `RequestBodyWriter` 统一为按值持有范围的单帧 `WriteEncrypted`（出站明文缓冲在加密完成后、写挂起前归还池）；出站 relay 的转发 lambda 不再占一个连接期帧；`Derive2022Subkey`/`Derive2022IdentitySubkey` 共用一份实现；删除 `Parsed2022Body::client_session_id`、`SsCipherInfo::tag_size` 等死字段。
   - AnyTLS / UoT / 原生 UDP：AnyTLS 写前的子流检查不再拷贝 `shared_ptr`；UoT 已缓冲时不进入 `EnsurePending`，`WritePacket` 改为同步编码头；`UdpIngress::EnqueueReply` 单次查表，`ProcessDecoded` 复用入口时间戳；删除生产不可达的五参数 `EnqueueUdpReply` 虚重载。
   - 删除 8 处恒不生效的 `if (x.empty()) x.ReleaseIfIdle();`。
5. **控制面与基础设施**：
   - `log.cpp`：`FormatRecord` 在时间戳串上原地追加转义后的消息（每条访问日志少 2 次分配和 1 次整行复制）；`json.cpp`：`ParseString` 按连续普通字符段批量追加；`controller.cpp`：删除 `JournalExecutor` 从未实例化的 `void` 分支、`collectTraffic` 无人读取的返回值与 3 个纯转发协程。

### 评估后未采纳

- **Hysteria `ReceiveLoop` 批量排空**：已实现并实测（16×64 上传，同一份代码仅切换该循环，三轮交错，均值）。每次可读最多连续处理 32 包使守护进程 CPU 由 `3.93 s` 降至 `3.45 s`，但消费者运行前有更多流输入各占一个 8 KiB 块，就绪匿名内存由 `34.06 MiB` 升至 `35.62 MiB`、负载结束时由 `34.50 MiB` 升至 `36.69 MiB`、回收后由 `11.92 MiB` 升至 `12.43 MiB`；逐包让出事件循环的变体内存接近持平（`34.36 / 34.86 / 12.13 MiB`），CPU 为 `3.75 s`，收益与轮间波动同量级。按“优化不得以内存换 CPU”两者均未采纳，收包循环保持每次可读处理一包。
- HTTP/2 帧 payload 按对端声明长度一次性分配（违反防未验证预分配）；Shadowsocks 握手多段读合并（改变探测方可见的读取时序）；`GroupCoordinator::PostReserved` 合并 eventfd 唤醒（配额归还时序会依赖被抢占线程）。
- 无读者的 `timeouts.read` 配置键（移除会改变校验报错文本）与 XHTTP 入站每连接的 `XHttpStreamOneHttpConfig` 预计算（需新增归一化派生字段）留待单独处理。

### 验证与性能/内存实证

全量 **1,251/1,251** 测试通过（325 项 unit、926 项真实进程 E2E），零编译告警。过程中两处修正：

- 首次全量运行 `buffer_ownership.BufferOwnership.Contract` 失败：删除 `InitialPayload` 的字节接口后，线程池首次使用落入了被跟踪的故障矩阵，运行时为 `thread_local` 池登记析构的一次性节点被计为泄漏。测试入口先预热线程池后通过，生产代码未因此改动。
- 独立只读复审指出，合并后的 VLESS Encryption 写路径在进入聚合分支前就以“首块指针 + 整条记录长度”构造 span（未解引用，但范围越出首块）；已改为在各自分支内构造。

基准环境：Linux x86-64、mise 固定的 Clang 工具链、Release、`CNODE_ENABLE_LTO=OFF`、4 Worker；基线为 `1be6301` 的构建产物，候选为本次工作区，两者交错运行。HY2、TCP 发送、采样与 UDP 发送各 3 轮，TLS 每项 9 次（`Upload8` 另补 30 次）。更早的一批数据被同机并发的无关构建污染（负载均值约 70），已整批弃用并在空闲时重跑；下列数值为均值，方括号内为最小..最大。

- **Hysteria2 四 Worker 真实进程基准（`cnode_hysteria_throughput_benchmark`）**：吞吐与 CPU 的差异都在轮间波动之内，收益在内存。

  | 场景 | 吞吐 MiB/s | 守护进程 CPU s | 就绪匿名内存 MiB | 负载峰值 RSS MiB | 回收后匿名内存 MiB |
  | --- | --- | --- | --- | --- | --- |
  | 256×1 上传 | 68.21 → 69.36 | 1.317 → 1.291 | 28.90 → 27.82 | 37.37 → 36.28 | 10.73 → 10.36 |
  | 256×1 下载 | 64.17 → 64.18 | 1.424 → 1.464 | 29.62 → 27.84 | 94.28 → 92.64 | 11.70 → 10.30 |
  | 16×64 上传 | 56.39 → 56.05 | 3.788 → 3.798 | 37.13 → 33.49 | 45.41 → 41.82 | 11.55 → 11.59 |
  | 16×64 下载 | 35.49 → 35.23 | 3.656 → 3.633 | 37.75 → 34.26 | 342.29 → 338.49 | 15.14 → 14.85 |

  1,024 条流就绪时匿名内存减少 `3.5 ~ 3.6 MiB`（约每流 3.5 KiB），256 条时减少约 `1.1 MiB`（下载场景基线含一个启动即多占约 2 MiB 的样本，均值差为 `1.8 MiB`）；回收后驻留不高于基线（16×64 上传 `11.55[11.41..11.68]` 对 `11.59[11.40..11.78]`，在波动内）。
- **已建立 VLESS 会话的进程内基准（`cnode_runtime_sampling_benchmark`）**：512 会话空闲 RSS 由 `26,824,704 B` 降至 `25,448,448 B`（−1.31 MiB），匿名内存由 `19,513,344 B` 降至 `17,850,368 B`（−8.5%，约每会话 −3.2 KiB）；`resources=1` 的进程峰值 RSS 由 `27,630,251 B` 降至 `25,701,035 B`。64 会话匿名内存由 `7,327,744 B` 降至 `7,229,440 B`，但该测试二进制的文件映射 RSS 由 `7,114,752 B` 升至 `7,467,008 B`，合计空闲 RSS 上升 248 KiB。关闭内核 fault-around 后逐映射核对：这是该测试二进制重排后触达的代码页变多（`1,812 kB → 2,216 kB`），守护进程二进制在 256 连接 HY2 负载结束时触达的代码页反而略少（`3,208 kB → 3,176 kB`）。采样延迟不变（`resources=0` `70.5 → 70.7 ns`，`resources=1` `88.4 → 89.2 ns`，0 次堆分配）。
- **守护进程启动驻留**：默认内核参数下 `server_started` RSS 由 `12.408 MiB` 升至 `12.514 MiB`、HY2 `startup` 由 `13.726 MiB` 升至 `13.772 MiB`，同期匿名内存持平或略降（`5.666 → 5.659 MiB`、`6.797 → 6.791 MiB`）。关闭 fault-around（`fault_around_bytes=4096`，测后恢复 `65536`）复测，启动 RSS 为 `9,207,808 B → 9,199,616 B`，文件映射部分 `3,268,608 B → 3,272,704 B`（多 1 页）：差值来自内核按 64 KiB 连带映射已触达页的邻页，而二进制布局变了，不是多用了内存。
- **VLESS/TLS 真实进程基准（`cnode_tls_throughput_benchmark`，每次仅传 16 MiB，波动大）**：`Download1` `541.6 → 542.1 MiB/s`，`Download8` `586.8 → 599.0 MiB/s`，`Upload1` `794.7 → 786.9 MiB/s`；`Upload8` 9 次均值曾为 `667.7 → 617.8 MiB/s`，补到 30 次后为 `616.8 → 640.7 MiB/s`（中位数 `622.9 → 641.2`）。结论是吞吐无可测变化。
- **`cnode_tcp_send_benchmark` / `cnode_udp_send_benchmark`**：`8192B (1 piece)` 单次 burst 由 `10,436.5 ns` 降至 `10,218.2 ns`（−2.1%），`8192B (8 pieces)` 由 `10,921.9 ns` 降至 `10,687.7 ns`（−2.1%），`8192B (16 pieces)` 由 `11,361.0 ns` 降至 `11,166.4 ns`（−1.7%），`65536B (8 pieces)` 由 `43,543.5 ns` 降至 `42,717.0 ns`（−1.9%），其余档位持平；UDP 发送各档均值在 `−5.2% ~ +0.3%` 之间，其中 `0B` 与 `60000B owned` 两档的差值主要来自单轮离群值，不计为收益。

未覆盖：限速用户、`IPIfNonMatch` 路由命中、WebSocket/XHTTP/gRPC 传输、Mux/AnyTLS/Shadowsocks/VMess/Trojan 稳态转发没有专项基准，这些路径只由单元与 E2E 测试验证行为不变，未宣称可测的吞吐收益。
