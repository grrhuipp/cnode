# 持续架构审查记录

目标：持续审查并重构，明确职责边界与抽象层次；每轮验证后继续，直到用户要求停止。本记录是阶段检查点，不表示全项目审查完成。

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

取消源仍为 Worker-local、无锁且稳定地址。CancelPending 不影响后来开始的操作；Stop 保留首个非 OK 终止原因，普通关闭以 CANCELLED 表示，后来订阅在构造期间同步收到终止通知。因此订阅上下文必须先完成初始化。CancellationSubscription 可在回调中 Resubscribe；gRPC/XHTTP 会话组合在临时取消时先重新订阅再转发，永久终止则同步传播且不重开。`tests/cancellation_source_test.cpp` 在禁止普通 new 的作用域内增加终止前后订阅、重复 Stop、四次独立临时取消转发和构造前已关闭的来源；原有批次重入、自身/同伴删除与事件源先销毁测试仍保留。针对性构建及测试为 `build/round34-focused-build.log`、`build/round34-focused-ctest.log` 和 `build/round34-focused-last-test.log`。

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
