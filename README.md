# cnode

cnode 是面向 V2Board 面板的高性能 Linux 代理节点服务端。项目使用 C++20 协程、地址稳定的执行域和单 Worker 执行租约，将面板同步、配置归一化、协议处理和流量转发拆成清晰的运行边界。

## 文档分工

- `README.md` 面向使用者，说明项目定位、运行架构、配置入口、部署和关键语义。
- `AGENTS.md` 面向代码修改和自动化协作者，记录必须遵守的职责边界、禁止项、审查清单和硬性删除规则。
- [`docs/local_logging.md`](docs/local_logging.md) 规定本地 error/access 文本格式、通道和级别口径。

如果只是部署、配置或了解项目，从本文件开始；如果要改代码、做重构或接入新协议/面板，先读 `AGENTS.md`。

## 项目定位

- 支持 VMess、VLESS、Trojan、Shadowsocks、AnyTLS、Hysteria、Hysteria2、Freedom、Blackhole。
- 支持 TCP、TLS、WebSocket、PROXY protocol、QUIC、原生 datagram、UDP-over-TCP 和 Mux/子流。
- 支持单进程接入多个 V2Board 面板和多个节点。
- 支持 geoip、geosite、域名、IP、端口、协议、用户等路由条件。
- 默认按多数据 Worker 运行；各数据 Worker 同构，通过 `SO_REUSEPORT` 分别拥有监听和转发资源。主线程作为唯一主控 Worker，面板、监控与 DNS 共用一个事件循环；数据 Worker 通过有界入口提交 DNS 请求。
- 部署脚本 `scripts/cnode.sh` 不带参数时更新默认线上二进制及 `geoip.dat`、`geosite.dat`，不改写既有配置。二进制先下载到同目录临时文件并校验版本，再原子替换；下载、空文件或版本校验失败时保留原二进制，不停止现有服务。二进制或 geo 数据变化后重启原本运行中的服务；geo 下载失败保留旧数据。`-variant <name>` 可选择 release 变体，`-debug_file true` 会额外下载匹配的 `.debug` 符号文件。

## 构建与测试

仅构建 Linux x86-64 musl 全静态程序，使用 C++20。自有编译与测试规则集中在根 `CMakeLists.txt`；`mise.toml` 管理 CMake、Ninja、ccache 和带 SHA256 校验的 LLVM musl 工具链。依赖、版本基线和 overlay 入口统一放在 `vcpkg.json`；BoringSSL 提供 TLS/QUIC 密码实现，overlay 保留 REALITY 与 VMess 所需接口补丁。`cmake/` 仅保留 vcpkg 配方、补丁、triplet 和 musl 工具链。

以下命令适用于 Linux x86-64、Bash。先安装 [mise](https://mise.jdx.dev/getting-started.html)，以及宿主工具（Debian/Ubuntu）：

```sh
sudo apt-get install build-essential binutils git curl zip unzip tar xz-utils pkg-config jq \
  autoconf autoconf-archive automake libtool perl nasm openssl
mise trust
mise install
mise run build
```

产物为 `build/musl/cnode`。默认 `BUILD_TESTING=OFF`，仅构建主程序；不安装测试依赖、不构建测试可执行文件。Ninja 与 vcpkg 使用自动并发；依赖、缓存和临时产物均位于 `build/`。

构建参数统一由 `mise run configure` 传给 CMake，不使用预设文件；额外 CMake 参数通过 `mise run configure -- -D选项=值` 传入。vcpkg 二进制缓存位于 `build/cache/vcpkg`，编译缓存位于 `build/cache/ccache`，CI 会持久化并跨提交恢复；依赖配置变化时仍可恢复旧缓存，由 vcpkg 的 ABI 校验和 ccache 的缓存键决定哪些结果可复用。保留这些目录可避免重复编译。

单元与 E2E 测试均使用 C++ GoogleTest，由 CTest 调度；不使用 Python/JavaScript 测试脚本。测试必须显式启用：

```sh
mise run test
```

`mise run test` 构建 `cnode_tests` 并运行 CTest。功能测试分为 `unit` 和 `e2e`；测试可执行文件不进入默认构建，普通测试复用生产静态库，分配故障场景共用一份按需构建的测试库。需要分步操作时：

```sh
mise run test:configure
mise exec -- cmake --build build/musl --target cnode_tests
mise exec -- ctest --test-dir build/musl --output-on-failure --no-tests=error --parallel -L '^unit$'
mise exec -- ctest --test-dir build/musl --output-on-failure --no-tests=error --parallel -L '^e2e$'
```

主程序与测试共用 `build/musl`，不重复建立独立发布构建树。若只需要某个测试，可显式构建其 `cnode_*_test` 目标，再用 `mise exec -- ctest --test-dir build/musl --output-on-failure --no-tests=error -R <名称>` 执行。切回 `mise run build` 会关闭测试注册。可选 io_uring 后端通过 `mise run configure -- -DCNODE_IO_URING=ON` 配置，再执行 `mise exec -- cmake --build build/musl --target cnode`；官方发布仅提供 epoll。

性能基准默认关闭，显式开启后通过独立的 `cnode_benchmarks` 目标和 CTest `benchmark` 标签运行，不随 `cnode_tests` 构建：

```sh
mise run test:configure -- -DBUILD_BENCHMARKS=ON
mise exec -- cmake --build build/musl --target cnode_benchmarks
mise exec -- ctest --test-dir build/musl --no-tests=error -L '^benchmark$' -V
```

分配微基准与守护进程使用相同的全局 mimalloc，覆盖带生命周期跟踪的字节缓冲追加、1/8/9/16 块 `MultiBuffer` 所有权移交，以及散布写描述符的构建与回收；描述符基准分别使用 span 和 `MultiBuffer` 输入，覆盖内联容量与溢出边界，并校验借用视图的地址与长度，不复制 payload。环形队列基准按每批 1/8/64 个元素填充并完全排空，预热 128 批后测量 `262144 / 批大小` 批，验证 FIFO、checksum、排空归还存储及活跃分配数，并输出 CPU/墙钟耗时和内存池 mapped/idle 字节。归还操作的计时包含空闲登记与到期回收检查；mapped/idle 是采样时刻的快照，不是全程峰值。微基准不代表端到端吞吐。

只运行分配与容器微基准可用 `mise exec -- ctest --test-dir build/musl --no-tests=error -R '^benchmark\.(AllocatorAppendBenchmark|MultiBufferBenchmark|BufferSpanBenchmark|RingDequeBenchmark)\.' -V`。

TCP 接收基准通过真实回环连接测量 1 B / 8 KiB / 64 KiB 突发：每种负载预热 128 轮、测量 4096 轮，逐字节校验载荷，输出每轮 CPU、墙钟耗时及读取次数。CPU 包含同进程收发双方与载荷校验，不是守护进程单侧 CPU，也不代表公网吞吐。

TCP 发送基准通过真实回环连接测量 1 B / 8 KiB / 64 KiB 突发，分别使用 1/8/16 个非空缓冲描述符（1 B 只测单缓冲）。每种负载预热 128 轮、测量 4096 轮，使用与守护进程相同的全局 mimalloc，校验全部接收字节。CPU 包含同进程发送、接收和校验，不含夹具初始化与接收缓冲分配；不代表守护进程单侧 CPU 或公网吞吐。

执行器微基准与守护进程使用相同的全局 mimalloc 分配器，覆盖属性适配、work tracking 的复制与释放，以及每批 1/8/64 个任务的真实投递执行。生命周期阶段预热 4096 轮、测量 262144 轮；投递阶段预热 128 批、测量 4096 批，逐批排空并校验执行顺序、执行域与 checksum。输出每操作 CPU/墙钟耗时及 tracked/untracked 执行器尺寸；CPU 包含对应阶段的构造、释放、队列调度与校验开销，不包含夹具初始化。

SS2022 TCP 身份匹配微基准覆盖 1/16/256/4096 个用户、无 identity key 或 1/4 个 key 组、输入首/中/末用户及 hint 命中/失效/缺失；失效 hint 在新旧实现中指向同一名其他用户。每格预热 32 次、默认测量 512 次，可用 `CNODE_BENCH_ITERATIONS` 调整。计时包含生产认证函数、协程驱动、结果校验与释放，不含客户端握手报文准备；这是认证微基准，不覆盖 TCP 传输或完整入站的重放检查。

SS2022 UDP 身份匹配基准包含 130 格：AES-128/256、1/16/256/4096 个用户、1/4/16 个 identity key 组、已发布快照的首/中/末用户、0/1200 B 载荷，并保留无 identity 与普通重放接收对照。预热和测量次数与 TCP 身份基准相同；每批最多预编码 32 个唯一包，编码在计时外，计时包含解码认证、目标/载荷/归属校验及结果释放。主矩阵只测延迟提交重放的认证阶段，不含入站目录的重放提交、路由或网络 I/O，不代表 UDP 转发吞吐。

SS 加密原语与身份模式 UDP 互操作可在构建 `cnode_tests` 后单独验证；覆盖 AES-128/256 单块及双块独立向量、单块重叠、双块原地操作与部分重叠拒绝，以及真实进程的数据转发与重放隔离：

```sh
mise exec -- ctest --test-dir build/musl --no-tests=error --output-on-failure \
  -R '^(shadowsocks_stream_crypto|e2e\.udp_ss2022_identity)\.'
```

运行时统计基准先建立真实 VLESS → Freedom 回环链路，覆盖 0/1/64/512 条物理连接、有/无资源统计，预热 16 轮后采集 64/256 轮。计时只包含 `Worker::CollectRuntimeStats` 与结果校验，不包含建连、载荷转发和停机；计时外等待既有空闲池回收截止期，再报告回收后的占用，不强制清池。这三项基准输出 CPU、延迟分位数、内存池映射和进程 RSS/峰值，并区分匿名页与文件页；峰值读取 Linux `/proc/self/status` 的 `VmHWM`，包含准备阶段。分配计数仅统计拦截到的 throwing C++ `new` 和 `mi_malloc_aligned` 入口，不等于全部 PMR 分配，两类不能相加。使用 CTest 使每个参数在独立进程运行：

```sh
mise exec -- ctest --test-dir build/musl --no-tests=error \
  -R '^benchmark\.(Shadowsocks(Udp)?IdentityBenchmark|SessionCountsAndRounds/RuntimeSamplingBenchmark)\.' -V
```

真实 cnode 进程基准覆盖 VLESS/TLS 上传、下载：固定 1 个 Worker、1/8 条并发流，每流预热 1 MiB、测量 16 MiB；对端按完整 64 KiB 块接收并校验载荷，避免每次短读重新分配大缓冲。

只测 TLS 链路并指定待测二进制：

```sh
CNODE_BENCHMARK_BINARY=/absolute/path/to/cnode \
  mise exec -- ctest --test-dir build/musl --no-tests=error \
  -L '^benchmark$' -R 'TlsThroughputBenchmark' -V
```

新旧二进制应使用同一份 benchmark，避免把测量端的改动计入生产收益。其 CPU 指标包含进程启动、握手、预热、传输和停机，不等于纯传输阶段 CPU；`daemon_lifetime_wall_seconds` 同时报告完整生命周期耗时，避免只看传输吞吐而漏掉握手或停机延迟。基准输出测量值，不以耗时阈值判定测试成功。启用基准时，功能回归使用 `-L '^(unit|e2e)$'`；重新运行未显式开启基准的 mise 配置任务会关闭基准注册。

Linux TLS 基准还在服务启动、预热完成及测量传输完成但连接尚未关闭时读取 cnode 自身 `/proc/<pid>/status`，输出 `memory.samples` 中以 bytes 为单位的 `vm_rss_bytes`、`vm_hwm_bytes`。RSS 包含共享驻留页，不含测试驱动和内核 socket 缓冲；HWM 是截至采样点的进程峰值，并非仅传输阶段的峰值，也不覆盖停机后的变化。同时读取 `smaps_rollup` 的 RSS、PSS、匿名页及匿名/文件透明大页，用于归因驻留内存波动；这些逐映射统计是采样时的值而不是峰值，与 status 也不是原子快照。

比较内存前，以相同写入方式生成并预热新旧可执行文件副本，先用同字节二进制做 A/A 对照。文件页缓存、映射及透明大页都会影响 RSS，不能把不同文件缓存状态造成的驻留差异当作堆内存收益。

官方参考程序互操作测试按需配置，使用本地可执行文件，不在测试期间下载。AnyTLS 参考程序可先用宿主 Go 准备，默认离线且要求固定提交的干净源码：

```sh
CNODE_ANYTLS_SOURCE=/path/to/anytls-go mise run reference:prepare
# 没有本地源码时，只有显式授权下载才会联网：
CNODE_REFERENCE_DOWNLOAD=ON mise run reference:prepare
```

配置参考程序后，仍通过同一 GoogleTest/CTest 入口运行：

```sh
mise run test:configure -- \
  -DCNODE_REFERENCE_GO="$(command -v go)" \
  -DCNODE_REFERENCE_ANYTLS_CLIENT="$PWD/build/reference/anytls/bin/anytls-client" \
  -DCNODE_REFERENCE_ANYTLS_SERVER="$PWD/build/reference/anytls/bin/anytls-server"
mise exec -- cmake --build build/musl --target cnode_tests
mise exec -- ctest --test-dir build/musl --output-on-failure --no-tests=error --parallel -L '^e2e$'
```

Xray 使用 `-DCNODE_REFERENCE_XRAY=/path/to/xray`，要求 `v26.10.31` 对应版本；Hysteria v1/v2 分别使用 `CNODE_REFERENCE_HYSTERIA1`、`CNODE_REFERENCE_HYSTERIA2`，可独立配置。参考测试通过 `CNODE_REFERENCE_GO` 检查来源和构建元数据；AnyTLS 必须同时提供客户端与服务端。不配置参考程序时只注册本地可控对端 E2E，不把缺失参考程序计为测试通过。

本地与 CI 使用同一份 mise 固定工具链、vcpkg 依赖基线和配置入口，均为 `Release` 并开启 LTO；测试配置统一运行 `mise run test:configure`。宿主发行版无需相同，不要求容器。密码学故障注入测试单独保留链接器可拦截的调用边界。CTest 使用不指定数量的 `--parallel`，按可用 CPU 自动调度。

CI 只对源码、测试、构建配置变更自动运行，纯文档和部署脚本变更不触发编译；也可手动运行。不设置工作流级并发分组，不同提交可同时运行。`build` job 复用同一构建树，`verify` 步骤统一执行单元、E2E 与静态 ELF 检查。vcpkg 缓存按依赖配置保存、ccache 按提交增量保存，两者在对应阶段成功后立即保存，不因后续测试失败丢失。仅分支 push 在验证通过后打包，`release` job 的 `publish` 步骤下载并发布产物；PR 和手动运行只验证。

集成测试按实际监听范围预留动态端口：同时监听 TCP/UDP 的场景会占有两个协议的同号端口，写完配置后才释放并启动进程，避免把仅 UDP 空闲的端口用于 TCP 监听。

## 架构总览

所有 TCP / UDP 请求最终只能经过一条数据链路：

```text
Inbound Handler::Process
  -> Dispatcher::Dispatch
  -> Outbound Handler::Process
  -> Relay
```

原生 datagram、UDP-over-TCP 和 Mux/子流可以有必要的窄适配，例如 UDP framer、`DispatchUDP` 或 `DialUDP`。这些适配只服务主链路语义：inbound 解析并生成 metadata，dispatcher 做路由，outbound 使用所属执行域的出站资源，relay 以协议无关方式搬运数据。

运行时主链路：

```text
main
  -> bootstrap
  -> Worker(per-core)
  -> listener / accept
  -> ExecutionDomain / session group
  -> TransportStack(TCP / TLS / WebSocket / PROXY protocol)
  -> InboundHandler(VMess / VLESS / Trojan / Shadowsocks / AnyTLS / Hysteria / Hysteria2)
  -> Dispatcher::Dispatch(immutable DispatchPolicy)
       -> sniffing
       -> forced outbound, or Router matched-rule decision
       -> no-match explicit inbound fallback
       -> RequestPolicy allow / block
       -> outbound handler lookup
  -> OutboundHandler(Freedom / VMess / VLESS / Trojan / Shadowsocks / AnyTLS / Blackhole)
  -> Relay(TCP / UDP / Mux)
```

每个数据 Worker 独立绑定同一组 `SO_REUSEPORT` 端口，并且各自持有唯一完整的 Worker-local 多级 PMR 池。物理连接只持有轻量分配域和按阶段借用的 arena，不复制尺寸类表、large-bin、空闲队列或 reclaimer；小对象由同一 Worker 上的连接共用 slab，运行期 payload、Buffer、子流及可扩缩容器逐块借还。会话迁移后新分配使用当前 Worker 池，旧块按槽头记录的来源进入原 Worker 的 remote-free 队列，由原 Worker 回收，绝不跨线程直接操作 `unsynchronized` pool。执行域在任一时刻只有一个 Worker 执行租约。XHTTP 请求按配置命名空间与 session id 在有界控制目录会合；跨 Worker 相遇时冻结相关会话组的用户回调、合并执行归属，再恢复运行。H2 物理连接上的多个 session 及桥接它们的连接一起合组，不拆分仍共享状态的宿主。原 reactor 只提交就绪通知，实际 socket 读写和协议处理在当前 owner 上执行，不把数据包持续转发到另一个 Worker。

不再使用源地址 CBPF 亲和；同一 XHTTP session 可来自不同客户端／CDN 回源地址，无须设为 `workers: 1`。不共享状态的会话组仍独立调度，整个入站不会被固定到一个 Worker。短上传完成后事件驱动移除目录和域成员，迟到上传由有界 tombstone 拒绝，不在满容量路径逐次扫描整张会话表。面板、DNS 和跨域元数据操作仍通过有界控制入口交互。

QUIC 与具有已认证会话身份的原生 UDP 关联只因同一会话的数据实际落到另一 Worker 而被动接管，不按负载或空闲定时迁移。QUIC 必须完成路径验证；SS2022 按配置、凭据和客户端会话身份隔离并保持唯一防重放状态。交接先冻结业务执行、排空原生 I/O 与回包，再将原 socket、协议状态、未完成读写和超时绑定到实际收包 Worker；失败回滚，不能恢复的会话关闭。仍在使用的出站连接一并接管，不重新拨号或更换本地端口，不移动共享入站监听 socket。TCP 重连是新连接，TCP 承载的 UoT 不单独迁移；无可验证会话身份的 UDP 不跨地址拼接关联。Hysteria2 仍只提供配置的服务端 UDP 端口，不实现端口跳跃。

迁移准备和回滚的协程完成通知不等于原生执行回调已退出：返回控制面前必须经过来源 Worker 队列屏障，确认旧分配租约已释放，才允许目标校验或恢复业务。回归同时覆盖该通知顺序，以及真实 SS2022 换源时的防重放、旧路径拒绝和当前路径乱序接收。

执行域直接复用 Worker executor；Worker 路由在准入前冷注册，接入与接管只查询不可变路由，不加同步锁，也不在协调器中保留依赖 reactor 私有分配器的 `strand`。Worker 退出后的延迟析构不会访问失效服务。饱和到时钟上限的超时仍保留可取消的原生等待，取消或提前到期不因重新分配等待节点而失败。会话域的超时回调异常先取消本域剩余等待，再交给所属会话的失败入口；无会话归属的 Worker 回调异常向运行时传播，其他域的等待不被一并取消。

监听前完成配置校验、路由编译、不可变策略和 TLS／REALITY 上下文准备；物理执行域只按实际协议与所选出口延迟创建运行态宿主，不复制整套 Worker runtime。控制面发布候选快照失败时保留旧配置。

数据 Worker 的监听标签、端点索引与 socket 控制块使用所属线程的 PMR。注销完成后移除注册项；尚未结束的 accept / receive 循环仅保留收束所需的退役状态，并在原 Worker 上释放，不累计空标签条目，也不把监听所有权带入每个请求。

出站配置与认证凭据在冷路径准备为不可变快照，handler 持有该快照，不在各执行域内重复解析或深拷贝。AnyTLS 空闲池与 VLESS Encryption 票据宿主按原准入 Worker、配置快照与出站 tag 隔离，不因请求迁移改变命名空间。AnyTLS 物理连接具有独立执行域，借出时独占附着到请求会话组，使用期间随请求被动接管；请求结束后分离，健康连接按其当前 Worker 归入原池索引。借用只选择与请求当前 Worker 一致的连接，归池与复用都不主动迁移物理连接；不同活跃请求不并发借用同一物理连接。padding 更新在池宿主串行发布，借用时一并取得下一次握手的不可变快照，不在请求路径读取 `atomic<shared_ptr>`，也不修改其他已建立会话的 padding 状态。VLESS 请求按值借用票据并在宿主内条件发布，不因共享票据永久合并入站执行域。替换配置停止旧池的新借用，已有请求继续使用旧快照，结束后收束旧池任务。空 PMR 容器只弱引用轻量分配域，不延长已退役物理连接寿命；若该容器随后复用，则在首次分配前绑定当前执行域。

proxyman / ingress 在冷路径准备 receiver 语义，公开 Dispatcher 只接收请求所需的窄契约；强制出口和未命中回退属于 Dispatcher 编排，Router 只回答“哪条路由规则命中”。每个 receiver 必须在构建时明确选择 `ForceOutbound` 或 `RouteWithFallback`，不存在 Worker 全局默认出口，也不存在可进入热路径的空策略。cnode 使用强类型、只读 `DispatchPolicy`，不把完整 `ReceiverSettings` 或可变配置 context 传入 Dispatcher。面板 `DetectRule` 由 Worker-local 实现通过通用 `RequestPolicy` 接口提供 allow / block 结果，不进入 Router，也不让 Dispatcher 依赖面板规则管理器。

HTTP 与 HTTPUpgrade 只在建链阶段处理 HTTP 握手，完成后继续使用原来的 TCP / TLS 流，不保留长期透传包装。握手提前读到的应用数据由实际读端按原顺序承接；TLS 明文残留不会进入底层 TCP 密文缓冲。残留读完或读端关闭后释放，取消、半关闭与 TLS 关闭仍沿原传输链路生效。

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
数据 Worker / panel DNS 客户端
  -> 主控 Worker 上 DNSWorker 的有界 mailbox
  -> 主控线程独占的缓存 / 同域在途查询
  -> upstream DNS query
  -> 按值返回解析结果
```

## 职责速览

| 层级 | 负责 | 不负责 |
| --- | --- | --- |
| inbound | 认证、入站协议解析、用户识别、目标地址解析、session metadata、调用 dispatcher | 路由选择、出站连接、relay 细节、访问 outbound handler registry 内部结构 |
| dispatcher | 接收只读 DispatchPolicy / session / link；编排 sniff、强制出口、Router 规则、显式 fallback、通用 RequestPolicy；选择 handler 并调用 outbound.Process | 接收完整 ReceiverSettings、依赖具体 DetectRule 策略实现、维护全局默认出口、解析协议、协议特判、执行 relay、读取 panel 字段 |
| router | 通过 `routing::Router` 只读契约查询真实规则命中；冷路径一次构建并共享不可变规则 | 原地重配规则、强制出口、隐式默认出口、未命中 fallback、创建连接、访问 outbound handler registry / relay / 协议实现 |
| request policy | 基于统一 session context 返回 allow / block；执行域内应用只读策略快照 | 路由选择、outbound handler 查找、协议解析、暴露面板原始字段 |
| outbound | 建立目标连接或下一跳连接，执行出站协议握手和编码，交给 relay | 路由决策、读取 panel 原始配置、绕过 dispatcher |
| relay | TCP / UDP / Mux 数据搬运和流量统计打点 | 解析协议、选择 outbound、访问 panel、暴露 wrapper API |
| Worker | 事件循环、accept 生命周期、执行域调度、监听与原生 UDP 资源所有权 | 协议解析、路由、panel 同步、理解具体 validator 或 outbound 类型 |
| control plane | 面板同步、配置归一化、runtime 构建、快照发布、状态与流量上报 | 进入热路径、直接改 live handler、访问 Worker buffer provider |

更完整的边界规则、禁止项和删除标准见 `AGENTS.md`。

## 配置设计

默认主配置文件为 `config.json`。cnode 使用 JSON 作为部署配置格式，进程级字段保留在 `config.json`，代理与分流条目放在同目录侧车文件中。

目录模式固定读取：

```text
config.json
inbounds.json
outbounds.json
routing.json
geoip.dat
geosite.dat
```

`config.json` 顶层必须是对象，数组、标量和 `null` 均拒绝加载。`inbounds.json` 和 `outbounds.json` 顶层固定为对象数组，`routing.json` 顶层固定为 routing 对象，不接受 `{ "inbounds": [...] }`、`{ "outbounds": [...] }`、`{ "routing": { ... } }` 等冗余外层包装。

所有本地配置键（含 `config.json`、侧车、`panels` 和嵌套 `settings`）不区分 ASCII 大小写，解析时统一转为小写；示例采用 camelCase。因此 `APIHost`、`apiHost`、`apihost` 等价，`NodeIDs`、`nodeIDs`、`nodeIds` 等价，无需因大小写差异迁移旧配置。大小写归一化后重复的键直接报错，即使值相同也不允许。`api_host` 等下划线别名以及已删除字段不会因此恢复支持，配置文件名仍固定为下列小写文件名。

语义上大小写无关的字段值同样在冷路径统一为小写：协议、`nodeType`、面板 `type`、`network`、`security`、日志级别、加密方法、`flow`、`decryption`/`encryption` 中的模式名、`packetEncoding`、`listen`/`sendThrough` 的 `auto`、`sendThroughStrategy`、Freedom `domainStrategy`／面板 `dnsType`、Blackhole 响应类型，以及 DNS 主机名语义的 Host、SNI、`serverName`、gRPC `authority`。路径、gRPC `serviceName`、Header 值、标签、邮箱、UUID、密码、密钥与 padding 方案区分大小写，保持原值。`nodeType` 只接受 `vmess`、`vless`、`trojan`、`shadowsocks`、`anytls`、`hysteria`、`hysteria2`；未知枚举、空值或错误类型拒绝加载。路由引用不存在的 outbound 也直接报错，不丢弃该规则或回退到其他出口。

面板 UniProxy `config` / `user` 下发以 xv2board 的 `UniProxyController` 为契约：整数字段（`server_port`、`base_config.*_interval`、`tls`、Hysteria `version`/`up_mbps`/`down_mbps`、用户 `id`/`speed_limit`/`device_limit`、REALITY `server_port`/`xver`/`max_time_diff`）同时接受 JSON 非负整数与纯十进制字符串；`tls` 另接受布尔值及 `"true"`/`"false"`；PHP 空关联数组 `[]` 视为空对象。浮点、负数、带空白或符号的数字字符串仍拒绝。Hysteria 按下发的 `version` 选择 v1/v2，并使用 `up_mbps`/`down_mbps`；面板下发的 Shadowsocks/Hysteria 混淆及 VLESS Encryption 当前运行时不支持，出现非空值时拒绝该节点而不是静默忽略。

部署模式添加面板时同样按大小写无关的字段名查找，但面板名称区分大小写；替换同名面板不会改写其他配置键或字段值。配置 JSON 损坏、面板列表类型错误或存在大小写冲突的字段时停止写入，保留原文件，不尝试猜测修复。

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

### 认证失败限制

`config.json` 可独立开启 IPBan；省略时关闭，配置默认值如下：

```json
{
  "limits": {
    "ipBan": {
      "enabled": false,
      "failureLimit": 10,
      "windowSeconds": 60,
      "banSeconds": 180
    }
  }
}
```

- IPBan 按入站标签和 PROXY protocol 提供的非空客户端 IP 计数；直连 socket IP、HTTP 转发头不参与。启用后可在传输握手前拒绝已封禁 IP，不踢掉已有连接。三个数值字段均为正整数，单位分别为次数、秒、秒；即使关闭也拒绝非法值。
- **失败凭据限制固定开启，不可配置或关闭**：同一入站、同一认证信息跨 IP 累计，60 秒内达到 10 次失败后临时拒绝 180 秒，拒绝期间跳过用户认证查找。支持 VLESS、Trojan、AnyTLS 和 Hysteria v1/v2；VMess、Shadowsocks 在认证失败时不能可靠识别原始凭据，只使用可选 IPBan。配置 `limits.credentialBan` 会报错。
- 两种限制独立，所有 Worker 共用计数。窗口从本轮首次失败起算，到达窗口末尾重新计数；认证成功不清零，封禁期间的请求不累计、不续期。用户快照更新后，该协议和入站的旧凭据失败记录不再影响新用户；其他入站记录不变。
- 失败状态仅保存在内存，进程重启后清空。每种规则最多跟踪 16,384 个键，局部跟踪容量耗尽时拒绝未知键，不无保护放行。凭据原文和跟踪指纹不写入日志。

## Release 产物

GitHub Release 仅发布 musl+epoll 全静态二进制及匹配的 `.debug` 符号文件：

```text
cnode-linux-amd64
cnode-linux-amd64.debug
cnode-linux-amd64-musl
cnode-linux-amd64-musl.debug
```

两种二进制名称对应同一产物，不再发布 glibc 变体。CI 在打包前检查 ELF 不含动态解释器和共享库依赖。

部署脚本默认下载 `cnode-linux-amd64`；符号文件只在显式要求时下载：

```sh
bash scripts/cnode.sh -debug_file true
```

配置进入 Worker 前必须完成归一化。Worker 热路径只读取不可变 runtime snapshot；控制面更新时以原子替换快照的方式发布，新旧连接按生命周期自然释放。

## 关键语义

- 静态入站和面板均支持 `proxyProtocol`：`"off"` 不探测，`"auto"` 自动识别 PROXY v1/v2 或保留普通应用字节，`"on"` 强制要求有效头；省略时默认 `"auto"`。畸形或截断头会失败，不静默降级。自动识别不验证代理来源：`auto/on` 接入端只应允许可信前置代理访问，否则客户端可伪造源地址；直连且不需要此功能时使用 `off`。
- `sendIP: "auto"` 表示 direct outbound 优先绑定入站连接命中的本地 IP，用于多 IP 服务器源进源出。
- `enableDNS` 默认值为 `true`。
- 原生 TCP 的单次 socket 接收最多借用一个 8 KiB Buffer；每个 relay 方向发送完当前批次才继续读取，空闲等待读取时不持有 payload Buffer。协议预读数据仍先于后续 socket 字节交付。
- TCP 嗅探只复制至多 4KB 的必要前缀。UDP 按原始数据报执行有状态 QUIC 嗅探，仅 `need_more` 触发续读：总窗口 200ms，最多 64 个数据报，累计输入达到 64KiB 后停止续读；已经读取的最后一个数据报即使跨过预算也完整保留。CRYPTO 重组上限 64KiB，独立记录已收到的字节，空洞不能作为有效 ClientHello 解析；不同 DCID / version 不混合，原始密文不修改。临时嗅探缓冲在路由前释放。
- 初始数据以 `MultiBufferBatch` 按值转交出站；每个元素保留一个原始 reader 结果，UDP 包边界、目标和顺序不变，零／单元素不分配队列。普通上行 relay 逐个发送缓存元素后继续读取，与后续数据共用限速、错误分类和统计。VLESS、Trojan、AnyTLS 的握手只写协议控制数据，用户数据由 relay 发送；结果字节数、会话字节数和流量统计保持一致，发送失败不计入成功流量。
- 嗅探续读超时不等于传输 EOF：TCP/TLS 活跃读取取消报告 `operation_aborted`，内存不足不能伪装成空数据。HTTP/1 chunked、VLESS Encryption 和 VMess reader 保留尚未完成的头、记录、读取进度及长度／掩码状态，取消后 relay 可继续读取同一会话；已经解码但尚未交出的批次也不会丢失。
- 首包容器只允许移动；单块缓冲通过 BufferGuard 转移所有权。追加、搬移和前缀拆分先完成分配准备再提交；内存不足时保留原有字节和长度，失败的单块插入自动释放交入的缓冲。
- 每个转发方向按 bytes/s 独立限速，初始额度为一秒流量，空闲积累最多两秒；限速等待已经消费对应的未来额度，等待结束不会重复补发。relay 半关闭截止时间和方向失败会取消限速等待，超时后不再发送排队数据；两个方向结束后才释放等待对象和截止回调。
- relay 从控制端点、出站逻辑流和 UDP 请求接收终止事件，同时结束同伴 I/O 与限速等待，并保留超时、取消或资源不足的实际原因。没有客户端控制对象的子流也执行 uplinkOnly/downlinkOnly 的剩余方向预算；父协程退出前等待全部传输和停止任务结束。
- 每个读端都提供通用取消来源，Mux、AnyTLS 和原生 UDP 入站子流沿 Link 传到 relay。取消当前操作与永久关闭分别处理；已取消子流在 relay 开始前就会被识别，排队首包不会在等待结束后继续发送。Link 同时传递 EOF 和写关闭语义，relay 区分 TCP 半关闭与完整逻辑关闭，完整关闭会结束两个方向的 I/O 和限速等待。
- TLS 读取以 `close_notify` 表示正常结束；未收到关闭通知的传输断开按截断错误处理，不当作正常 EOF，符合 [TLS 关闭语义](https://www.rfc-editor.org/rfc/rfc9846.html#section-6.1)。
- gRPC / HTTP/2 的 END_STREAM 通过读端 EOF 语义关闭目标写方向，并允许反向数据继续传输；协议 TCP reader 保留底层语义。DATA 和控制帧共用所属 Worker 的异步写入门，完整帧写完后才允许下一次写入。VMess 在协议内部编码结束帧，关闭失败沿请求错误路径返回；空响应也先发送响应头。
- gRPC Hunk 的单条未压缩 protobuf 消息正文最多 4 MiB。接收长度头不预分配消息存储，正文按实际收到的字节增长；完整校验后才交付 data，重复字段取最后一个，消费或关闭后释放消息存储。该存储与 relay 的 8KB payload Buffer 分开计量。发送端将较大写入分成多条有界 Hunk，接收端拒绝超限、压缩或畸形消息。
- gRPC、h2 和 XHTTP 的 HTTP/2 服务端共用会话、流准入、HPACK 状态及控制帧处理。每个连接最多接纳 256 个并发流，超额以 REFUSED_STREAM 拒绝；流接收窗口为 4 MiB、连接窗口为 8 MiB，并限制会话存储预算。慢消费者耗尽信用时形成背压，不靠持续提前归还窗口再堆积数据。真实存储预算不足以 ENHANCE_YOUR_CALM 重置相关流，已有流继续工作。无效 RST_STREAM 以 GOAWAY 关闭连接；HPACK 解码错误以 GOAWAY(COMPRESSION_ERROR) 关闭连接。请求伪首部重复、trailer 携带伪首部或 `host` 与 `:authority` 不一致时以 RST_STREAM(PROTOCOL_ERROR) 重置该流。
- HTTP/2 客户端与服务端发送 DATA 均受连接及流窗口约束（RFC 9113 §6.9），额度不足时等待 WINDOW_UPDATE，其他流与控制帧仍可写出；`SETTINGS_INITIAL_WINDOW_SIZE` 按差值调整已打开流。接收按含 padding 的完整 DATA 负载计费，消费、丢弃或转入有界 Hunk 装配后才归还对应额度；关闭／重置返还未消费的连接额度，不复活已关闭流。窗口溢出或违规发送按对应的 FLOW_CONTROL_ERROR 处理，合法最大 Hunk 不依赖对端违反窗口才能完成。
- HTTP/2 物理连接的连接额度按 `max(1, 活动逻辑请求数)` 计费；子流的绝对握手期限独立于物理写入背压，到期后释放该子流额度，不中止仍在传输的同伴。H1 XHTTP 完成 HTTP 建链后移除物理握手期限，分离的逻辑请求独立执行代理握手期限，正常转发不受旧期限影响。H1 XHTTP 以 `Content-Length` 上传的 packet-up 请求遵循 HTTP/1.1 持久连接（RFC 9112 §9.3），同一连接可承载后续及流水线请求；每个请求从首字节起享有独立握手期限，请求之间只受空闲超时约束。分块上传、HTTP/1.0 或任一 `Connection` 字段行含 `close` 的请求以 `Connection: close` 响应后关闭，其后流水线请求不再处理。H1 上传正文（packet-up、stream-up、stream-one）须恰好使用一种分帧（RFC 9112 §6.1–6.3）：单个合法 `Content-Length`，或唯一且只含 `chunked` 的 `Transfer-Encoding`；两者并存、重复或非法长度、其他传输编码及无分帧的请求一律拒绝，`Content-Length` 正文读满声明长度即结束，其后字节不进入上行。上传可能先于其下行 GET 到达：上传为未出现过的 id 建立 session，并在本请求期限内等待下行加入，同一 session 的多个等待上传在下行加入或 session 关闭时全部放行；已结束 session 的迟到上传读完正文后以 404 丢弃，连接与其上其他 session 的请求继续。无 session 的 POST（stream-one）在 H1 下以分块响应承载下行。XHTTP 每个逻辑 session 的已排队数据及并发上传共用 4 MiB payload Buffer 容量预算，最多 1024 个排队包和 64 个在途上传；拒绝超额上传不破坏已有会话。XHTTP `mode` 只接受 `auto`（或省略）、`packet-up`、`stream-up`、`stream-one`（不区分大小写），其他值在加载配置时报错。
- VMess 和 Trojan 入站按协议结构增量读取握手；正常 TCP 分段或不完整 EOF 不计为认证失败。VMess 请求头声明未知的 body security 时在路由前拒绝。协议认证诊断不输出认证字节、AuthID、密码哈希片段或私钥文本。
- VMess 重放检查与用户设备准入在单 owner 的有界控制服务中原子执行，跨 Worker 或迁移不能绕过。VMess 重放窗口为 180 秒、最多 65,536 项；容量满时拒绝新记录。
- Shadowsocks、VMess 和 VLESS 共用 AEAD 上下文操作；连接内复用算法与密钥状态，记录之间只更新 nonce。Shadowsocks 与 VMess（入站请求体和出站响应体）reader 在取消后保留不完整记录；认证失败、非法长度和残帧 EOF 报告错误，不当作正常结束；VMess 仅在记录边界上的传输 EOF 视为正常结束。原生 SS2022 association 的回包保留同一 server session ID，packet ID 连续推进，重放窗口按认证用户与 session ID 隔离。
- WebSocket 升级要求 HTTP/1.1 GET、`Upgrade: websocket`、所有 `Connection` 字段行合并后的 `upgrade` token、版本 `13` 和解码后为 16 字节的握手 key。HTTPUpgrade 同样按多行 token 列表处理 `Connection`。HTTP chunked 长度及扩展共用解析契约，支持合法 quoted-string，拒绝溢出和畸形分帧。
- WebSocket 的帧头、扩展长度、mask、控制帧和分片状态在读取取消后保留；数据帧收到多少便交付多少，不等待调用者缓冲填满。错误方向的 mask、非法长度／opcode／RSV、无效 UTF-8、非法 Close 和截断帧均报协议错误。PING、PONG、Close 与普通数据按完整物理帧串行写入；写入失败立即关闭底层连接。
- V2Board Shadowsocks 2022 节点会自动使用面板下发的 `server_key` 作为 identity PSK，并按 V2Board 规则从用户 UUID 前缀构造用户 PSK；无需把订阅中的两段式密码回填到用户表。
- Shadowsocks 和 AnyTLS inbound 会自动识别 UoT v2（`sp.v2.udp-over-tcp.arpa`）及 v1（`sp.udp-over-tcp.arpa`）。Shadowsocks outbound 可用 `"uot": true` 开启 UoT（默认 v2），以 `"uotVersion": 1` 选择 v1；也可使用 `"uot": {"enabled": true, "version": 2}`。
- VMess outbound 的 UUID 和 Shadowsocks outbound 的加密方法、密码会在加载配置时验证。VMess、VLESS、Trojan、Shadowsocks 与 AnyTLS outbound 的 settings 字段若存在但类型错误会拒绝加载，不按缺省处理。Shadowsocks 省略 `method` 时使用 `aes-256-gcm`；显式的空值、非字符串或未知方法会报错。SS2022 每段 PSK 必须符合所选方法的密钥长度，身份链只支持 AES 方法，不能包含无效或空片段；错误配置不会启动服务。
- VLESS outbound 的 Vision flow 要求 TCP 搭配 TLS 或 Reality；明文 TCP、WebSocket 等组合会在加载配置时被拒绝。VLESS 的 1–30 字节自定义 ID 仍按 UUIDv5 映射，与入站使用同一转换。
- Vision 按完整 TLS 记录推进填充阶段，正确处理收到的 CommandPaddingDirect（cmd2），先排空 TLS 解密及预读残留再切换 raw TCP。发送端仍使用 cmd0／cmd1，不宣称已经实现双向 raw-write 优化。
- VLESS Encryption 的服务端票据按配置身份、入站及认证用户隔离；跨 Worker 恢复经控制目录到票据 owner 原子检查并提交重放状态，不依赖源地址亲和，也不迁移数据包。重复保存同一票据不会重置重放记录。
- `tlsSettings` 中的 `certificateFile`／`certFile`、`keyFile`、`caFile` 以及面板的 `tlsCert`／`tlsKey` 在加载配置时一次性读入；文件不存在、不可读、为空或超过 1 MiB 时拒绝加载。TLS／REALITY 上下文在配置发布前构建并共享只读，握手不读取文件或重建上下文。PEM 损坏、证书与私钥不匹配等错误使静态配置拒绝启动，面板本次更新失败并保留原节点；证书文件更新需重新加载配置。
- autosign 只为配置的名称生成 SAN，不按任意 SNI 临时签名；冷路径生成证书并由独立有界更新器在到期前更新不可变上下文，已有 SSL 保留旧上下文。没有到期事件时不定时轮询；过期且无法更新时拒绝新握手。
- AnyTLS outbound 的 `idleSessionCheckInterval`（默认 30 秒）驱动各独立池的检查，`idleSessionTimeout`（默认 60 秒）决定空闲到期时间；`minIdleSession`（默认 0）保留该池最近归还的健康空闲会话。占用中的会话不参与空闲淘汰，短物理入站的结束不等于池退役。
- AnyTLS 出站请求使用统一的 relay 空闲、写入和半关闭超时；持续接收数据不会延长半关闭的绝对截止时间。取消受阻写入会关闭物理会话；成功请求归还前清除请求超时，空闲连接的寿命随后由会话池控制。
- Freedom 和 Shadowsocks 原生 UDP 出站共用 datagram transport，并沿统一请求主链进入 relay。每个逻辑请求独占一个 UDP socket，本地源端口在请求存续期间保持不变；取消或关闭不会影响其他请求，即使它们访问同一远端。写入预算包含 DNS 等待；Shadowsocks 仅把认证通过的回包计为有效活动。
- UDP 出站 socket 的地址族在创建时确定：literal IPv6 目标自动使用 IPv6，显式绑定按配置执行；不兼容的目标或解析结果会失败，不会重建 socket 或改变源端口。每 Worker 最多同时拥有 4096 个原生 UDP 出站 socket；容量或系统资源不足时拒绝新请求，不降级为共享 socket。运行时日志的 `udp_sockets` 统计实际打开的出站 socket，不包含入站监听或 DNS socket。
- UDP 按需接收，在可读后才申请 payload，不保留应用层回包队列；内核接收队列满时遵循 UDP 丢包语义。上行半关闭后，在 `timeouts.downlinkOnly` 的绝对窗口内继续收包；流量只在成功发送后计入。零长度 UDP 载荷保留报文边界，不视为 EOF。向普通 VMess UDP 转发空报文时，以 `NOT_SUPPORTED` 结束该请求，不将其伪装成协议结束帧。
- 原生 UDP 入站在接收缓冲或单包处理内存不足时丢弃当前包，继续在原 socket 上接收；空闲等待前释放接收缓冲。仍在注册的接收循环意外结束、或监听提交后无法启动接收循环时，进程以失败状态退出，避免留下已绑定但无人读取的端口。
- 原生 UDP association 在没有新包时也会分批回收已关闭和过期记录；每个 Worker 共用一个维护事件，不为每个 association 建定时器。该事件只在有记录关闭或到达最近的过期时刻时唤醒，没有可回收记录时不唤醒，单个上行包也不调整它。association 的 idle 按有效上行活动判断，单纯下行不续期；idle 为零只禁用开放会话过期，已关闭记录仍回收。每个 Worker 的全部原生 UDP 入站共享资源预算：最多 4096 个仍存活的 association、8192 份排队或正在发送的数据报，以及 64 MiB 排队 payload Buffer 容量。容量按实际缓冲容量而非有效字节数计量；association 直到请求清理与最后持有者完成才归还额度。满额时拒绝新 association 或当前新数据报，已有请求不被驱逐。这些是资源限制，不是协议限制，也不代表整个进程的内存上限。
- 原生 UDP 更换监听 socket 或注销入站时，先停止新请求并取消旧请求，再等待旧分发任务实际结束；删除 association 或关闭 socket 不等于请求完成。同 socket 的协议更新保留现有会话，旧请求继续使用创建时的元数据和分发策略，新请求使用新配置。
- 原生 UDP 回包按 socket 保持一个在途发送任务；payload 按值存于该任务帧内，普通数据报出队不额外申请堆节点，也不逐包复制监听字符串键。旧 socket 的发送完成不能清除替换 socket 的活动队列；删除队列后，在途 payload 仍计入共享预算，直至 I/O 完成并释放。
- `limits.maxConnections` 和 `limits.maxConnectionsPerIP` 使用未拆分的进程配置值，所有 Worker／入站共享，`0` 表示不限；不再按 Worker 数向上取整。物理连接保留一个额度 floor，额外并发逻辑请求增加额度。IP 跟踪满时拒绝新准入；半关闭仍在工作的请求继续占用额度，完整结束后通过预留控制通道归还，业务邮箱满或关闭不能丢失归还。
- TCP 和原生 UDP 的 idle/read/write/phase 超时共用聚合状态，由所属执行域／原生资源调度器承载；逻辑读写结束或连接关闭时撤销预算。超时终止在通知取消前设置 abortive close，排队写数据不会在逻辑失败后无限期继续发送。连接级驻留任务组在没有实际子任务时只保存 executor，首次启动子任务才申请 join 状态和自持有组；取消与 join 语义不变。
- `info` 级别的周期资源日志按 `Runtime activity / memory / traffic / DNS cache`、`Process descriptors`、`Worker activity / memory / UDP resources / UDP traffic` 和 `Panel node totals` 分行输出，不把原有指标隐藏到 `debug`。`udp_listeners` 是当前注册的入站 socket 数，`udp_receive_loops` 包含尚未完成退役的接收任务，`udp_native_dispatches` 是尚未实际完成的原生 UDP 分发任务数，包含退休中的任务；association 记录归零不代表此计数也已归零，不统计 TCP 或 Mux 子流。`udp_resource_drops` 累计记录接收资源不足、处理分配失败或截断导致的丢包。队列指标是当前占用，不是累计吞吐；回包统计包含正在发送的包，`udp_reply_senders` 是活跃发送 socket 数。`timeout_heap=活跃事件数/索引容量` 区分当前超时占用与历史峰值容量保留；取消会立即移除索引，不保留过期节点。容量未回落不等于泄漏，PMR 映射量也不等于 RSS。FD 采样不可用时显示 `unknown`，不会伪报为零。这些日志用于故障前后的趋势对照，不能单凭重启恢复判定资源耗尽。
- 本地日志格式与分流见[日志格式](#日志格式)。`loglevel` 取 `none`、`trace`、`debug`、`info`、`warning`（或 `warn`）、`error`；缺省为 `info`，其他取值拒绝启动。默认启用 `rotateDaily` 和 `gzip`：`access` / `error` 配置作为基础文件名，运行时写入 `access_YYYY-MM-DD.log` / `error_YYYY-MM-DD.log`，历史日志轮转后压缩为 `.gz`，`maxDays` 控制保留天数。不提供集中上传。
- `logDir`、`access`、`error` 和面板 `Name` 未配置时可使用显式缺省；显式空字符串属于错误配置，不能用默认值掩盖。
- 空闲 Worker 不再执行固定周期的内存回收；回收由真实负载变化、资源归还或最近到期事件驱动。周期资源日志与内存回收不是同一机制。
- WS 入站默认使用 `X-Forwarded-For` 的首个 IP 作为客户端地址；缺失或无效时保留 TCP 对端。`streamSettings.wsSettings.realIpHeader` 可指定其他头，设为 `""` 可关闭该行为。此头可被伪造：仅应通过可信代理访问源站，且代理必须覆盖客户端传入的同名头；当前程序不自行校验代理来源。通过 HTTP 头无法恢复客户端源端口，日志记为 `:0`。
- 面板 `dnsType` 会映射到 freedom outbound 的 `settings.domainStrategy`。
- 静态 outbound 的顶层 `sendThrough` 可填单个源 IP、`auto`，或按优先级排列的 IP/CIDR 数组；数组按顺序选首个同地址族条目：单个 IP 直接用，CIDR 从网段中生成一个地址；不检查接口地址或本地路由。CIDR 地址由 `sendThroughStrategy` 选择：默认 `random`，也可显式设 `ip_hash`（按最初入站客户端源 IP 哈希，不含端口）或 `user_hash`（按最初入站 `inbound_tag + user_id + email` 组合哈希，无用户标识时回退按最初客户端源 IP 哈希）。代理 outbound 顶层可设 `"passthrough": true`（默认 `false`），在向下一跳 cnode 节点发起请求或复用子流时透传最初入站的标签、用户身份与真实客户端 IP，供下游节点的 `ip_hash` / `user_hash` 使用。每个目标地址族仅选定一个源 IP：绑定或连接失败不更换同族源 IP，也不回退系统默认源 IP；只有完全没有同族条目才由系统选择。`settings.domainStrategy: "UseIPv6v4"` 下 IPv6 目标失败仍可尝试 IPv4 目标，IPv4 单独选源 IP；若目标已由路由预先解析为单个 IP，则不会重新查询另一地址族。UDP 域名逐包解析，建立 socket 前无法获知每包最终地址族；数组绑定依据请求初始目标地址族。原有字符串 `sendThrough` 行为不变。
- 未显式配置 `inboundTag` 的路由规则匹配所有入站；只有显式写出 `inboundTag` 时才限制入站来源。`network`、`inboundTag`、`user`、`source`、`protocol` 显式写成空字符串或空数组时拒绝启动，不按“匹配全部”解释。
- 启动时只加载路由规则实际引用的 geoip / geosite 分类（tag 大小写无关），之后所有 Worker 只读共享。`geoip.dat` / `geosite.dat` 缺失、截断或格式损坏，或引用的分类不存在、重复时拒绝启动；geosite 的 regexp 条目不加载。
- 静态 inbound 默认 `"routingEnabled": false`，不经过分流，直接走内置 `direct`（`sendThrough: "auto"` 源进源出）出口；仅当显式设置 `"routingEnabled": true` 且未指定 `outboundTag` 时参与 routing，未命中回落内置 `direct`；指定 `"outboundTag": "出口标签"` 时全部走该出口，不经过分流（即使规则可命中）。标签必须指向已配置或内置的静态 outbound；不存在或为空会拒绝启动。
- 面板创建的 direct outbound 是 routing 未命中时的 fallback，命中规则始终优先生效。
- 出口列表顺序不表达默认出口；动态增删 outbound 不会改变其他 receiver 的选择。明确的 forced / fallback tag 不存在时请求失败，不隐式切换到第一个 outbound。
- AnyTLS 使用 TLS session pool、单物理 session read loop、按 sid demux、共享 session 串行写，以及 `settings.clients` 和 `settings.paddingScheme` 配置。
- Hysteria v1 使用 ALPN `hysteria`，Hysteria2 使用 HTTP/3 `/auth` 后切换原生 QUIC stream；两代均支持 QUIC DATAGRAM UDP 与分片重组。按 Xray `transport/internet/hysteria` 的划分，QUIC、认证与流/数据报会话属于传输层，认证后每个 TCP 请求流与 UDP 会话作为逻辑传输流交给同一入站 Handler 与 `Inbound::Process`，连接级物理准入与连接统计在认证前完成。QUIC 与 TCP 一样由全部数据 Worker 以 `SO_REUSEPORT` 监听；未认证连接归接受它的 Worker，已认证会话在路径变化使数据包实际落到另一 Worker 且完成路径验证后被动接管，不跨 Worker 转发数据包（RFC 9000 §9、§10.3）。`ngtcp2`、`nghttp3` 及流队列借用当前 Worker PMR，监听入口共享收发循环和超时调度。`ngtcp2` 不提供 Hysteria v1 的 Brutal 拥塞控制，v1 服务端使用其 BBR v2 实现；线协议与官方 v1 客户端互通，但带宽控制行为不是 Brutal。
- Hysteria UDP 每轮未完成分片重组采用固定资源预算：5 秒没有有效新片，或达到 15 秒整体期限，即丢弃并释放该轮分片；有效进度只续空闲期限，不续整体期限。分片到期不会主动关闭健康的 UDP 会话或 QUIC 连接。这是本地资源限制，不是协议规定的时限。
- Hysteria UDP 下行按对端 QUIC DATAGRAM 帧上限与本地报文预算分片，每片携带完整地址。地址本身放不下或超过协议片数上限时，仅终止对应 UDP 请求，不关闭共享 QUIC 连接。

AnyTLS FIN 关闭整个逻辑流：远端 FIN 之前的已接收数据按有界队列排空，同时停止新的反向写入且不回复 FIN；本地关闭只发送一次 FIN。请求的两个方向结束后，完整且正常的物理会话可供新流复用；物理帧写入中断则关闭会话。第四十八轮已通过固定提交官方实现对照、双向直接互通和提前 FIN 检查，验证范围及当前环境限制见[架构审查记录](docs/architecture-review-20260909.md#第四十八轮anytls-完整关闭与-tls-取消传递)。
- REALITY 支持 TLS 1.3 + X25519 + Ed25519 临时证书签发与验证、服务端准入控制（`serverNames`、`shortIds`、`minClientVer`、`maxClientVer`、`maxTimeDiff`）、可选后量子 `mldsa65Seed` / `mldsa65Verify`（ML-DSA-65 证书扩展签名与验签）、未认证连接透明回落转发（`dest` + `xver` 0/1/2 PROXY Protocol v1/v2）、客户端 `fingerprint` 浏览器指纹模拟（`chrome`/`firefox`/`safari`/`ios`/`android`/`edge`/`360`/`qq`/`random`）、客户端 `spiderX` 回退路径访问，以及 V2Board 面板 `tls=2` REALITY 节点自动同步。握手阶段的认证状态与 transcript 缓冲在握手结束时立即释放，不随连接常驻；无读者的 `show`、`type`、`masterKeyLog` 字段会被配置加载器拒绝。
- REALITY 按实际到达字节增量重组跨记录 ClientHello，未认证回落保留原始线面字节；只在冷路径预计算可复用的证书部分，每次握手必要的认证／transcript 签名仍独立执行，临时密钥与缓冲在阶段结束后释放。DNS 名称比较接受末尾根点。
- REALITY 未认证回落按 Xray 留在传输层，但经公共拨号（`timeouts.dial`，默认 10 秒；域名 `dest` 与普通出站相同，存在 IPv4 记录时只拨 IPv4）与公共 relay 转发：沿用 `timeouts.connIdle`／`write`／`uplinkOnly`／`downlinkOnly`，字节计入 Worker 流量统计；PROXY 头与原始 ClientHello 仍作为首次写入一并发往 `dest`。回落连接在整个转发期间持有物理连接准入，不进入分发、路由或用户计费。

## 日志格式

控制台采用 [XrayR v25.3.6](https://github.com/XrayR-project/XrayR/blob/974abc9a98d8b64f7f0a7b7b3044140087a1bc4e/service/controller/controller.go) 的 logrus 文本风格，访问和错误文件采用 Xray 文本风格；三个通道不混用前缀。

**控制台**：显示启动、配置、面板状态、上报结果和资源统计。时间为带本地时区偏移的 RFC3339；面板记录附加真实 `Host`、`ID`、`Name`、`Type`，未知字段省略。`Host` 只保留 origin，不含 URL 用户信息、路径、query 或 fragment。

```text
time="2026-11-05T12:30:00+08:00" level=info msg="Panel status: state=ready inbound=ready protocol=vless port=443 network=tcp users=128 rules=12 pull=60s push=60s" Host="https://panel.example.com" ID=1041 Name=main Type=vless
```

**访问文件**：只记录访问事实，不带日志级别。`accepted` 的记录时机不变；认证、配额和策略拒绝使用 `rejected` 并说明实际原因。认证成功后，flow、设备限制与重放等拒绝保留已确认身份、已解析目标及 network；Mux 子流拒绝使用子流目标，不冒用父连接目标。`user:` 是已确认的数字 UID，`email:` 是已有用户标识，不用其冒充 UID；与 UID 完全相同的标识不重复输出。当入站收到上游 `passthrough` 透传元数据时，额外以 `|` 分隔记录最初入口的客户端 IP、入站标签与用户标识（`origin:<ip>|<tag>|<uid>|<email>`，与 UID 相同的标识同样不重复输出）。`sendThrough:` 只记录实际连接的本地地址。认证前不记录候选用户，尚无有效目标或出口时不填写虚构值。

```text
2026/11/05 12:30:01.123456 from 192.0.2.10:52000 accepted tcp:example.com:443 [vless-in -> direct] user:123 email:user@example.com sendThrough:198.51.100.2
2026/11/05 12:30:02.123456 from 192.0.2.10:52001 rejected authentication failed: no matching user [vless-in]
```

**错误文件**：保存受 `loglevel` 控制的诊断，时间精确到微秒。连接记录保留完整 64 位 ID、组件、已有路由与已确认 UID；不截断 Worker 位，不在正文重复 ID，也不为缺失上下文伪造 ID。认证失败与认证后的设备数、连接数或策略拒绝分别说明原因。

```text
2026/11/05 12:30:02.123456 [Warning] [4294967303] proxy/vless/inbound: [vless-in] authentication failed from 192.0.2.10:52001 > no matching user
```

控制台普通诊断同样遵守 `loglevel`，连接认证失败不刷控制台；面板警告与错误同时进入控制台和错误文件。常规控制台 Error 使用 stderr，其余级别使用 stdout；日志后端自身的故障、丢弃与恢复诊断走 stderr。`none` 不隐藏访问事实或致命启动失败。正常 EOF、取消和停机不输出对应 Warning/Error；已到达但未完成的 PROXY 头或加密握手仍按截断诊断，真正的密码学拒绝与超时分别记录。内存耗尽等 allocation-free 紧急退出保留最小 stderr 文本，避免错误路径再次分配。

控制台与文件日志使用独立有界异步输出；慢控制台读者不阻塞 DNS 或 Worker，停机不等待读者排空管道。访问／错误文件分别检测写入、刷新与关闭故障，失败和恢复经控制台报告，不连带停用另一通道；恢复由后续真实日志触发，不空闲轮询或伪造访问记录。队列容量、丢弃与恢复边界见[本地日志规范](docs/local_logging.md#4-文件和后端)。

日志统一转义换行、NUL、ESC 等控制字符，控制台消息同时转义引号与反斜杠；不记录认证 UUID、密码、认证摘要、密钥或原始认证包。HTTP 请求诊断只使用解析后的安全字段，去除 URL 用户信息、query 和 fragment；非法或歧义 URL 使用固定占位，不回显请求行的额外尾部、未经验证的版本或响应 reason phrase。面板 HTTP 失败不回显响应正文。依赖旧 `[Info]` 控制台前缀、秒级时间或低 32 位连接 ID 的采集规则需迁移，不保留旧格式旁路。

## 运行时状态

面板用户、静态用户和测试用户最终进入同一套认证存储模型。面板客户端只把原始响应解析为 `api::UserInfo`；Controller 只做字段归一化、差量对比和发布触发；协议私有凭据构建由 `proxy/<protocol>` 注册的 user builder 完成，输出统一的 `UserSet`。热路径 validator 只加载 `UserStore` 的不可变视图做认证。

V2Board 上报只包含实际用户流量与在线设备；不发送该 API 未实现的节点资源或违规命中报告，也不为这些空操作采集系统资源或维护命中历史。策略阻断仍在所属 Worker 的请求准入阶段执行，面板同步与状态心跳保持独立循环。

启动时，静态配置和测试模式先合并为同一组普通入站配置，统一校验主标签及监听端点，再通过协议注册入口准备全部 handler 配置和用户。准备阶段不改写用户存储或 Worker；全部准备成功后，一次发布完整的启动用户批次，再启动监听。批次构建失败不会发布部分用户更新。

传输配置归一化返回独立的新值，只有成功后才替换调用者持有的配置；分配失败可由冷路径捕获，不改写输入或终止进程。JSON 解析与传输模式、ALPN 的值转换分开实现。出站协议在注册配置的准备阶段完成归一化，各 Worker 的 handler 直接消费该结果。

TCP 连接启用 keepalive，空闲 60 秒后开始探测，以 10 秒间隔探测 6 次；不设置 `TCP_QUICKACK`（tcp(7) 规定该选项不持久，仅在设置时刻切换一次）。XHTTP 握手元数据只在请求缓冲有效期内借用；跨域会合仅传递拥有型身份元数据，持久 session 状态随会话组执行。

IP 目标、请求来源和访问日志共用数值地址文本转换：IPv4-mapped 地址按 IPv4 表示，IPv6 endpoint 使用方括号，非零 scope 保留所在平台的接口名或数字语义。临时 IP 文本只在栈上存在，不为格式化再申请普通堆字符串。

`--test` 仍提供 `test-vmess-10086` 入站；未配置面板和静态入站时也会启用该默认测试入站。它与普通静态入站使用相同的准备流程，同名标签或重叠监听会在 Worker 创建之前报错，不能通过追加测试入站覆盖已有配置。

生产环境只有一个主控 Worker，与主线程合并。面板、监控和 DNSWorker 共用主线程的 `io_context`；DNSWorker 不创建额外线程，独占 DNS service、缓存、在途查询、UDP socket 和 DNS 超时状态。数据 Worker 和面板持有 DNS 客户端，域名按值经有界 mailbox 投递，结果按值返回；数据 Worker 不持有 DNS live 状态。

`dns.servers` 中每项可以是裸 IPv4/IPv6（默认 UDP 53），或指定端口的 `127.0.0.1:5353`、`[::1]:5353`。IPv6 带端口时必须使用方括号，端口为 1–65535 的十进制整数；只接受 IP，不使用域名解析 DNS 服务器。配置加载时完成地址与端口拆分并发布完整 endpoint，主控线程上的 DNSWorker 按列表顺序使用；解析、默认值和平台字符串兼容不进入查询路径。

IP 字段必须是完整地址：IPv4 使用四段无前导零的十进制格式，IPv6 可使用数字 scope ID（如 `fe80::1%3`），不接受 `%eth0` 等接口名。`sendThrough` 数组项也可使用规范 CIDR。单独的 host、listen、sendThrough 等字段不接受端口、方括号、空白或 NUL 后缀。方括号仅用于支持 endpoint 或 URL 的入口，且括号内必须是 IPv6；出站服务器字段也可以使用合法 DNS 主机名。旧版在部分平台上接受的地址简写或多余后缀不再兼容。

连接超时和会话池空闲检查由所属执行域的 TimeoutScheduler 汇聚；原生等待结束后才释放调度器与域。事件嵌入宿主，取消不保留失效节点。限速、Mux 背压和 accept 退避使用可取消等待；协议协程继承当前域 executor，native reactor 不能直接执行用户回调或访问域私有池。

DNSWorker 将多个调用者的并发同域查询合并为一次服务级解析，每个调用者独立等待、独立取消；首个调用者取消不会终止其他等待者的查询。最后一个等待者退出后取消无用查询，已取消但尚未收束的查询仍占准入容量；停机等待全部查询完成清理。每个上游复用一个 UDP socket，三次 A 地址采样与 AAAA 查询并发执行，仍保留多地址合并与按顺序切换上游的语义。主控线程只有一层 DNS 缓存；缓存写入分配失败不会丢失已经取得的答案，缓存在完整构建新条目后才淘汰旧条目。

DNS 缓存默认容量为 `dns.cacheSize: 10240`，设置为 `0` 可禁用；`minTTL` / `maxTTL` 默认分别为 60 / 3600 秒。仅成功地址结果与无记录结果进入缓存，超时、SERVFAIL、REFUSED 等临时失败不缓存。零 TTL 地址结果只用于本次解析，不受 `minTTL` 延长；接收到最高位置位的 TTL 时整体按零处理，仍保留本次可用地址。A / AAAA 数据长度错误属于 `DNS_FORMAT_ERROR`，不伪装成无记录结果，按既有上游失败策略尝试备用服务器。

共享上游查询最终失败时，在 `warning` 级别向 error 日志记录一次域名、错误码、`source=upstream`、最后使用的上游地址／端口及 A、AAAA 查询原因。`NXDOMAIN` 表示域名不存在，`NODATA` 表示响应没有所需地址记录；仅含不支持的记录、服务失败、拒绝、超时与畸形响应分别保留具体原因。负缓存命中保留原始原因而不逐连接刷 Warning；在到期、刷新、恢复、淘汰或停机时以 `info` 汇总 `event`、`hits`、`suppressed` 和原始原因，计数只包含负缓存命中，不包含共享查询等待者。过期条目不再提供答案，仅保留受缓存容量约束的恢复元数据；`cacheSize: 0` 不保留该状态。每条连接的访问拒绝记录仍保留。只要 A 或 AAAA 提供可用地址，解析仍成功；正常取消不记录成解析故障，真实系统异常不伪装成 DNS 无记录错误。

无锁设计的前提是唯一执行租约，而非连接终身固定在接入线程。listener slot 与原生 UDP 监听仍由原 Worker 独占；可迁移宿主、stats shard、allocator 与 buffer provider 只能在所属会话组的租约内访问。跨线程只投递有界元数据／就绪通知或发布只读快照，不共享可并发修改的 live handler。

控制面批量任务在所有已启动的子任务结束后才返回。取消和部分启动失败遵守同一完成边界，避免子任务继续访问已经销毁的聚合结果或调用者状态。

Dispatcher 通过实际读端的取消来源管理完整请求，覆盖嗅探、路由 DNS、出站连接和握手，以及 relay。已停止的请求不再选择出站；取消后等待请求清理完成，再释放负载计数和记录终态。逻辑子流无需持有物理控制端即可取消自己的请求；正常 relay 收尾不改变已完成结果，嗅探的内存不足及逻辑链路错误保留原分类。

运行状态采样和统计输出是独立的常驻监控循环。每个循环持有自己的上下文，异常退出时立即记录循环名称及原因；停机取消不计为故障。停机时取消所有循环并等待其实际完成，不自动重启已经停止的循环。

每个面板的同步与状态输出分别运行独立循环，异常退出时记录面板名称、节点 ID 与循环职责。状态循环启动时输出一次，之后按稳态时钟每 60 秒读取最后提交的节点状态；网络请求的等待不会阻塞心跳，错过的周期不补发日志。同步循环继续按面板下发间隔拉取和推送，首次推送延后一个完整间隔。停机停止新同步并取消在途等待，等待已启动的任务收束；未完成的节点清理不会被标记为成功。

Mux 和 AnyTLS 的帧循环及子请求由所属执行域的有限任务组持有，Mux 后台读取也在该组内。会话退出先终止逻辑读端并取消任务，覆盖尚未进入 relay 的等待；全部协程完成后才释放会话、transport 和在线租约。父任务取消与部分启动失败遵守同一顺序。正常逻辑 FIN 排空已接收数据，子请求仍经过 Dispatcher、outbound 和 relay。

Mux 每条连接最多同时承载 1,024 个子会话（高于 Xray 客户端单条连接可承载的会话数），重复或超额的 NEW 帧收到带错误标志的 END。所有子会话尚未被转发的客户端数据共享一个预算：达到 4 MiB 时暂停解析后续客户端帧，降至 2 MiB 后恢复；单个子会话不另设上限，停滞的子会话会使同连接的其他子会话一并等待，直到它被消费或因超时结束（与 Xray 的队头阻塞语义相同）。子会话映射项只在其分发结束后移除，同一 sid 在此之前的 NEW 按重复处理。拒绝或结束子会话所需的 END 写入失败时，整条 Mux 连接立即关闭。

AnyTLS 每个 Session 的新 stream ID 必须严格递增且非零，允许跳号；活动 ID、已经结束的 ID 和回绕后的 ID 均不能重用。非法 SYN 会收到 Alert 并结束该会话，SYN 本身不能携带数据。每条子流独立持有请求上下文，其任务从逻辑字节流解析目标和 UoT 请求，支持地址跨 PSH 以及地址与首包同帧；剩余数据转交统一首包或 UoT reader，保持字节及 UDP 包边界。帧循环仅处理控制和分发，等待数据时保留子流所有权。单条请求的地址无效或不完整只结束该子流。

AnyTLS 出站处理开流写入期间提前到达的 FIN：正常关闭立即交由 Relay 排空已接收数据，并允许后续请求复用健康连接；已经发生的关闭或错误不会重新等待 SYNACK 而误报超时。开流等待的定时器随该次操作回收，错误 SYNACK 文本被截断时保留实际连接关闭原因。

AnyTLS 入站每个 Session 最多同时接纳 128 条未结束子流，包含等待地址的子流和正在转发的请求。这是 cnode 的资源预算，超额新流收到 FIN，v2 同时收到带错误信息的 SYNACK；原有流继续使用，已拒绝 ID 不能重用。子流从 SYN 起使用 `timeouts.handshake`（默认 60 秒）作为绝对握手期限，覆盖目标地址、UoT 初始请求及 SYNACK 写入，心跳或逐字节发送不会续期。正常握手完成后移除该期限，后续请求按 Dispatcher 和 relay 的超时处理。超时通常只结束该子流；若已经开始的物理帧写入被中断，则关闭整个会话以保护帧边界。静态与面板入站使用同一处理规则。

AnyTLS 入站和出站每条子流的接收队列最多保留 65,535 字节有效数据，并合并小片段，使排队数据块的容量不超过 128 KiB。两端满队列时均暂停物理读取，等待消费者释放空间；慢客户端仍可接收完整大响应，取消和超时会终止等待。两端共用私有的字节聚合逻辑，完整大块直接转移所有权，UoT 解码继续负责 UDP 包边界。远端正常 FIN 会排空此前收到的数据，本地主动关闭和错误关闭立即丢弃未读数据。该上限只描述排队数据块，物理帧读取、正在消费的数据及其他会话状态另计。

AnyTLS 入站和出站共用协议私有的 settings 解析，按完整 `v` 字段协商；未声明版本时使用 v1 能力，未来版本只启用本地已支持的功能。v1 会话不发送 SYNACK 或心跳，v2 会话启用 ServerSettings、SYNACK 和心跳；出站收到服务器声明之前保持 v1 行为。重复 settings、非法版本或方向不符的控制帧会结束会话，已建立请求不会被后来的设置改写。客户端标识为 `client=cnode`。

AnyTLS 池的跨请求物理读取任务由独立池宿主的常驻任务组持有，不借用某条请求的栈、上下文或短物理宿主。坏会话立即从可借池摘除并关闭，后台清理仍由池 owner 跟踪。Worker 停机先收束全部请求，再取消并 join 池任务、释放 handler 与域调度器，最后释放域根；物理入站退出不会提前销毁健康池。

AnyTLS 编解码保留内存不足及逻辑链路错误，由拥有请求或物理会话的边界处理；只有真实系统 I/O 错误才按 socket 原因映射。已开始的物理帧写入异常会关闭会话，后续请求重新连接；出站物理读取在帧负载中途失败时同样关闭整个会话，而非只结束对应子流。子流即使已从会话索引移除，仍通过自己持有的请求上下文记录失败。

AnyTLS 填充方案按实际规则数保存，大报文索引不会创建中间空槽。索引及 `stop` 使用完整的无符号 32 位范围，`stop` 必须大于零，只有小于它的已配置索引生效。默认方案与入站配置在准备后共享只读对象，原始文本及其 MD5 保持一致；出站收到合法更新后替换方案，在途写入继续持有原方案。包序号不会回绕到认证索引 0，达到 `stop` 后停止填充，无效更新保留原方案。入站配置的方案须能装入单个更新帧：字符串或数组归一化后的 UTF-8 文本最多 65,535 字节，数组元素之间的换行也计入长度，超限在准备配置时拒绝。

每个原准入 Worker／配置／出站 tag 的 AnyTLS 池独立保存服务器下发的填充方案；物理连接断开后，该池的新连接继续使用它。不同出站即使连接相同端点也不共享方案。认证、首次 settings 摘要和首次帧写入使用同一快照；配置被替换后新池从默认方案开始，旧在途请求不被改写。认证填充按实际长度临时构建，支持完整 16 位长度，认证结束即释放。

认证索引 `0` 独立于会话帧规则，只接受单个长度范围；缺少索引 `0` 或显式 `0=0-0` 时不发送认证填充，`stop=1` 可表示完全不填充的方案。正数范围按 `[较小值, 较大值)` 采样，两端相等时使用固定长度。所有可能的认证长度必须在 0～65,535 之间，例如 `0=65535-65536` 有效；零与非零混合范围、溢出、`c`、多个范围及格式错误会使整个方案无效。认证规则不会作为会话帧规则使用，默认的 30 字节来自显式默认方案，不作为解析失败后的回退。静态配置在准备阶段拒绝无效方案，远端无效更新保留当前方案。

会话填充分段尺寸独立于内部 Buffer 容量，支持 1～65,535 字节，包括跨帧头的小分段和大于 8,192 字节的填充。每个有效范围的全部采样结果都必须满足 16 位 Waste 长度容量；可能超限的范围会使整个方案在编译时失败，不能通过后续重复项或 `c` 标记绕过。纯数据分段直接引用本次数据，Waste 在临时写入缓冲中生成，不使用固定大小的零填充块。分段尺寸表示协议写入策略，TLS 仍可根据记录层限制继续拆分。

每个单节点面板对象在加入控制面前完整构造，直接拥有客户端、只读配置、连接状态、已提交节点快照和统计。用户数从已提交用户快照读取；配置与身份来自同一个归一化入口，不再通过客户端反查或多张关联表补齐。入站、出站和 TLS 构建都要求明确的面板配置。

面板节点的资源标签使用 `panel/{Name}/{NodeID}/{protocol}/{port}`，同一面板下不同节点的用户、handler 和清理目标相互独立。这替换了旧的 `{Name}-{protocol}-{port}` 格式，引用旧入站标签的路由匹配或日志筛选需要同步迁移；不保留旧标签别名。静态入站主 tag 和静态出站 tag 不得使用 `panel/` 前缀。

面板流量统计使用不含协议和端口的稳定节点身份。端口更新前仍在途的请求继续归属原节点，不会因资源 tag 退役而丢失统计；静态入站不创建无人上报的按节点流量表。会话关闭仅提交预先准备的计数，不在析构路径申请统计节点。

流量增量先持久化到 `<配置目录>/traffic-journal/<身份哈希>/`，成功后才从 Worker 提交对应快照，期间新产生的流量留待下一批。磁盘操作在有界阻塞执行器中进行，不阻塞数据 Worker；每个身份最多保留 1,024 条、64 MiB 记录，达到上限时保留未提交计数并明确报错。目录身份区分面板名称、APIHost、协议和节点 ID，不保存 API key。

V2Board 上报是无幂等键的增量接口，不能承诺 exactly-once。发送前记录转为 `unknown`；仅完整 HTTP 200 后清除。非 200、响应截断、连接中断或发送中崩溃都不能证明面板未入账，`unknown` 不自动重发。HTTP 200 也只证明接口接受了请求，不证明面板异步账务已最终提交。正常停止会持久化最终采样；SIGKILL 前尚未采样的内存计数不具备耐久性。

停机后根据面板侧账务证据逐批对账；确认已应用则删除未知批次，确认未应用才重新置为可发送。工具使用独占锁并持久化审计记录，不能仅凭超时判断“未应用”：

```sh
mise exec -- cmake --build build/musl --target cnode_traffic_journal
build/musl/cnode_traffic_journal '/path/to/traffic-journal/<身份哈希>' list
build/musl/cnode_traffic_journal '/path/to/traffic-journal/<身份哈希>' resolve batch-XXXXXX.unknown \
  --decision confirmed-applied --evidence '面板侧对账记录编号'
```

确认未入账时将 `--decision` 改为 `confirmed-not-applied`，下次启动允许该批次重新发送。

不同入站不能占用重叠的监听端点。相同端口、相同地址族下，通配地址与具体地址也视为冲突；IPv4 和 v6-only IPv6 可以分开监听，auto 模式保留两个地址族的请求范围。控制面在投递 Worker 前检查其他面板节点，包括更新中和等待清理的旧/候选端点；Worker 另外检查 TCP、UDP 各自的监听归属，防止与静态入站冲突。冲突会使本次节点更新失败，原监听继续服务。

节点变更由私有事务编排，具体 Worker 操作集中在 NodeRuntime。最后提交的快照以共享只读指针持有，运行态另行记录停止、就绪、变更中或需要恢复。候选快照和回滚凭据在变更前准备，全部运行操作成功后才发布。回滚不完整时保留旧节点及候选节点的清理目标；下一轮先完成本地清理，再拉取并重建，避免相同配置被误当作普通刷新，也避免遗留候选资源依赖面板网络恢复才能释放。

多个面板节点的变更通过启动时固定的有界等待槽按 FIFO 准入，每个节点最多一个在途申请。首次同步不会因为另一个节点正在提交而被丢弃并推迟到下一次拉取；未完成回滚的节点先恢复，其他节点随后继续，停机唤醒全部等待者。

面板 HTTPS 使用系统 CA 校验证书与主机名，支持 TLS 1.3，最低接受 TLS 1.2。面板 HTTP 请求可在连接或 TLS 握手失败时尝试下一个 DNS 地址。开始发送请求后，写入或响应失败直接报告本次失败，不跨地址重发，避免重复提交流量增量。

面板接口异常（包括配置或用户接口返回 `404`、其他 HTTP 错误、超时和无效响应）时，保留最后成功的节点配置与用户。含重复键或嵌套超过 128 层的 JSON、用户列表中重复的 `id`、节点配置中无法识别的 `tls` 取值或类型错误的字段、`base_config` 中非整数的拉取/推送间隔，含控制字符的 `ETag`，以及分帧不明确的响应（同时带 `Transfer-Encoding` 与 `Content-Length`、HTTP/1.0 响应带 `Transfer-Encoding`、传输编码不是唯一的 `chunked`）均视为无效响应；`1xx` 中间响应会被跳过，`304`/`204` 在头部结束即完成，不等待 `Content-Length` 声明的正文。同一入站的多个用户经协议派生出相同凭据（如仅大小写或连字符不同的 UUID、相同的 Trojan/AnyTLS 密码）时，本次用户更新整体失败并保留旧用户；静态入站出现这种用户时拒绝启动。只有用户接口成功返回合法的空用户列表时才清空该节点用户。面板恢复后继续同步；配置、规则和用户验证器仅随成功提交的节点快照确认，未完成的候选会继续携带旧验证器重试。

面板策略中的任一正则非法时整份候选失败，不跳过坏规则或确认新 ETag；初始无合法快照时不启动监听。外部节点字段 `cipher`／`server_key` 的缺失或 `null` 按其可选语义处理，不与非法类型混淆。

面板配置的 `RequestTimeout` 以秒为单位，默认 `30`，只接受 `1` 至 `3600` 的整数。每次 HTTP 请求共用一个时限，覆盖 DNS 等待、连接、TLS 握手、发送和响应读取；超时会取消请求并等待资源释放，再报告本次失败。完整收到响应后，TLS 关闭握手最多额外占用剩余请求时间中的 1 秒，关闭失败或取消不会丢弃已经收到的响应。

运行时接管后，收到停机信号先关闭新请求与连接准入、取消控制面网络和监控，再收束请求并持久化最终流量；随后 join 独立池任务、清除已完成协程的取消槽、释放所有域根和服务，Finalize 最后停止预留返回通知。原生 reactor 的 work guard 保持到这一步之后，避免在途完成通知丢失；最后 join 数据线程。持久化临界区的取消屏蔽不能扩散到后续 HTTP 请求。不等待代理流量自然排空。启动、线程创建或事件循环故障走同一收束流程但返回失败，取消不掩盖原始错误。

## 代码组织

```text
include/               公共 API 和窄接口
src/app/              Worker、dispatcher、router、proxyman、stats、bootstrap
src/proxy/            协议实现
src/transport/        传输层实现
src/service/          控制面 controller
src/api/              面板 API client
src/infra/            配置、JSON、日志、校验
src/common/           通用类型、buffer、allocator、session、mux
src/geo/              geoip / geosite 数据读取
src/sniff/            HTTP / TLS / QUIC sniffing
config/               示例配置
scripts/              部署与更新脚本
```

公共头直接使用 `common/...`、`transport/...` 等路径；命名空间按职责划分，不再套项目根命名空间。

协议、面板和路由各自位于独立边界，通过统一请求链路及只读运行时配置协作。

## 构建兼容性

- x86-64 构建启用 BLAKE3 运行时 SIMD 分派并保留 portable 回退，不要求部署机器与构建机器具有相同指令集。
