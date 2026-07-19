# cnode

cnode 是面向 V2Board 面板的高性能代理节点服务端。项目使用 C++23、Asio 协程和 Worker-local 资源模型实现，在保留 xray-core 配置语义的同时，把面板同步、配置归一化、协议处理和流量转发拆成清晰的运行边界。

## 文档分工

- `README.md` 面向使用者和贡献者，说明项目定位、运行架构、配置入口、关键语义和代码组织。
- `AGENTS.md` 面向代码修改和自动化协作者，记录必须遵守的职责边界、禁止项、审查清单和硬性删除规则。
- [`docs/centralized_access_logging.md`](docs/centralized_access_logging.md) 记录集中访问日志、面板节点身份、上报协议和 ClickHouse 存储设计。
- [`docs/local_logging.md`](docs/local_logging.md) 规定对齐 xray-core 的 error/access 文本格式、通道和级别口径。

如果只是部署、配置或了解项目，从本文件开始；如果要改代码、做重构或接入新协议/面板，先读 `AGENTS.md`。

## 项目定位

- 支持 VMess、VLESS、Trojan、Shadowsocks、AnyTLS、Freedom、Blackhole。
- 支持 TCP、TLS、WebSocket、PROXY protocol、原生 datagram、UDP-over-TCP 和 Mux/子流。
- 支持单进程接入多个 V2Board 面板和多个节点。
- 支持 geoip、geosite、域名、IP、端口、协议、用户等路由条件。
- 默认按多 Worker 运行，每个 Worker 持有自己的事件循环和热路径资源。
- 部署脚本 `scripts/cnode.sh` 不带参数时只更新默认线上二进制；`-variant <name>` 可选择 release 变体，`-debug_file true` 会额外下载匹配的 `.debug` 符号文件。

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
  -> Dispatcher
  -> Router
  -> OutboundHandler(Freedom / VMess / VLESS / Trojan / Shadowsocks / AnyTLS / Blackhole)
  -> Relay(TCP / UDP / Mux)
```

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
| dispatcher | 接收 session / context / link，调用 router，选择 outbound handler，调用 outbound.Process | 解析协议、创建协议专属对象、协议特判、执行 relay、读取 panel 字段 |
| router | 基于归一化 metadata 输出 outbound tag / route decision | 创建连接、访问 relay、访问协议实现、理解 Worker 资源 |
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
- TCP scatter-read 固定最多使用 4 个 8KB Buffer，不按连接压力动态降档。
- V2Board Shadowsocks 2022 节点会自动使用面板下发的 `server_key` 作为 identity PSK，并按 V2Board 规则从用户 UUID 前缀构造用户 PSK；无需把订阅中的两段式密码回填到用户表。
- Shadowsocks 和 AnyTLS inbound 会自动识别 UoT v2（`sp.v2.udp-over-tcp.arpa`）及 v1（`sp.udp-over-tcp.arpa`）。Shadowsocks outbound 可用 `"uot": true` 开启 UoT（默认 v2），以 `"uotVersion": 1` 选择 v1；也接受 `"udp_over_tcp": {"enabled": true, "version": 2}`。
- 本地日志对齐 xray-core：`error` 保存受 `loglevel` 控制的诊断与错误，`access` 保存无级别的访问事实。默认启用 `rotateDaily` 和 `gzip`：`access` / `error` 配置作为基础文件名，运行时写入 `access_YYYY-MM-DD.log` / `error_YYYY-MM-DD.log`，历史日志轮转后压缩为 `.gz`，`maxDays` 控制保留天数。
- 面板 `DNSType` 会映射到 freedom outbound 的 `settings.domainStrategy`，取值对齐 xray-core freedom outbound。
- 未显式配置 `inboundTag` 的路由规则匹配所有入站；只有显式写出 `inboundTag` 时才限制入站来源。
- 静态 inbound 默认不参与 routing，固定走内置 `direct`；只有配置 `"routingEnabled": true` 时才参与 routing，未命中仍回落 `direct`。静态 inbound 不使用 `outbound` 或 `outboundTag` 选择出口。
- 面板创建的 direct outbound 是 routing 未命中时的 fallback，命中规则始终优先生效。
- AnyTLS 按 xray-core wire model 实现：TLS session pool、单物理 session read loop、按 sid demux、共享 session 串行写、`settings.users` 和 `settings.paddingScheme` 语义。
- REALITY 当前只实现原生 TLS 1.3 + Ed25519 认证握手，不实现未认证连接的 `dest` / `target` 回落、uTLS `fingerprint` 模拟、`spiderX` 爬虫或 ML-DSA-65 证书附加签名/验证；配置这些字段或启用非零 `xver` 会在启动时明确拒绝。

## 运行时状态

面板用户、静态用户和测试用户最终进入同一套认证存储模型。面板客户端只把原始响应解析为 `api::UserInfo`；Controller 只做字段归一化、差量对比和发布触发；协议私有凭据构建由 `proxy/<protocol>` 注册的 user builder 完成，输出统一的 `UserSet`。热路径 validator 只加载 `UserStore` 的不可变视图做认证。

DNS service 不是全局共享对象。每个 Worker 持有绑定自身 `io_context` 的 DNS service、inflight resolve 表、UDP socket、timeout scheduler 和 L1 cache。进程级 `GlobalDnsCache` 只保存 DNS 结果的不可变分片快照，热路径只做 atomic load 和只读查询。

Worker-local 无锁设计的前提是单 Worker 所有权。Worker 私有 manager、handler 表、listener slot、UDP session、stats shard、allocator 和 buffer provider 只能在所属 Worker 线程访问；跨线程控制面必须通过投递、不可变 snapshot 或明确同步的冷路径完成。

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
