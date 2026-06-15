# cnode

cnode 是面向 V2Board 面板的高性能代理节点服务端。项目以 C++23、Asio 协程和 Worker-local 资源模型实现，目标是在保持 xray-core 配置语义的同时，把面板同步、配置归一化、协议处理和流量转发拆成清晰的职责边界。

## 项目定位

- 支持 VMess、Trojan、Shadowsocks、AnyTLS、Freedom、Blackhole。
- 支持 TCP、TLS、WebSocket、PROXY protocol 和 UDP-over-TCP 等传输形态。
- 支持单进程接入多个 V2Board 面板和多个节点。
- 支持 geoip、geosite、域名、IP、端口、协议、用户等路由条件。
- 默认按多 Worker 运行，每个 Worker 持有自己的事件循环和热路径资源。
- 部署脚本 `scripts/cnode.sh` 不带参数时只更新线上二进制；`-debug_file true` 会额外下载匹配的 `.debug` 符号文件。

## 总体架构

所有 TCP 和 UDP 请求都必须进入同一条数据链路：

```text
inbound.Process
  -> dispatcher.Dispatch
  -> outbound.Process
  -> relay
```

运行时主链路：

```text
main
  -> bootstrap
  -> Worker(per-core)
  -> listener / accept
  -> TransportStack(TCP / TLS / WebSocket / PROXY protocol)
  -> InboundHandler(VMess / Trojan / Shadowsocks / AnyTLS)
  -> Dispatcher
  -> Router
  -> OutboundHandler(Freedom / VMess / Trojan / Shadowsocks / AnyTLS / Blackhole)
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

## 模块职责

- `proxy/<protocol>` 只负责协议认证、解析、编码、握手和协议私有 helper。
- `app/dispatcher` 负责从入站 session metadata 进入路由和出站选择，不能包含协议特判。
- `app/router` 只做路由决策，输入归一化 metadata，输出 outbound tag。
- `app/proxyman` 负责 prepared inbound/outbound handler 的构建和持有。
- `transport/internet` 只负责 TCP、TLS、WebSocket、PROXY protocol、dialer 和 transport stack。
- `app/relay` 与 `common/mux` 只搬运已经准备好的数据，不解析协议，不选择路由。
- `service/controller` 与 `api/*` 只属于控制面，负责面板同步、用户/节点/规则拉取和流量上报。
- `infra` 负责日志、JSON、配置加载、配置校验和冷路径归一化。
- `common/buf`、`common/allocator`、`app/worker*` 共同维护 Worker-local buffer、统计和运行时资源边界。

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

配置进入 Worker 前必须完成归一化。Worker 热路径只读取不可变 runtime snapshot；控制面更新时以原子替换快照的方式发布，新旧连接按生命周期自然释放。

## 关键语义

- `ProxyProtocol` 是 cnode 自有三态设置：`"off"`、`"auto"`、`"on"`。省略 `ProxyProtocol` 时默认使用 `"auto"`。
- `SendIP: "auto"` 表示 direct outbound 优先绑定入站连接命中的本地 IP，用于多 IP 服务器源进源出。
- `EnableDNS` 默认值为 `true`。
- 面板 `DNSType` 会映射到 freedom outbound 的 `settings.domainStrategy`，取值对齐 xray-core freedom outbound。
- 未显式配置 `inboundTag` 的路由规则匹配所有入站；只有显式写出 `inboundTag` 时才限制入站来源。
- 面板创建的 direct outbound 是 routing 未命中时的 fallback，命中规则始终优先生效。
- AnyTLS 按 xray-core wire model 实现：TLS session pool、单物理 session read loop、按 sid demux、共享 session 串行写、`settings.users` 和 `settings.paddingScheme` 语义。

## 开发规范

- 先分析现有代码和配置，再决定修改方式。
- 新代码优先沿用现有目录、命名、RAII、协程和错误处理风格。
- 冷路径可以使用 factory、builder、registry、JSON 解析和兼容归一化。
- 热路径只消费预构建结构，避免 JSON 解析、面板字段判断、临时协议分支、重复分配和重复拷贝。
- 公共头文件保持窄接口，避免传播运行时存储、完整配置类型、协议私有 helper 或 umbrella 依赖。
- 协议实现统一暴露 `Handler::Process` 风格入口，reader、writer、codec、crypto helper 留在协议私有实现内。
- MultiBuffer / Buffer 必须保持清晰所有权，move 即转移所有权，消费后及时归还或释放。
- 统计由统一 stats / traffic 层聚合；relay 可以打点，但不能理解面板或协议私有细节。

## 开发约束

- Worker 不直接理解协议 validator、outbound 具体类型或 panel 字段。
- Dispatcher 不 include 具体协议，不直接执行 relay，不读取 panel 配置。
- Router 不创建连接，不访问 relay，不依赖 proxyman 具体实现。
- Relay 不解析 VMess、Trojan、Shadowsocks、AnyTLS，也不选择 outbound。
- Panel/client/controller 不进入热路径，不修改 live handler 内部状态。
- 出站处理不能读取面板原始字段；所有字段必须在冷路径归一化。
- 配置热更新只能替换 runtime snapshot，不能原地修改正在使用的对象图。
- 禁止把 legacy、compat、adapter、wrapper、old 或旧面板私有命名作为最终公开设计保留。
- 禁止协议、transport、relay、panel 各自维护长期私有大 buffer pool。
- 禁止为了局部方便绕过 `inbound.Process -> dispatcher.Dispatch -> outbound.Process -> relay` 主链路。

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
config/               示例配置
scripts/              部署与更新脚本
```

仓库结构应表达最终职责，而不是表达迁移历史。删除或替换一个协议时，不应影响 dispatcher、router、relay、Worker 的结构；替换面板实现时，不应影响协议热路径；替换路由规则时，不应影响 inbound/outbound 协议实现。
