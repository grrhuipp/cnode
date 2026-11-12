# cnode

cnode 是面向 V2Board 面板的高性能 Linux 代理节点服务端。项目使用 C++20 协程与无共享（Share-Nothing）同构 Worker 架构，将面板同步、配置归一化、协议处理和流量转发拆成清晰的运行边界。

## 文档分工

- `README.md` 面向使用者，说明项目定位、构建、配置、部署、日志格式和对使用者可见的运行语义；本地日志文本格式由本文件[日志格式](#日志格式)一节维护。
- [`AGENTS.md`](AGENTS.md) 面向代码修改和自动化协作者，记录分层职责、禁止项、审查清单和删除规则。
- [`docs/local_logging.md`](docs/local_logging.md) 说明本地 error/access/console 通道的语义、级别口径与后端行为。

如果只是部署、配置或了解项目，从本文件开始；如果要改代码、做重构或接入新协议/面板，先读 `AGENTS.md`。

## 项目定位

- 支持 VMess、VLESS、Trojan、Shadowsocks、AnyTLS、Hysteria、Hysteria2、Freedom、Blackhole。
- 支持 TCP、TLS、REALITY、WebSocket、HTTPUpgrade、gRPC、XHTTP、PROXY protocol、QUIC、原生 datagram、UDP-over-TCP 和 Mux/子流。
- 支持单进程接入多个 V2Board 面板和多个节点。
- 支持 geoip、geosite、域名、IP、端口、协议、用户等路由条件。
- 默认按多数据 Worker 运行；各数据 Worker 同构，通过 `SO_REUSEPORT` 分别拥有监听和转发资源。

## 构建与测试

仅构建 Linux x86-64 musl 全静态程序，使用 C++20。自有编译与测试规则集中在根 `CMakeLists.txt`；`mise.toml` 管理 CMake、Ninja、ccache 和带 SHA256 校验的 LLVM musl 工具链。依赖和 overlay 入口统一放在 `vcpkg.json`，不设版本基线或固定版本覆盖：`mise run bootstrap`（`configure` 前自动执行）把 `build/vcpkg` 更新到上游最新提交，依赖使用其中的最新端口；设置 `CNODE_VCPKG_COMMIT` 可改用指定提交。BoringSSL 提供 TLS/QUIC 密码实现，overlay 保留 REALITY 与 VMess 所需接口补丁。`cmake/` 仅保留 vcpkg 配方、补丁、triplet 和 musl 工具链。

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

单元与 E2E 测试均使用 C++ GoogleTest，由 CTest 调度。测试必须显式启用：

```sh
mise run test
```

`mise run test` 构建 `cnode_tests` 并运行 CTest。功能测试分为 `unit` 和 `e2e` 标签；需要分步操作时：

```sh
mise run test:configure
mise exec -- cmake --build build/musl --target cnode_tests
mise exec -- ctest --test-dir build/musl --output-on-failure --no-tests=error --parallel -L '^unit$'
mise exec -- ctest --test-dir build/musl --output-on-failure --no-tests=error --parallel -L '^e2e$'
```

主程序与测试共用 `build/musl`。若只需要某个测试，可显式构建其 `cnode_*_test` 目标，再用 `mise exec -- ctest --test-dir build/musl --output-on-failure --no-tests=error -R <名称>` 执行。切回 `mise run build` 会关闭测试注册。可选 io_uring 后端通过 `mise run configure -- -DCNODE_IO_URING=ON` 配置，再执行 `mise exec -- cmake --build build/musl --target cnode`；官方发布仅提供 epoll。

性能基准默认关闭，显式开启后通过独立的 `cnode_benchmarks` 目标和 CTest `benchmark` 标签运行；各基准的测量范围与口径见对应 `tests/*_benchmark.cpp`、`tests/e2e/*_benchmark.cpp` 文件头注释。真实进程基准可用 `CNODE_BENCHMARK_BINARY=/absolute/path/to/cnode` 指定待测二进制。启用基准时，功能回归使用 `-L '^(unit|e2e)$'`。

```sh
mise run test:configure -- -DBUILD_BENCHMARKS=ON
mise exec -- cmake --build build/musl --target cnode_benchmarks
mise exec -- ctest --test-dir build/musl --no-tests=error -L '^benchmark$' -V
```

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

Xray 使用 `-DCNODE_REFERENCE_XRAY=/path/to/xray`，要求 `v26.10.31` 对应版本；Hysteria v1/v2 分别使用 `CNODE_REFERENCE_HYSTERIA1`、`CNODE_REFERENCE_HYSTERIA2`，可独立配置。Hysteria 支持带干净版本元数据的源码构建，以及按精确 SHA256 固定的[官方 v2.13.0 Linux amd64 发布文件](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.13.0)。参考测试通过 `CNODE_REFERENCE_GO` 检查来源和构建元数据；AnyTLS 必须同时提供客户端与服务端。不配置参考程序时只注册本地可控对端 E2E，不把缺失参考程序计为测试通过。例如只跑 HY2 参考测试：

```sh
mise run test:configure -- \
  -DCNODE_REFERENCE_GO="$(command -v go)" \
  -DCNODE_REFERENCE_HYSTERIA2=/path/to/hysteria
mise exec -- cmake --build build/musl --target cnode_e2e_reference_hysteria
mise exec -- ctest --test-dir build/musl --no-tests=error \
  -R '^e2e\.reference_hysteria\..*/V2_' -V
```

本地与 CI 使用同一份 mise 固定工具链和配置入口，均为 `Release`；vcpkg 跟随上游最新提交，CI 每次运行先解析一次最新提交，再供引导与缓存键共用。本地默认关闭 LTO（`CNODE_ENABLE_LTO=OFF`），仅 CI 开启 LTO（`-DCNODE_ENABLE_LTO=ON`）；测试配置统一运行 `mise run test:configure`。宿主发行版无需相同，不要求容器。CTest 使用不指定数量的 `--parallel`，按可用 CPU 自动调度。

CI 只对源码、测试、构建配置变更自动运行，纯文档和部署脚本变更不触发编译；也可手动运行。不设置工作流级并发分组，不同提交可同时运行。`build` job 复用同一构建树，`verify` 步骤统一执行单元、E2E 与静态 ELF 检查。vcpkg 缓存按 vcpkg 提交与依赖配置保存、ccache 按提交增量保存，两者在对应阶段成功后立即保存，不因后续测试失败丢失。仅分支 push 在验证通过后打包，`release` job 的 `publish` 步骤下载并发布产物；PR 和手动运行只验证。

## 架构总览

所有 TCP / UDP 请求经过同一条数据链路：

```text
Inbound Handler::Process
  -> Dispatcher::Dispatch（嗅探、强制出口或路由规则、未命中回退、请求策略）
  -> Outbound Handler::Process
  -> Relay（TCP / UDP / Mux）
```

每个数据 Worker 独立绑定同一组 `SO_REUSEPORT` 端口；连接与有状态会话一生固定在创建它的 Worker 上。Hysteria2 QUIC 连接通过内核态 CID 分流固定到原 Worker，客户端路径迁移后仍由原 Worker 服务；Hysteria2 只提供配置的服务端 UDP 端口，不实现端口跳跃。主线程运行唯一主控事件循环，承载面板同步、监控、DNS 与全局准入。

控制面从面板拉取节点、用户和规则，归一化为不可变运行时快照后原子发布到各 Worker。用户或规则的局部更新保留未变更的监听和资源，成功应用后才确认同步验证器；失败保留最后提交的配置。分层职责与边界规则见 [`AGENTS.md`](AGENTS.md)。

## 部署

一键部署脚本 `scripts/cnode.sh` 适用于带 systemd 的 Linux x86-64，需要 root、Bash（用于进程替换）以及 `curl`、`jq`（缺失时尝试用 apt-get/yum/dnf/pacman/zypper 安装）。安装目录固定为 `/opt/cnode`，配置目录 `/opt/cnode/config`，日志目录 `/opt/cnode/log`，服务名 `cnode`。

部署或追加一个面板：

```sh
bash <(curl -sL https://raw.githubusercontent.com/grrhuipp/cnode/master/scripts/cnode.sh) \
  -name xxx -api_host https://panel.example.com -api_key xxx -node_id 1,2 -node_type vmess
```

必填 `-name`、`-api_host`、`-api_key`、`-node_id`（逗号分隔）、`-node_type`。可选项：

| 选项 | 说明 |
| --- | --- |
| `-dns <ip>` | 新建 `config.json` 时写入 `dns.servers`；省略则使用系统 `/etc/resolv.conf` |
| `-tls_enable true`、`-tls_cert <path>`、`-tls_key <path>` | 面板启用程序内 TLS 及证书路径 |
| `-inbound_url`、`-outbound_url`、`-route_url <url>` | 每次覆盖下载 `inbounds.json`、`outbounds.json`、`routing.json` |
| `-v <tag>` | release tag，默认 `cnode-latest`；`latest` 表示 GitHub latest release |
| `-debug_file true` | 额外下载匹配的 `cnode-linux-amd64.debug` 符号文件 |

部署模式依次更新 geodata 与二进制、写入 systemd 服务、仅在不存在时创建 `config.json`、下载指定的侧车文件、按名称添加或替换面板，最后重启服务。侧车文件先下载到临时文件并通过 JSON 校验后才替换，下载失败或内容无效时保留原文件并以失败退出，不重启服务。面板按大小写无关的字段名查找、按区分大小写的面板名称替换，不改写其他配置键；`config.json` 损坏、`panels` 类型错误或存在大小写冲突的字段时停止写入并保留原文件。

不带参数运行时只更新二进制及 `geoip.dat`、`geosite.dat`，不改写既有配置。二进制先下载到同目录临时文件并校验版本，再原子替换；下载、空文件或版本校验失败时保留原二进制，不停止现有服务。二进制或 geo 数据变化后重启原本运行中的服务；geo 下载失败保留旧数据。

## Release 产物

GitHub Release 仅发布 musl+epoll 全静态二进制及匹配的 `.debug` 符号文件：

```text
cnode-linux-amd64
cnode-linux-amd64.debug
```

CI 在打包前检查 ELF 不含动态解释器和共享库依赖。部署脚本默认只下载二进制，符号文件需显式 `-debug_file true`。x86-64 构建启用 BLAKE3 运行时 SIMD 分派并保留 portable 回退，不要求部署机器与构建机器具有相同指令集。

## 配置

### 文件与启动

目录模式固定读取：

```text
config.json      进程级配置与 panels
inbounds.json    静态入站（对象数组）
outbounds.json   静态出站（对象数组）
routing.json     路由（routing 对象）
geoip.dat
geosite.dat
```

`config.json` 顶层必须是对象。`inbounds.json`、`outbounds.json` 顶层为对象数组，`routing.json` 顶层为 routing 对象，不接受 `{ "inbounds": [...] }`、`{ "routing": { ... } }` 等外层包装。仓库 `config/*.json.example` 是样例，实际文件名不带 `.example`。

推荐部署目录：

```text
/opt/cnode/
  cnode
  config/   config.json inbounds.json outbounds.json routing.json geoip.dat geosite.dat
  log/      access_YYYY-MM-DD.log error_YYYY-MM-DD.log 及轮转后的 .gz
```

```sh
./cnode --config-file /opt/cnode/config/config.json
./cnode --config-dir /opt/cnode/config
./cnode -c /opt/cnode/config
```

`-c, --config <path>` 自动判断文件或目录；`--config-file` 只接受文件；`-C, --config-dir` 只接受目录。`-v` 输出版本标识。`--test` 启用 `test-vmess-10086` 测试入站；未配置面板和静态入站时也会启用它，与已有入站的标签或监听冲突时拒绝启动。

### 键名与取值

- 所有本地配置键（含侧车、`panels` 和嵌套 `settings`）不区分 ASCII 大小写，示例采用 camelCase：`APIHost`、`apiHost`、`apihost` 等价。大小写归一化后重复的键直接报错。`api_host` 等下划线别名不被识别。
- 语义上大小写无关的值统一按小写处理：协议、`nodeType`、面板 `type`、`network`、`security`、日志级别、加密方法、`flow`、`decryption`/`encryption`、`packetEncoding`、`auto`、`sendThroughStrategy`、`domainStrategy`、`dnsType`、Blackhole 响应类型、Host/SNI/`serverName`/gRPC `authority`。路径、gRPC `serviceName`、Header 值、标签、邮箱、UUID、密码、密钥与 padding 方案区分大小写。
- 未知枚举、空值、错误类型拒绝加载；路由引用不存在的 outbound 直接报错。
- 主配置、日志、DNS、限额、超时、面板、入站、出站和路由对象中的未知键拒绝加载。例如连接空闲超时必须写 `timeouts.connIdle`，`timeouts.idle` 不再被静默忽略。
- IP 字段必须是完整地址：IPv4 四段无前导零，IPv6 可带数字 scope ID（如 `fe80::1%3`），不接受接口名 scope。单独的 host、listen、sendThrough 字段不接受端口、方括号或尾随内容；方括号只用于 endpoint/URL 中的 IPv6。出站服务器字段可使用 DNS 主机名。

### config.json

完整样例见 [`config/config.json.example`](config/config.json.example)。

| 字段 | 默认值与说明 |
| --- | --- |
| `log.loglevel` | `none`、`trace`、`debug`、`info`（默认）、`warning`、`error`，其他值拒绝启动 |
| `log.logDir`、`log.access`、`log.error` | 日志目录与基础文件名；显式空字符串报错；access 与 error 不能指向同一文件 |
| `log.rotateDaily`、`log.gzip`、`log.maxDays` | 默认均开启按日轮转与 gzip 压缩；`maxDays` 默认 15 天 |
| `workers` | 数据 Worker 数，`0` 为自动 |
| `dns.servers` | 见下文；省略使用系统 DNS，显式空数组报错 |
| `dns.timeout` | 秒，默认 5 |
| `dns.cacheSize` | 默认 10240，`0` 禁用缓存 |
| `dns.minTTL`、`dns.maxTTL` | 默认 60 / 3600 秒 |
| `limits.maxConnections`、`limits.maxConnectionsPerIP` | 全进程共享的连接配额，`0` 表示不限 |
| `limits.ipBan` | 见[认证失败限制](#认证失败限制) |
| `timeouts.handshake` | 握手阶段期限，秒，默认 60 |
| `timeouts.dial` | 出站拨号，秒，默认 10 |
| `timeouts.read`、`timeouts.write` | 读写期限，秒，默认 15 / 30 |
| `timeouts.connIdle` | 连接与 UDP 会话空闲超时，秒，默认 300 |
| `timeouts.uplinkOnly`、`timeouts.downlinkOnly` | 单方向结束后另一方向的剩余时间，秒，默认 5 / 5 |
| `panels` | 面板对象数组，见下文 |

`dns.servers` 每项为裸 IPv4/IPv6（默认 UDP 53）或带端口的 `127.0.0.1:5353`、`[::1]:5353`，只接受 IP。省略时启动加载一次 `/etc/resolv.conf` 的前 3 个 `nameserver`（UDP 53），无可用项时使用 `127.0.0.1:53`，文件存在但读取失败则启动报错；运行期修改需重启生效。DNS 缓存只保存成功地址与无记录结果，临时失败不缓存；零 TTL 结果不受 `minTTL` 延长。上游查询最终失败时以 `warning` 记录一次，负缓存命中按事件汇总，不逐连接刷告警。

### 面板

```json
{
  "name": "vmess-panel",
  "type": "V2board",
  "apiHost": "https://your-panel.com",
  "key": "your-api-key-here",
  "nodeIDs": [1, 2, 3],
  "nodeType": "vmess",
  "listenIP": "auto",
  "sendIP": "auto",
  "enableDNS": true,
  "tlsEnable": false,
  "tlsCert": "",
  "tlsKey": ""
}
```

- `nodeType` 只接受 `vmess`、`vless`、`trojan`、`shadowsocks`、`anytls`、`hysteria`、`hysteria2`。
- `sendIP: "auto"` 表示 direct 出站优先绑定入站连接命中的本地 IP（源进源出）；`enableDNS` 默认 `true`；`dnsType` 映射为 freedom 出站的 `domainStrategy`；`proxyProtocol` 见下文。
- `tlsEnable: true` 且 `tlsCert`/`tlsKey` 为空时自动生成自签名证书（仅测试用）；TLS 由外部 nginx/caddy 终结时保持 `false`。
- `requestTimeout` 以秒为单位，默认 30，范围 1–3600，覆盖单次面板请求的 DNS、连接、TLS、发送和响应读取。
- 面板 HTTPS 使用系统 CA 校验证书与主机名，最低 TLS 1.2。连接或握手失败可换下一个地址；请求开始发送后失败不跨地址重发。
- 面板节点资源标签为 `panel/{Name}/{NodeID}/{protocol}/{port}`，可在路由 `inboundTag` 与日志筛选中使用；静态入站与出站标签不得使用 `panel/` 前缀。
- 面板下发字段以 xv2board `UniProxyController` 为契约：整数字段同时接受非负整数与纯十进制字符串，`tls` 另接受布尔值与 `"true"`/`"false"`。Hysteria 按 `version` 选择 v1/v2。面板下发的 Shadowsocks/Hysteria 混淆与 VLESS Encryption 不受支持，出现非空值时拒绝该节点。
- V2Board Shadowsocks 2022 节点自动使用面板 `server_key` 作为 identity PSK，并按 V2Board 规则从用户 UUID 构造用户 PSK。
- 面板接口异常（HTTP 错误、超时、无效响应、重复键或嵌套超过 128 层的 JSON、重复用户 `id`、非法正则）时保留最后成功的节点配置与用户。同一入站多个用户派生出相同凭据时本次用户更新失败；只有用户接口返回合法空列表才清空用户。
- 节点监听端点不得与其他节点或静态入站重叠（同端口下通配地址与具体地址视为冲突），冲突时本次更新失败，原监听继续服务。

### 静态入站、出站与路由

样例见 [`config/inbounds.json.example`](config/inbounds.json.example)、[`config/outbounds.json.example`](config/outbounds.json.example)、[`config/routing.json.example`](config/routing.json.example)。

- 静态入站默认 `"routingEnabled": false`，直接走内置 `direct`（源进源出）；`"routingEnabled": true` 且未指定 `outboundTag` 时参与路由，未命中回落内置 `direct`；指定 `"outboundTag"` 时全部走该出口。标签不存在或为空拒绝启动。
- 静态入站的 `settings.clients` 中，VMess/VLESS 使用 `id`，其他协议使用 `password`；`flow` 仅用于 VLESS，不将另一种凭据键当作回退来源。
- 面板创建的 direct 出站是路由未命中时的回退；命中规则始终优先。出口列表顺序不表达默认出口，明确的出口不存在时请求失败。
- 未写 `inboundTag` 的路由规则匹配所有入站。`network`、`inboundTag`、`user`、`source`、`protocol` 写成空字符串或空数组时拒绝启动。
- 启动时只加载路由实际引用的 geoip/geosite 分类；数据文件缺失、损坏或引用的分类不存在时拒绝启动；geosite 的 regexp 条目不加载。
- `proxyProtocol`（静态入站与面板）：`"off"` 不探测，`"auto"`（默认）自动识别 PROXY v1/v2 或普通字节，`"on"` 强制要求。自动识别不验证来源，只应让可信前置代理访问。
- 传输名称保留 [Xray 的公开拼写](https://github.com/XTLS/Xray-core/blob/main/infra/conf/transport_internet.go)：`raw`/`tcp`、`ws`/`websocket`、`xhttp`/`splithttp` 分别表示同一种传输；本实现另支持用 `h2` 强制 HTTP/2。
- WebSocket 入站默认取 `X-Forwarded-For` 首个 IP 作为客户端地址；`wsSettings.realIpHeader` 可改用其他头，设为 `""` 关闭。该头可被伪造，仅应经可信代理访问，源端口记为 `:0`。
- WebSocket 与 HTTPUpgrade 入站按 URL 路径精确匹配配置（包括 `/`），查询字符串不参与路径匹配；Host 比较前去除首尾空白。
- TLS 证书可写 `tlsSettings.certificates[].certificateFile`/`keyFile`，或 `tlsSettings.certFile`/`keyFile`；这些文件、`tlsSettings.caFile` 与面板 `tlsCert`/`tlsKey` 在加载配置时读入，文件缺失、为空或超过 1 MiB 时拒绝加载；证书更新需重新加载配置。autosign 只为配置的名称签发证书并在到期前自动更新。
- XHTTP `mode` 只接受 `auto`（或省略）、`packet-up`、`stream-up`、`stream-one`。
- REALITY 服务端支持 `dest`、`xver`（0/1/2）、`serverNames`、`shortIds`、`privateKey`、`minClientVer`、`maxClientVer`、`maxTimeDiff`、`mldsa65Seed`；客户端支持 `serverName`、`publicKey`、`shortId`、`fingerprint`（`chrome`/`firefox`/`safari`/`ios`/`android`/`edge`/`360`/`qq`/`random`）、`spiderX`、`mldsa65Verify`。`show`、`type`、`masterKeyLog` 会被拒绝。未认证连接透明回落到 `dest`，使用 `timeouts.dial`、`connIdle`、`write`、`uplinkOnly`、`downlinkOnly`。V2Board `tls=2` 节点自动同步为 REALITY。
- 出站 `settings` 的每层对象均拒绝未知键。Trojan/Shadowsocks 可用扁平服务器字段或单元素 `servers` 数组；VLESS/VMess 可用扁平字段或单元素 `vnext` 数组及其中的单元素 `users` 数组，不能混用两种结构。
- Trojan 出站 `serverName` 与 `tlsSettings.serverName` 使用相同取值规则：非空时必须是 IP 或 DNS 主机名，不能填写端口或路径。非法值在配置加载时拒绝，`allowInsecure` 不跳过名称校验。
- VLESS 出站身份字段为 `id`，支持 UUID 或 1–30 字节自定义 ID，并按 [Xray 的 UUIDv5 映射](https://xtls.github.io/config/outbounds/vless.html#outboundconfigurationobject)处理。Vision flow 要求 TCP 搭配 TLS、REALITY 或 VLESS Encryption。`packetEncoding` 接受 `none`、`packetaddr`、`xudp`（默认）；[PacketAddr 与 XUDP](https://sing-box.sagernet.org/configuration/outbound/vless/#packet_encoding)分别对应 V2Ray 5+ 与 Xray 的 UDP 封装。
- VMess 出站 `security` 接受 `auto`、`aes-128-gcm`、`chacha20-poly1305`、`none`、`zero`；`alterId` 仅接受 `0`。Shadowsocks 与 Trojan 的凭据字段为 `password`。
- Shadowsocks 出站省略 `method` 时使用 `aes-256-gcm`；SS2022 每段 PSK 必须符合方法密钥长度，身份链只支持 AES 方法。`"uot": true` 开启 UoT（默认 v2），`"uotVersion": 1` 选择 v1，也可写 `"uot": {"enabled": true, "version": 2}`。Shadowsocks 与 AnyTLS 入站自动识别 UoT v1/v2。
- AnyTLS 出站：`idleSessionCheckInterval` 默认 30 秒，`idleSessionTimeout` 默认 60 秒，`minIdleSession` 默认 0。AnyTLS 入站通过 `settings.clients` 与 `settings.paddingScheme` 配置，padding 方案归一化后最多 65,535 字节，无效方案拒绝加载。
- 出站顶层 `sendThrough` 可填单个源 IP、`auto`，或按优先级排列的 IP/CIDR 数组：按目标地址族选第一个同族条目，CIDR 地址由 `sendThroughStrategy` 选择——`random`（默认）、`ip_hash`（按最初入站客户端 IP）或 `user_hash`（按入站标签与用户标识，无用户时回退 IP）。绑定失败不换源 IP，也不回退系统默认；没有同族条目时由系统选择。
- 代理出站顶层 `"passthrough": true`（默认 `false`）向下一跳 cnode 透传最初入站的标签、用户身份与客户端 IP，供下游 `ip_hash`/`user_hash` 与访问日志使用。
- Freedom `settings.domainStrategy` 接受 `AsIs`、`UseIP`、`UseIPv4`、`UseIPv6`、`UseIPv4v6`、`UseIPv6v4` 及对应 `Force*` 策略；TCP 与 UDP 的地址族选择均由拨号器执行。`settings.redirect` 为 TCP 目标的 `host:port`；源地址统一由出站顶层 `sendThrough` 配置。

### 认证失败限制

`config.json` 可独立开启 IPBan；省略时关闭，默认值如下：

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

- IPBan 按入站标签和 PROXY protocol 提供的非空客户端 IP 计数；直连 socket IP、HTTP 转发头不参与。启用后在传输握手前拒绝已封禁 IP，不踢掉已有连接。三个数值字段均为正整数，即使关闭也拒绝非法值。
- **失败凭据限制固定开启，不可配置**：同一入站、同一认证信息跨 IP 累计，60 秒内 10 次失败后拒绝 180 秒。支持 VLESS、Trojan、AnyTLS 和 Hysteria v1/v2；VMess、Shadowsocks 只使用可选 IPBan。配置 `limits.credentialBan` 会报错。
- 计数在所有 Worker 间共享，仅保存在内存，重启清空；认证成功不清零，封禁期间不续期。每种规则最多跟踪 16,384 个键，满时拒绝未知键。凭据原文不写入日志。

## 资源上限与运行语义

以下为对使用者可见的固定预算；它们是本地资源限制，不是协议限制。

- 连接配额：`maxConnections`/`maxConnectionsPerIP` 是全进程值，物理连接占一个额度，额外并发逻辑请求增加额度。
- 限速：每个转发方向按 bytes/s 独立限速，初始额度一秒流量，空闲最多积累两秒。
- TCP keepalive：空闲 60 秒后开始探测，间隔 10 秒，共 6 次。
- 嗅探：TCP 复制至多 4 KiB 前缀；UDP QUIC 嗅探总窗口 200 ms、最多 64 个数据报、累计 64 KiB。
- HTTP/2（gRPC、h2、XHTTP 服务端）：每连接最多 256 个并发流，超额 REFUSED_STREAM；流窗口 4 MiB、连接窗口 8 MiB。gRPC 单条消息正文最多 4 MiB。
- 面板 HTTP：每行最多 64 KiB，响应头（含临时响应及 trailer）累计最多 256 KiB，解码后响应体最多 64 MiB；这些预算不扩大普通代理传输的限制。
- XHTTP：每个 session 排队数据与并发上传共用 4 MiB 预算，最多 1024 个排队包、64 个在途上传。
- Mux：每连接最多 1,024 个子会话；未转发客户端数据共享 4 MiB 预算，降至 2 MiB 后恢复读取（与 Xray 相同的队头阻塞语义）。
- AnyTLS 入站：每个 Session 最多 128 条未结束子流，子流从 SYN 起受 `timeouts.handshake` 绝对期限约束；每条子流接收队列最多 65,535 字节有效数据。
- 原生 UDP：每 Worker 最多 4096 个出站 UDP socket、4096 个存活入站 association、8192 份排队数据报、64 MiB 排队缓冲；满额拒绝新请求，不驱逐已有请求。每个逻辑 UDP 请求独占一个出站 socket，源端口在请求期间不变。上行半关闭后在 `downlinkOnly` 窗口内继续收包。
- Hysteria UDP 分片重组：5 秒无新片或 15 秒整体期限即丢弃该轮分片，不关闭会话。Hysteria v1 服务端使用 BBR v2 拥塞控制，与官方 v1 客户端线协议互通，但带宽控制行为不是 Brutal。
- VMess 重放窗口 180 秒，最多 65,536 项，满时拒绝新记录。
- SS2022 TCP 按 [SIP022 §3.1.5](https://shadowsocks.org/doc/sip022.html#_3-1-5-replay-protection) 记录已认证请求的 salt：进程级去重，保留 65 秒，最多 262,144 项；满时拒绝新记录，不提前淘汰未过期项。重放或跟踪容量拒绝不计入认证失败封禁。
- TLS 读取以 `close_notify` 为正常结束，未收到关闭通知的断开按截断错误处理。

### 流量上报

- V2Board 上报包含用户流量与在线设备。`online` 沿用 v2node 口径：本 push 周期内产生过流量的不同 UID；人数为 0 时也发送空 `/push`。首次上报在启动后一个完整 `push_interval` 之后。
- 流量增量先持久化到 `<配置目录>/traffic-journal/<身份哈希>/`，每个身份最多 1,024 条、64 MiB，达到上限时明确报错并保留未提交计数。
- 上报接口无幂等键，不承诺 exactly-once：发送前记录转为 `unknown`，仅完整 HTTP 200 后清除；`unknown` 批次不自动重发。正常停止会持久化最终采样，SIGKILL 前未采样的计数会丢失。

停机后根据面板侧账务证据逐批对账；确认已入账则删除，确认未入账才重新置为可发送：

```sh
mise exec -- cmake --build build/musl --target cnode_traffic_journal
build/musl/cnode_traffic_journal '/path/to/traffic-journal/<身份哈希>' list
build/musl/cnode_traffic_journal '/path/to/traffic-journal/<身份哈希>' resolve batch-XXXXXX.unknown \
  --decision confirmed-applied --evidence '面板侧对账记录编号'
```

确认未入账时将 `--decision` 改为 `confirmed-not-applied`，下次启动允许该批次重新发送。

### 停机

收到停机信号后先关闭新连接准入、取消面板与监控，再收束请求并持久化最终流量，最后停止各 Worker；数据面的在途操作结束后才收束主控协调器，不等待代理流量自然排空。转发载荷只按成功写出的字节计入流量。

## 日志格式

控制台采用 [XrayR v25.3.6](https://github.com/XrayR-project/XrayR/blob/974abc9a98d8b64f7f0a7b7b3044140087a1bc4e/service/controller/controller.go) 的 logrus 文本风格，访问和错误文件采用 Xray 文本风格；三个通道不混用前缀。默认 `access` / `error` 配置作为基础文件名，运行时写入 `access_YYYY-MM-DD.log` / `error_YYYY-MM-DD.log`，历史日志轮转后压缩为 `.gz`，`maxDays` 控制保留天数。不提供集中上传。

**控制台**：显示启动、配置、面板状态、上报结果和资源统计。时间为带本地时区偏移的 RFC3339；面板记录附加 `Host`（只保留 origin）、`ID`、`Name`、`Type`，未知字段省略。

```text
time="2026-11-05T12:30:00+08:00" level=info msg="Panel status: state=ready inbound=ready protocol=vless port=443 network=tcp users=128 rules=12 pull=60s push=60s" Host="https://panel.example.com" ID=1041 Name=main Type=vless
```

`Panel status` 每 60 秒输出一次，`state` 取 `connecting / ready / degraded / missing / unavailable`，含义见 [`docs/local_logging.md`](docs/local_logging.md#4-文件和后端)。`info` 级别周期资源日志按 `Runtime activity / memory / traffic / DNS cache`、`Process descriptors`、`Worker activity / UDP resources / UDP traffic`、`Panel node totals` 分行输出；FD 采样不可用时显示 `unknown`。

**访问文件**：只记录访问事实，不带日志级别。接受为 `accepted`，认证、配额与策略拒绝为 `rejected` 并说明原因。`user:` 是数字 UID，`email:` 是用户标识（与 UID 相同时不重复）；收到上游 `passthrough` 元数据时追加 `origin:<ip>|<tag>|<uid>|<email>`；`sendThrough:` 是实际连接的本地地址。认证前不记录候选用户。

```text
2026/11/05 12:30:01.123456 from 192.0.2.10:52000 accepted tcp:example.com:443 [vless-in -> direct] user:123 email:user@example.com sendThrough:198.51.100.2
2026/11/05 12:30:02.123456 from 192.0.2.10:52001 rejected authentication failed: no matching user [vless-in]
```

**错误文件**：受 `loglevel` 控制的诊断，时间精确到微秒。连接记录带完整 64 位连接 ID、组件、已有路由与已确认 UID。

```text
2026/11/05 12:30:02.123456 [Warning] [4294967303] proxy/vless/inbound: [vless-in] authentication failed from 192.0.2.10:52001 > no matching user
```

控制台普通诊断同样遵守 `loglevel`，连接认证失败不刷控制台；面板警告与错误同时进入控制台和错误文件。常规控制台 Error 使用 stderr，其余级别使用 stdout；日志后端自身的故障与恢复诊断走 stderr。`none` 不隐藏访问事实或致命启动失败。正常 EOF、取消和停机不输出 Warning/Error。

日志统一转义换行、NUL、ESC 等控制字符，控制台消息同时转义引号与反斜杠；不记录 UUID、密码、认证摘要、密钥或原始认证包。HTTP 诊断去除 URL 用户信息、query 和 fragment；面板 HTTP 失败不回显响应正文。控制台与文件使用独立有界异步输出，慢控制台读者不阻塞服务；队列容量与故障恢复见[本地日志规范](docs/local_logging.md#4-文件和后端)。

## 代码组织

```text
include/              公共 API 和窄接口
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
