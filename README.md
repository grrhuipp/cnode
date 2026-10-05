# cnode

cnode 是面向 V2Board 面板的高性能代理节点服务端。项目使用 C++20 与 Asio 协程，支持静态配置和面板下发配置，并把协议处理、路由、出站连接、转发、DNS 与控制面划分为独立职责。

内部修改规范见 [`AGENTS.md`](AGENTS.md)，日志格式见 [`docs/local_logging.md`](docs/local_logging.md)。README 只说明使用方式和当前架构。

## 支持范围

- 入站与出站协议：VMess、VLESS、Trojan、Shadowsocks、AnyTLS。
- 出站：Freedom、Blackhole。
- 传输：TCP、TLS、WebSocket、HTTP/2、gRPC、XHTTP，以及协议支持的 UDP、UDP-over-TCP 和 Mux。
- 面板：V2Board。
- TLS：AWS-LC。
- Linux 网络后端：epoll。项目不提供 io_uring 变体。
- REALITY 已移除；`security: "reality"` 和 `realitySettings` 会在配置阶段被拒绝。

## 构建与测试

依赖统一由 vcpkg manifest 管理，固定版本见 [`vcpkg.json`](vcpkg.json) 和 [`vcpkg-configuration.json`](vcpkg-configuration.json)。仓库 overlay port 只构建固定版本的上游原始源码，不应用第三方补丁。项目不使用 CMake preset。

本机 vcpkg 路径为 `/opt/vcpkg`：

```sh
export VCPKG_ROOT=/opt/vcpkg
export PATH="$VCPKG_ROOT:$PATH"

cmake -S . -B build -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCNODE_BUILD_TESTS=ON
cmake --build build --parallel
ulimit -n 8192
ctest --test-dir build --no-tests=error --output-on-failure --parallel 2
```

macOS 上使用支持 C++20 的编译器。当前本机验证使用 Homebrew GCC：

```sh
cmake -S . -B build -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -DCMAKE_C_COMPILER=gcc-16 \
  -DCMAKE_CXX_COMPILER=g++-16 \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCNODE_BUILD_TESTS=ON
```

## 配置

默认主配置文件是 `config.json`。同目录侧车固定为：

```text
config.json
inbounds.json
outbounds.json
routing.json
```

示例位于 [`config/`](config/)。配置只接受 JSON 和 camelCase 键，不读取旧侧车或其他格式。

`config.json` 包含日志、事件循环线程数、DNS、超时和面板配置。`ioThreads` 表示运行同一个共享 `io_context` 的固定线程数；`0` 表示按 CPU 核心数选择。它不创建线程私有的监听、handler 或业务运行态。

静态入站必须通过以下两种方式之一明确选择出口：

- 指定 `outboundTag`：强制使用该出口，不进入 Router。
- 不指定 `outboundTag`：进入 Router；真实规则未命中时使用该 receiver 在冷路径准备好的显式 fallback。

出口列表顺序不表示默认出口，空 tag 或不存在的 tag 会使配置失败。面板资源使用 `panel/{Name}/{NodeID}/...` 保留前缀，静态 tag 不得占用该前缀。

DNS 服务器接受裸 IPv4/IPv6，或带端口的 `127.0.0.1:5353`、`[::1]:5353`。带端口的 IPv6 必须使用方括号；DNS 服务器地址本身不再经域名解析。

## 日志

未配置 `log.logDir` 时，日志目录固定为实际二进制所在目录的 `logs/`，不受当前工作目录、配置文件目录或符号链接启动路径影响。显式 `log.logDir` 会覆盖该位置。

`access` 与 `error` 的相对路径以日志目录为基准，绝对路径保持原值。默认按日轮转并压缩历史文件：

```text
<binary-directory>/logs/
  access_YYYY-MM-DD.log
  error_YYYY-MM-DD.log
  access_YYYY-MM-DD.log.gz
  error_YYYY-MM-DD.log.gz
```

`error` 保存受 `loglevel` 控制的诊断记录，`access` 保存访问事实。`maxDays` 控制历史日志保留天数。

## 运行架构

进程只有一个 `io_context`，启动时创建固定线程池，所有线程只运行同一个事件循环。监听、连接、DNS、控制面和监控通过各自的 executor 与 strand 表达所有权，不依赖执行线程身份。

```text
fixed thread pool
        │
        ▼
shared io_context
  ├─ listener strand ── accept ──► connection/session strand
  ├─ UDP listener strand ────────► association strand
  ├─ DNS service strand
  ├─ control-plane strand
  ├─ monitor strand
  └─ shared physical outbound owner strands
```

每个监听端点只有一个监听所有者，监听数量与线程数无关。TCP accept 完成后把 socket 一次性交给新建的物理会话 strand；监听所有者不再操作该 socket。普通代理连接的入站、分发、独占出站、握手和双向转发沿用同一会话 strand。

Mux、HTTP/2 和 AnyTLS 会话按物理连接拥有 socket、编解码状态与发送队列。子流沿用该物理连接的 strand。可被多个请求共享的出站物理连接由独立 service strand 持有，请求只通过有界入口传递拥有数据的消息。

DNS 的查询、在途请求、UDP socket、缓存和超时都属于 DNS service strand。连接与面板提交自有域名并按值取得结果，不直接访问 DNS 内部状态。在线设备、连接限制、限速、认证重放、统计聚合和出站池同样由各自的服务所有者维护。

跨所有者入口有明确容量，容量同时覆盖排队和在途工作。队列满时返回资源不足或执行明确背压；关闭时先停止准入和 I/O，再取消并等待已经启动的任务，最后销毁状态。

### 请求主链

TCP 和 UDP 共用一条主链：

```text
inbound handler
  -> dispatcher
  -> router / explicit fallback
  -> outbound handler
  -> relay
```

协议 handler 只负责认证、协议解析、目标解析和 session metadata。Dispatcher 编排强制出口、真实路由命中与显式 fallback；Router 只返回规则实际命中的出口 tag；Outbound 完成拨号、下一跳握手与编码；Relay 只搬运数据和累计连接内流量。

跨所有者入口使用 Asio `concurrent_channel` 的有界容量令牌：令牌从准入一直持有到任务及取消清理完成，容量同时覆盖排队和在途操作；满载时明确拒绝。关闭、注销等必要清理提前预留令牌，不与普通请求竞争最后一个入口。业务状态仍只由所属 strand 操作，channel 不授予直接访问权。

配置和面板响应先在冷路径归一化并构建候选对象图，成功后发布不可变快照。活动连接继续持有自己的旧快照，新连接读取新快照；运行中的 handler 不被原地改写。

TLS 读端结束后的完整关闭发送 `close_notify`。仍有下行读取时，写端半关闭使用 TCP FIN，避免并发运行 Asio 的双向 TLS shutdown；这一半关闭路径不发送 `close_notify`。

### 内存与超时

数据面内存归连接、会话、阶段或服务，不归事件循环线程。通用数据分配资源支持并发分配和跨线程释放；需要 PMR 的阶段必须显式绑定资源及 owner strand，不能从当前线程或默认 PMR 推导所有者。

每条连接只常驻 socket、strand、必要协议状态、一个集中超时调度项和一块可复用读缓冲。临时握手和请求数据按阶段释放，空闲连接不保留大 scratch。超时服务在自己的 strand 上管理调度，到期事件投递回会话 strand，再由会话关闭实际 I/O。

## 部署与更新

部署脚本安装到 `/opt/cnode`。首次部署示例：

```sh
bash scripts/cnode.sh \
  -name main \
  -api_host https://panel.example.com \
  -api_key your-key \
  -node_id 1,2 \
  -node_type vmess
```

可用 `-variant musl` 或 `-variant glibc` 选择发布变体；只有显式传入 `-debug_file true` 才下载符号文件。

脚本不带参数时只更新二进制和 geo 数据，不改写既有 panel 或 sidecar 配置。geo 数据先下载到临时目录，失败保留旧文件；内容发生变化后才重启原服务。

## 代码组织

```text
include/acppnode/      公共 API 与窄接口
src/runtime/           runtime 与 listener
src/app/               dispatcher、router、proxyman、bootstrap
src/proxy/             协议实现
src/transport/         字节传输与超时服务
src/service/           控制面
src/api/               面板客户端
src/infra/             配置、JSON、日志与校验
src/common/            通用类型、buffer、allocator、session、mux
src/geo/               geoip / geosite
src/sniff/             HTTP / TLS / QUIC 嗅探
config/                示例配置
scripts/               部署与更新脚本
```

协议只实现 Handler 契约。删除一个协议不应改动 dispatcher、router、relay 或 runtime；替换面板实现不应改动协议热路径。
