# cnode

高性能代理节点服务端，兼容 V2Board 面板。

## 特性

- **C++23** — Boost.Asio + Boost.Cobalt 协程，零拷贝中继
- **多核并行** — SO_REUSEPORT 多 Worker 模型，每核一个事件循环
- **多协议** — VMess / Trojan / Shadowsocks 入站+出站，Freedom / Blackhole
- **多面板** — 单进程同时接入多个 V2Board 面板和节点
- **传输层** — TCP / TLS / WebSocket 可组合堆叠
- **TLS 自签** — 未配证书时按 SNI 自动生成泛域名证书（EC P-256）
- **路由** — 兼容 Xray 配置格式，geoip / geosite 规则，域名/IP/端口/协议/用户条件匹配
- **嗅探** — TLS SNI + HTTP Host 自动嗅探
- **密码学** — AWS-LC（BoringSSL 分支），AEAD、SHAKE128 XOF
- **内存分配** — mimalloc 高性能分配器
- **部署** — 一键脚本 / Docker / systemd，自动版本检测增量更新

## 架构

```
main.cpp → Worker (per-core)
  → AcceptLoop → SessionHandler
    → TransportStack (TCP → TLS → WebSocket)
    → InboundHandler (VMess / Trojan / Shadowsocks 解码)
    → Router (geoip/geosite/域名/IP/端口/协议/用户 规则匹配)
    → OutboundHandler (Freedom / VMess / Trojan / Shadowsocks 编码)
    → Relay (TCP 双向中继 / UDP 帧转发)
```

## 一键部署

```bash
# 仅更新二进制（默认 release）
bash <(curl -sL https://raw.githubusercontent.com/grrhuipp/cnode/master/scripts/cnode.sh)

# VMess 节点
bash <(curl -sL https://raw.githubusercontent.com/grrhuipp/cnode/master/scripts/cnode.sh) \
  -name my-panel \
  -api_host https://your-panel.com \
  -api_key your-api-key \
  -node_id 1001,2001 \
  -node_type vmess

# Trojan + TLS（同一 cnode 实例追加面板）
bash <(curl -sL https://raw.githubusercontent.com/grrhuipp/cnode/master/scripts/cnode.sh) \
  -name my-trojan \
  -api_host https://your-panel.com \
  -api_key your-api-key \
  -node_id 3001 \
  -node_type trojan \
  -tls_enable true \
  -tls_cert /etc/certs/fullchain.pem \
  -tls_key /etc/certs/privkey.pem

# 自定义路由/出站
bash <(curl -sL https://raw.githubusercontent.com/grrhuipp/cnode/master/scripts/cnode.sh) \
  -name my-panel \
  -api_host https://your-panel.com \
  -api_key your-api-key \
  -node_id 1001 \
  -node_type vmess \
  -outbound_url https://example.com/outbound.json \
  -route_url https://example.com/route.json

# 安装 debug 版本
bash <(curl -sL https://raw.githubusercontent.com/grrhuipp/cnode/master/scripts/cnode.sh) \
  -build_type debug
```

### 参数

| 参数 | 必填 | 说明 |
|------|------|------|
| `-name` | 是 | 面板名称（同名覆盖更新） |
| `-api_host` | 是 | 面板 API 地址 |
| `-api_key` | 是 | 面板 API 密钥 |
| `-node_id` | 是 | 节点 ID，多个用逗号分隔 |
| `-node_type` | 是 | 节点类型：`vmess` / `trojan` / `shadowsocks` |
| `-dns` | 否 | DNS 服务器 IP（默认 `1.1.1.1`） |
| `-tls_enable` | 否 | 设为 `true` 启用 TLS |
| `-tls_cert` | 否 | TLS 证书路径（不填则自动生成泛域名自签证书） |
| `-tls_key` | 否 | TLS 私钥路径 |
| `-outbound_url` | 否 | 远程 outbound.json 地址 |
| `-route_url` | 否 | 远程 route.json 地址 |
| `-inbound_url` | 否 | 远程 inbound.json 地址 |
| `-build_type` | 否 | 二进制类型：`release` / `debug` |

### 管理命令

```bash
systemctl status cnode      # 查看状态
systemctl restart cnode     # 重启
systemctl stop cnode        # 停止
journalctl -u cnode -f      # 实时日志
```

## Docker

```bash
docker run -d --name cnode \
  -v /path/to/config:/etc/cnode \
  --network host \
  ghcr.io/grrhuipp/cnode:latest
```

## 配置格式

兼容 Xray JSON 格式（camelCase），支持配置目录模式（`-c /path/to/dir/`）自动加载拆分文件。

### 目录结构

```
/opt/cnode/
├── cnode                   # 可执行文件
└── config/
    ├── config.json         # 主配置（面板、DNS、超时）
    ├── inbound.json        # 入站配置（可选，面板自动下发）
    ├── outbound.json       # 出站配置（freedom/blackhole/vmess/trojan/shadowsocks）
    ├── route.json          # 路由规则（域名/IP/端口/协议/用户条件）
    ├── geoip.dat           # IP 地理数据（v2fly）
    └── geosite.dat         # 域名地理数据（v2fly）
```

### 主配置示例

```jsonc
{
  "log": { "loglevel": "info", "logDir": "/var/log/cnode" },
  "workers": 0,                    // 0 = 自动检测 CPU 核数
  "dns": {
    "servers": ["1.1.1.1"],
    "cacheSize": 10000,
    "minTTL": 60, "maxTTL": 3600
  },
  "timeouts": {
    "handshake": 10, "dial": 10,
    "read": 15, "write": 30, "idle": 300
  },
  "panels": [
    {
      "name": "my-panel",
      "type": "V2Board",
      "apiHost": "https://your-panel.com",
      "apiKey": "your-api-key",
      "nodeID": [1, 2, 3],
      "nodeType": "vmess"
    },
    {
      "name": "trojan-panel",
      "type": "V2Board",
      "apiHost": "https://your-panel.com",
      "apiKey": "your-api-key",
      "nodeID": [10],
      "nodeType": "trojan",
      "tlsEnable": true,
      "tlsCert": "/etc/certs/fullchain.pem",
      "tlsKey": "/etc/certs/privkey.pem"
    }
  ]
}
```

### 出站示例

```jsonc
[
  { "tag": "direct", "protocol": "freedom" },
  { "tag": "blackhole", "protocol": "blackhole" },
  {
    "tag": "proxy-vmess", "protocol": "vmess",
    "settings": {
      "vnext": [{
        "address": "proxy.example.com", "port": 443,
        "users": [{ "id": "uuid-here", "security": "auto" }]
      }]
    },
    "streamSettings": {
      "network": "ws", "security": "tls",
      "wsSettings": { "path": "/ws" },
      "tlsSettings": { "serverName": "proxy.example.com" }
    }
  }
]
```

### 路由示例

```jsonc
{
  "domainStrategy": "AsIs",
  "rules": [
    { "domain": ["geosite:category-ads-all"], "outboundTag": "blackhole" },
    { "domain": ["geosite:cn"], "outboundTag": "direct" },
    { "ip": ["geoip:private", "geoip:cn"], "outboundTag": "direct" },
    { "protocol": ["bittorrent"], "outboundTag": "blackhole" }
  ]
}
```

## TLS 模式

| 模式 | 配置 | 说明 |
|------|------|------|
| 外部处理 | `tlsEnable` 不设或 `false` | TLS 由 nginx/caddy 等处理 |
| 指定证书 | `tlsEnable: true` + `tlsCert` + `tlsKey` | 使用指定证书文件 |
| 自动签名 | `tlsEnable: true`（不填证书） | 按 SNI 自动生成泛域名自签证书 |

## 构建

```bash
# 依赖: CMake 3.20+, vcpkg, C++23 编译器 (GCC 14+ / MSVC 19.40+)
cmake -B build -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
cmake --build build
```

### 依赖

| 库 | 用途 |
|-----|------|
| Boost.Asio | 异步 I/O |
| Boost.Cobalt | C++20 协程 |
| Boost.Beast | WebSocket |
| Boost.JSON | 配置解析 |
| AWS-LC | 密码学（AES-GCM, ChaCha20-Poly1305, SHAKE128, EC P-256） |
| mimalloc | 高性能内存分配 |
| zlib | CRC32 |
