# cnode configuration

cnode accepts either a config file or a config directory:

```sh
cnode -c /opt/cnode/config/config.json
cnode -c /opt/cnode/config
```

When `-c` points to a directory, cnode reads `config.json` from that directory and
also loads optional sidecar files such as `inbounds.json`, `outbounds.json`,
`routing.json`, `geoip.dat`, and `geosite.dat` when present.

cnode uses JSON as the deployment configuration format. This is an intentional
difference from XrayR's YAML-oriented layout. The default main file is
`config.json`; proxy entries stay in xray-core-shaped sidecar files:
`inbounds.json`, `outbounds.json`, and `routing.json`.

The sidecar contents should use xray-core object shapes. `inbounds.json` may be
either an array of inbound objects or an object containing an `inbounds` array;
`outbounds.json` follows the same rule for `outbounds`; `routing.json` accepts
the routing object directly or `{ "routing": { ... } }`. Unsupported xray-core
options are ignored instead of being translated into a cnode-only schema.
Routing rules follow xray-core matching semantics: a rule without `inboundTag`
matches traffic from every inbound, while `inboundTag` only restricts matching
when it is explicitly present.

## Panel example

```json
{
  "log": {
    "loglevel": "info",
    "access": "/opt/cnode/log/access.log",
    "error": "/opt/cnode/log/error.log",
    "logDir": "/opt/cnode/log"
  },
  "workers": 0,
  "dns": {
    "servers": ["1.1.1.1", "8.8.8.8"],
    "timeout": 5,
    "cacheSize": 10000,
    "minTTL": 60,
    "maxTTL": 3600
  },
  "timeouts": {
    "handshake": 10,
    "dial": 10,
    "read": 15,
    "write": 30,
    "idle": 300
  },
  "panels": [
    {
      "Name": "trojan-panel",
      "Type": "V2board",
      "APIHost": "https://api.example.com",
      "Key": "your-api-key",
      "NodeIDs": [1011, 2011],
      "NodeType": "trojan",
      "ListenIP": "auto",
      "SendIP": "auto",
      "EnableDNS": true,
      "TLSEnable": false,
      "TLSCert": "",
      "TLSKey": ""
    }
  ]
}
```

AnyTLS panel nodes use the same panel fields with `NodeType: "anytls"`.
AnyTLS is carried over TLS, so enable TLS termination in cnode or put an
equivalent trusted TLS terminator in front of the listener.

```json
{
  "panels": [
    {
      "Name": "anytls-panel",
      "Type": "V2board",
      "APIHost": "https://api.example.com",
      "Key": "your-api-key",
      "NodeIDs": [3011],
      "NodeType": "anytls",
      "ListenIP": "auto",
      "SendIP": "auto",
      "EnableDNS": true,
      "TLSEnable": true,
      "TLSCert": "/opt/cnode/certs/fullchain.pem",
      "TLSKey": "/opt/cnode/certs/privkey.pem"
    }
  ]
}
```

Static AnyTLS inbounds use xray-core `settings.users` and
`settings.paddingScheme`.
cnode joins the array lines with `\n`, compares the client's `padding-md5`,
and sends `UpdatePaddingScheme` when the client needs the server scheme.

## NodeType

`NodeType` is the only protocol selector in panel config. It is case-insensitive
for supported protocols. cnode uses it both to build the local inbound and to
derive the V2Board API `node_type` parameter.
For VMess, `NodeType: "vmess"` is sent to the panel as `node_type=v2ray`.
For other supported protocols, cnode sends the normalized protocol name. AnyTLS
must be written as `"anytls"`; `"any-tls"` is not a supported alias.

```json
{
  "tag": "anytls-static",
  "protocol": "anytls",
  "listen": "auto",
  "port": 8443,
  "settings": {
    "paddingScheme": [
      "stop=8",
      "0=30-30",
      "1=100-400",
      "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
      "3=9-9,500-1000",
      "4=500-1000",
      "5=500-1000",
      "6=500-1000",
      "7=500-1000"
    ],
    "users": [
      {
        "password": "change-me",
        "email": "user@example.com"
      }
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "certFile": "/opt/cnode/certs/fullchain.pem",
      "keyFile": "/opt/cnode/certs/privkey.pem"
    }
  }
}
```

## ProxyProtocol

`ProxyProtocol` is a cnode-specific three-state setting for inbound listeners:

- `"auto"`: default. Detect PROXY protocol v1/v2 at the beginning of a connection. If no PROXY header is present, the connection continues as ordinary protocol traffic.
- `"off"`: do not inspect or consume a PROXY protocol header.
- `"on"`: require a valid PROXY protocol header. Connections without one are rejected.

Use `"auto"` when the same node may receive traffic both directly and through a
load balancer. Use `"on"` only when every connection is guaranteed to come from
a trusted upstream that always sends PROXY protocol.

When `ProxyProtocol` is omitted, cnode uses `"auto"`.

## SendIP

`SendIP` controls the local source address used by the panel-created direct
outbound.

- `"auto"`: default. Bind outbound TCP connections to the local IP that received
  the inbound connection when the address family matches the remote target. This
  implements source-in/source-out for multi-IP servers.
- A concrete IP such as `"192.0.2.10"` or `"2001:db8::10"`: always bind outbound
  connections to that local address.
- `""`, `"0.0.0.0"`, or `"::"`: let the operating system choose the outbound
  source address.

`"auto"` uses the inbound local address, not the client's remote address. It is
intended for servers with multiple local IPs where traffic entering IP A should
leave from IP A.

## DNSType / domainStrategy

Panel `DNSType` is copied into the generated freedom outbound
`settings.domainStrategy` when `EnableDNS` is enabled. If `EnableDNS: true` and
`DNSType` is omitted or empty, cnode uses `"UseIP"`. `EnableDNS` defaults to
`true`.

cnode follows xray-core freedom outbound values:

- `"AsIs"`
- `"UseIP"`, `"UseIPv6v4"`, `"UseIPv6"`, `"UseIPv4v6"`, `"UseIPv4"`
- `"ForceIP"`, `"ForceIPv6v4"`, `"ForceIPv6"`, `"ForceIPv4v6"`, `"ForceIPv4"`

`UseIPv6v4` / `ForceIPv6v4` prefer IPv6 addresses before IPv4 addresses.
`UseIPv4v6` / `ForceIPv4v6` prefer IPv4 addresses before IPv6 addresses.
`UseIPv4` / `ForceIPv4` only use IPv4 records, and `UseIPv6` / `ForceIPv6`
only use IPv6 records.

`Force*` values are accepted for xray-core config compatibility. In cnode's
current direct outbound implementation, domain targets are resolved before
dialing, so each `Force*` value has the same dialing behavior as its matching
`Use*` value.

## TLS

`TLSEnable` defaults to `false`, meaning cnode does not terminate TLS for the
inbound and TLS is expected to be handled by an external proxy if needed.

When `TLSEnable` is `true`:

- If `TLSCert` and `TLSKey` are set, cnode loads those certificate files.
- If both are empty, cnode uses its SNI-based self-signed certificate mode.
