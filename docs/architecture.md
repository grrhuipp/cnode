# cnode architecture

cnode is structured around one request path and narrow ownership boundaries.
The implementation intentionally tracks xray-core configuration and protocol
semantics where they fit cnode's C++/Asio runtime model, while keeping XrayR
panel synchronization on the control-plane side.

## Request Path

All TCP and UDP traffic must enter the same chain:

```text
inbound.Process
  -> dispatcher.Dispatch
  -> outbound.Process
  -> relay
```

No Worker, router, panel client, protocol helper, or transport implementation
should create a parallel path around this chain.

## Layer Ownership

- `proxy/<protocol>` owns protocol authentication, parsing, encoding, and
  protocol-specific readers or writers.
- `app/dispatcher` owns the handoff from inbound session metadata to routing and
  outbound selection. It must preserve the accepted local endpoint so
  `sendThrough: "auto"` can keep source-in/source-out behavior even when a
  protocol exposes only a reader/writer link or carries UDP over a TCP-like
  substream.
- `app/router` only makes routing decisions and returns outbound tags.
- `app/proxyman` owns prepared inbound and outbound handler construction.
- `transport/internet` owns TCP, TLS, WebSocket, PROXY protocol, and dialer
  mechanics.
- `app/relay` and `common/mux` only move already-prepared data.
  Mux TCP and UDP sub-sessions inherit the parent inbound local endpoint before
  dispatching outbound work.
- `service/controller` and `api/*` own panel synchronization and never enter the
  hot traffic path.

## Runtime Config

Configuration is parsed and normalized before it reaches Worker hot paths.
Workers read immutable runtime snapshots and replace those snapshots atomically
when control-plane state changes.

默认主配置文件为 `config.json`。cnode 与 XrayR YAML 配置布局有意不同：
`config.json` remains the process-level main file, and proxy entries are loaded
from xray-core-shaped sidecar files in the same directory:

- `inbounds.json`
- `outbounds.json`
- `routing.json`

Unsupported xray-core options may be ignored, but cnode should not introduce a
second cnode-only schema for supported inbound, outbound, or routing content.

## Protocol Scope

Supported protocol handlers are VMess, Trojan, Shadowsocks, AnyTLS, Freedom, and
Blackhole. AnyTLS follows the xray-core AnyTLS wire model: TLS session pooling,
single read loop per physical session, stream demux by sid, serialized writes,
and xray-core-shaped `settings.users`, `settings.paddingScheme`, and outbound
session fields.

## Regression Gates

The `tests/no_*.cmake` and protocol-specific CMake checks are retained as
structural regression gates. They are not e2e traffic tests. Their job is to
prevent old public wrappers, compat fields, hot-path config dependencies,
protocol leaks, and cross-layer shortcuts from returning.

The original staged migration log is archived at
`docs/archive/xray-core-xrayr-alignment.md`.
