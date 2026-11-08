#pragma once

// ============================================================================
// acppnode - Common Definitions (umbrella header)
//
// 子模块头文件（可单独 include）：
//   common/network.hpp          — Network 枚举、AddressType 枚举
//   common/defaults.hpp         — defaults:: 命名空间常量
//   common/clock.hpp            — 时间工具（NowMicros/FormatBytes 等）
// ============================================================================

#include <asio.hpp>
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/steady_timer.hpp>
#include <asio/system_error.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <atomic>
#include <functional>

// 子模块
#include "common/asio_types.hpp"
#include "core/constants.hpp"
#include "common/network.hpp"
#include "common/defaults.hpp"
#include "common/clock.hpp"


// ============================================================================
// 前向声明
// ============================================================================
struct TargetAddress;
struct SniffResult;
struct DialResult;
namespace app::dns {
struct DnsCacheStats;
class DNS;
}  // namespace app::dns
namespace api {
struct UserInfo;
struct NodeInfo;
struct UserTraffic;
}  // namespace api

class AsyncStream;
class Datagram;
class Outbound;

namespace session {
struct Context;
}  // namespace session

namespace api {
class API;
}  // namespace api

struct Config;
class Stats;
class Worker;

