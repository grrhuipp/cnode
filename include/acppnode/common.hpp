#pragma once

// ============================================================================
// acppnode - Common Definitions (umbrella header)
//
// 子模块头文件（可单独 include）：
//   common/network.hpp          — Network 枚举、AddressType 枚举
//   common/defaults.hpp         — defaults:: 命名空间常量
//   common/clock.hpp            — 时间工具（NowMicros/NowMillis/FormatBytes 等）
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

// Windows 兼容性
#ifdef _WIN32
// 宏污染清理（asio.hpp 间接包含 <windows.h>）
#  ifdef ERROR
#    undef ERROR
#  endif
#  ifdef DOMAIN
#    undef DOMAIN
#  endif
#  ifdef WriteConsole
#    undef WriteConsole
#  endif
// POSIX ssize_t 在 Windows 上不存在（等价于 SSIZE_T）
// 直接定义避免依赖具体 SDK 头文件（basetsd.h/BaseTsd.h）
#  if !defined(ssize_t) && !defined(_SSIZE_T_DEFINED)
#    if defined(_WIN64)
       using ssize_t = long long;
#    else
       using ssize_t = int;
#    endif
#    define _SSIZE_T_DEFINED
#  endif
// MSG_NOSIGNAL 在 Windows 上不存在（Windows 没有 SIGPIPE）
#  ifndef MSG_NOSIGNAL
#    define MSG_NOSIGNAL 0
#  endif
#endif

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
#include "acppnode/common/asio_types.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/common/network.hpp"
#include "acppnode/common/defaults.hpp"
#include "acppnode/common/clock.hpp"

namespace acpp {

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
struct NodeStatus;
}  // namespace api

class AsyncStream;
class Datagram;
class Outbound;

namespace session {
struct Context;
}  // namespace session

namespace api {
class API;
struct ClientInfo;
}  // namespace api

class Config;
class Stats;
class Worker;

}  // namespace acpp
