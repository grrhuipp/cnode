#pragma once

// ============================================================================
// acppnode - Common Definitions (umbrella header)
//
// 子模块头文件（可单独 include）：
//   common/unique_function.hpp  — unique_function<> move-only wrapper
//   common/network.hpp          — Network 枚举、AddressType 枚举
//   common/conn_state.hpp       — ConnState 枚举
//   common/defaults.hpp         — defaults:: 命名空间常量
//   common/clock.hpp            — 时间工具（NowMicros/NowMillis/FormatBytes 等）
// ============================================================================

#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/cobalt.hpp>

// Windows 兼容性
#ifdef _WIN32
// 宏污染清理（boost/asio.hpp 间接包含 <windows.h>）
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
#include <any>
#include <atomic>
#include <functional>

// 子模块
#include "acppnode/common/unique_function.hpp"
#include "acppnode/common/network.hpp"
#include "acppnode/common/conn_state.hpp"
#include "acppnode/common/defaults.hpp"
#include "acppnode/common/clock.hpp"

namespace acpp {

// ============================================================================
// Boost.Asio + Boost.Cobalt 别名
// ============================================================================
namespace net = boost::asio;
namespace cobalt = boost::cobalt;
using tcp = net::ip::tcp;
using udp = net::ip::udp;

// ============================================================================
// 前向声明
// ============================================================================
struct TargetAddress;
struct SessionContext;
struct SniffResult;
struct DialResult;
struct DnsCacheStats;
struct PanelUser;
struct NodeConfig;
struct TrafficData;

class AsyncStream;
class Datagram;
class IOutbound;
class IDnsService;
class IPanel;

class Config;
class Stats;
class Worker;

}  // namespace acpp
