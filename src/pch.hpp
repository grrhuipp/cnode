#pragma once

// ============================================================================
// 预编译头（PCH）
//
// 只放稳定的第三方库和标准库头文件，不放项目自身头文件。
// 项目头文件改动频繁，放进 PCH 会导致全量重编。
//
// 编译收益最大的是 Boost（Asio + Cobalt 展开量极大），其次是标准库模板。
// ============================================================================

// ============================================================================
// Windows 预处理（必须在 Boost/winsock2 之前）
// ============================================================================
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  define NOMINMAX
// Boost.Log 依赖 Boost.Atomic wait 操作（WaitOnAddress），需要 Windows 8+ (0x0602)
// Boost.Asio 默认设置 _WIN32_WINNT=0x0601，在此覆盖为 Windows 10
#  undef  _WIN32_WINNT
#  define _WIN32_WINNT 0x0A00
#  undef  WINVER
#  define WINVER 0x0A00
#endif

// ============================================================================
// Boost（最重，PCH 收益最大）
// ============================================================================
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/cobalt.hpp>
#include <boost/json.hpp>

// Boost.Beast（WebSocket 传输层）
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>

// Boost/windows.h 宏污染清理
#ifdef _WIN32
#  ifdef ERROR
#    undef ERROR
#  endif
#  ifdef DOMAIN
#    undef DOMAIN
#  endif
#  ifdef WriteConsole
#    undef WriteConsole
#  endif
#endif

// ============================================================================
// 标准库
// ============================================================================
#include <algorithm>
#include <array>
#include <atomic>
#include <any>
#include <bit>
#include <cassert>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <deque>
#include <expected>
#include <filesystem>
#include <format>
#include <functional>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <ranges>
#include <shared_mutex>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

// ============================================================================
// MSVC intrinsics（SpinLock pause 优化）
// ============================================================================
#ifdef _MSC_VER
#include <intrin.h>
#endif

// ============================================================================
// AWS-LC（OpenSSL 兼容头文件）
// ============================================================================
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

// ============================================================================
// zlib
// ============================================================================
#include <zlib.h>
