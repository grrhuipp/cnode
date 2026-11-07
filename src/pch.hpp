#pragma once

// ============================================================================
// 预编译头（PCH）
//
// 只放稳定的第三方库和标准库头文件，不放项目自身头文件。
// 项目头文件改动频繁，放进 PCH 会导致全量重编。
//
// 编译收益最大的是 Asio/OpenSSL，其次是标准库模板。
// ============================================================================

// ============================================================================
// Asio（最重，PCH 收益最大）
// ============================================================================
#include <asio.hpp>
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/co_spawn.hpp>
#include <asio/connect.hpp>
#include <asio/detached.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/read.hpp>
#include <asio/read_until.hpp>
#include <asio/signal_set.hpp>
#include <asio/ssl.hpp>
#include <asio/steady_timer.hpp>
#include <asio/system_error.hpp>
#include <asio/write.hpp>

// liburing headers expose BLOCK_SIZE as a macro; keep it from breaking
// third-party C++ headers that use BLOCK_SIZE as an identifier.
#ifdef BLOCK_SIZE
#  undef BLOCK_SIZE
#endif

// ============================================================================
// 标准库
// ============================================================================
#include <algorithm>
#include <array>
#include <atomic>
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
#include <tl/expected.hpp>
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
// BoringSSL（OpenSSL-compatible headers）
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
