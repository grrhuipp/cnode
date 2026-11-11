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
// asio.hpp 总头不含实验特性与 SSL，单独列出。
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/ssl.hpp>

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
#include <filesystem>
#include <format>
#include <functional>
#include <fstream>
#include <iostream>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <ranges>
#include <span>
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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

// ============================================================================
// tl::expected
// ============================================================================
#include <tl/expected.hpp>

// ============================================================================
// zlib
// ============================================================================
#include <zlib.h>
