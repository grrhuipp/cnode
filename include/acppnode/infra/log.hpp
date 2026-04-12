#pragma once

// ============================================================================
// 日志系统（std::ofstream + std::mutex，无第三方依赖）
// ============================================================================
//
// 日志输出说明：
// - 控制台:     只打印配置信息和状态统计
// - app.log:    程序自身状态日志（初始化、监听、统计、面板同步等）
// - access.log: 所有连接相关日志（访问记录、连接失败、认证失败等）
//
// ============================================================================

#include <chrono>
#include "acppnode/common/clock.hpp"
#include <filesystem>
#include <format>
#include <ostream>
#include <string>

// Windows 宏污染清理
#ifdef _WIN32
#  ifdef ERROR
#    undef ERROR
#  endif
#endif

namespace acpp {

// 返回当前本地时间字符串，格式：YYYY-MM-DD HH:MM:SS.ffffff（跨平台）
// 优化：thread_local 缓存日期时间部分，仅秒变化时重新格式化
inline std::string LogLocalNow() {
    using namespace std::chrono;
    thread_local std::string cached_base;   // "2026-03-04 14:23:45"
    thread_local std::time_t cached_sec = -1;

    auto now = system_clock::now();
    auto secs = floor<seconds>(now);
    auto sec_tt = system_clock::to_time_t(secs);

    if (sec_tt != cached_sec) {
        cached_sec = sec_tt;
        cached_base = FormatLocalTime(secs, "%Y-%m-%d %H:%M:%S");
    }

    auto us = duration_cast<microseconds>(now - secs).count();
    return std::format("{}.{:06d}", cached_base, us);
}

// 日志级别
enum class LogLevel {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR
};

// Boost.Log 格式化器通过 ADL 在此命名空间找到该运算符
inline std::ostream& operator<<(std::ostream& os, LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return os << "trace";
        case LogLevel::DEBUG: return os << "debug";
        case LogLevel::INFO:  return os << "info";
        case LogLevel::WARN:  return os << "warn";
        case LogLevel::ERROR: return os << "error";
    }
    return os << "?";
}

class Log {
public:
    // 初始化日志系统
    [[nodiscard]] static bool Init(const std::string& level,
                                   const std::filesystem::path& log_dir,
                                   uint16_t max_days = 15);

    // 关闭日志系统
    static void Shutdown();

    // 刷新所有日志
    static void Flush();

    // 写入各通道
    static void WriteApp(LogLevel level, const std::string& msg);
    static void WriteAccess(const std::string& msg);
    static void WriteConsole(const std::string& msg);

    // 检查日志级别
    [[nodiscard]] static bool ShouldLog(LogLevel level) noexcept;

private:
    static LogLevel min_level_;
    static bool initialized_;
};

// ============================================================================
// 便捷日志宏
// ============================================================================

// 控制台日志（配置和状态信息）
// 使用 C++20 __VA_OPT__ 替代 GNU 扩展 ##__VA_ARGS__
#define LOG_CONSOLE(fmt_str, ...) acpp::Log::WriteConsole(std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))

// ============================================================================
// 应用日志（写入 app.log，不输出到控制台）
// 由运行时 level 配置控制是否输出，不在编译期裁剪
// ============================================================================

#define LOG_TRACE(fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::TRACE)) \
            acpp::Log::WriteApp(acpp::LogLevel::TRACE, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while(0)

#define LOG_DEBUG(fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::DEBUG)) \
            acpp::Log::WriteApp(acpp::LogLevel::DEBUG, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while(0)

#define LOG_INFO(fmt_str, ...)  acpp::Log::WriteApp(acpp::LogLevel::INFO,  std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))
#define LOG_WARN(fmt_str, ...)  acpp::Log::WriteApp(acpp::LogLevel::WARN,  std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))
#define LOG_ERROR(fmt_str, ...) acpp::Log::WriteApp(acpp::LogLevel::ERROR, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))

// ============================================================================
// 带连接上下文的日志
//   TRACE/DEBUG/INFO → access.log（连接访问轨迹，按级别过滤）
//   WARN/ERROR       → error.log（连接级错误）
// ============================================================================
#define LOG_CONN_TRACE(ctx, fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::TRACE)) \
            acpp::Log::WriteAccess(std::format("{} [conn={}][w={}][tag={}][trace] " fmt_str, acpp::LogLocalNow(), ctx.conn_id, ctx.worker_id, ctx.inbound_tag __VA_OPT__(,) __VA_ARGS__)); \
    } while(0)

#define LOG_CONN_DEBUG(ctx, fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::DEBUG)) \
            acpp::Log::WriteAccess(std::format("{} [conn={}][w={}][tag={}][debug] " fmt_str, acpp::LogLocalNow(), ctx.conn_id, ctx.worker_id, ctx.inbound_tag __VA_OPT__(,) __VA_ARGS__)); \
    } while(0)

#define LOG_CONN_INFO(ctx, fmt_str, ...) \
    acpp::Log::WriteAccess(std::format("{} [conn={}][w={}][tag={}] " fmt_str, acpp::LogLocalNow(), ctx.conn_id, ctx.worker_id, ctx.inbound_tag __VA_OPT__(,) __VA_ARGS__))
#define LOG_CONN_WARN(ctx, fmt_str, ...) \
    acpp::Log::WriteAccess(std::format("{} [conn={}][w={}][tag={}][warn] " fmt_str, acpp::LogLocalNow(), ctx.conn_id, ctx.worker_id, ctx.inbound_tag __VA_OPT__(,) __VA_ARGS__))
#define LOG_CONN_ERROR(ctx, fmt_str, ...) \
    acpp::Log::WriteAccess(std::format("{} [conn={}][w={}][tag={}][error] " fmt_str, acpp::LogLocalNow(), ctx.conn_id, ctx.worker_id, ctx.inbound_tag __VA_OPT__(,) __VA_ARGS__))

// ============================================================================
// 访问日志（写入 access.log）
// ============================================================================
#define LOG_ACCESS(msg) acpp::Log::WriteAccess(msg)
#define LOG_ACCESS_FMT(fmt_str, ...) acpp::Log::WriteAccess(std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))

// 无 ctx 的协议层 access 日志（按级别过滤，用于协议解析函数内）
#define LOG_ACCESS_DEBUG(fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::DEBUG)) \
            acpp::Log::WriteAccess(std::format("{} [debug] " fmt_str, acpp::LogLocalNow() __VA_OPT__(,) __VA_ARGS__)); \
    } while(0)
#define LOG_ACCESS_WARN(fmt_str, ...) \
    acpp::Log::WriteAccess(std::format("{} [warn] " fmt_str, acpp::LogLocalNow() __VA_OPT__(,) __VA_ARGS__))

// ============================================================================
// 连接失败日志（写入 access.log）
// ============================================================================
#define LOG_CONN_FAIL(fmt_str, ...) acpp::Log::WriteAccess(std::format("{} " fmt_str, acpp::LogLocalNow() __VA_OPT__(,) __VA_ARGS__))
#define LOG_CONN_FAIL_CTX(ctx, fmt_str, ...) \
    acpp::Log::WriteAccess(std::format("{} [conn={}][w={}][tag={}] " fmt_str, acpp::LogLocalNow(), ctx.conn_id, ctx.worker_id, ctx.inbound_tag __VA_OPT__(,) __VA_ARGS__))

}  // namespace acpp
