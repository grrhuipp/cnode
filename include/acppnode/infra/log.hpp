#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <format>
#include <source_location>
#include <string>
#include <string_view>

namespace acpp {

enum class LogLevel {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    NONE
};

enum class LogChannel {
    System,
    Connection
};

struct ConnectionLogContext {
    uint64_t conn_id{0};
    uint32_t worker_id{0};
    std::string inbound;
};

// Every file and console record is emitted as one JSON object. Formatting is
// owned here so protocols and runtime components never construct timestamps,
// levels, channel names, or connection prefixes themselves.
class Log {
public:
    [[nodiscard]] static bool Init(const std::string& level,
                                   const std::filesystem::path& log_dir,
                                   uint16_t max_days = 15,
                                   const std::filesystem::path& access_path = {},
                                   const std::filesystem::path& error_path = {},
                                   bool rotate_daily = true,
                                   bool gzip = true);

    static void Shutdown();
    static void Flush();

    static void WriteSystem(
        LogLevel level,
        std::string message,
        std::string_view event = "diagnostic",
        std::source_location location = std::source_location::current());

    static void WriteConnection(
        LogLevel level,
        std::string message,
        std::string_view event = "diagnostic",
        std::source_location location = std::source_location::current());

    static void WriteConnection(
        LogLevel level,
        ConnectionLogContext context,
        std::string message,
        std::string_view event = "diagnostic",
        std::source_location location = std::source_location::current());

    template <typename Context>
    static void WriteConnection(
        LogLevel level,
        const Context& context,
        std::string message,
        std::string_view event = "diagnostic",
        std::source_location location = std::source_location::current()) {
        WriteConnection(
            level,
            ConnectionLogContext{
                .conn_id = context.conn_id,
                .worker_id = context.worker_id,
                .inbound = std::string(context.inbound.tag),
            },
            std::move(message),
            event,
            location);
    }

    static void WriteConsole(
        LogLevel level,
        std::string message,
        std::string_view event = "status",
        std::source_location location = std::source_location::current());

    [[nodiscard]] static bool ShouldLog(LogLevel level) noexcept;

private:
    static std::atomic<LogLevel> min_level_;
    static std::atomic_bool initialized_;
};

#define LOG_CONSOLE(fmt_str, ...) \
    acpp::Log::WriteConsole(acpp::LogLevel::INFO, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))

#define LOG_TRACE(fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::TRACE)) \
            acpp::Log::WriteSystem(acpp::LogLevel::TRACE, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_DEBUG(fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::DEBUG)) \
            acpp::Log::WriteSystem(acpp::LogLevel::DEBUG, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_INFO(fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::INFO)) \
            acpp::Log::WriteSystem(acpp::LogLevel::INFO, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_WARN(fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::WARN)) \
            acpp::Log::WriteSystem(acpp::LogLevel::WARN, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_ERROR(fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::ERROR)) \
            acpp::Log::WriteSystem(acpp::LogLevel::ERROR, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)

#define LOG_CONN_TRACE(ctx, fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::TRACE)) \
            acpp::Log::WriteConnection(acpp::LogLevel::TRACE, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_CONN_DEBUG(ctx, fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::DEBUG)) \
            acpp::Log::WriteConnection(acpp::LogLevel::DEBUG, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_CONN_INFO(ctx, fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::INFO)) \
            acpp::Log::WriteConnection(acpp::LogLevel::INFO, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_CONN_WARN(ctx, fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::WARN)) \
            acpp::Log::WriteConnection(acpp::LogLevel::WARN, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_CONN_ERROR(ctx, fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::ERROR)) \
            acpp::Log::WriteConnection(acpp::LogLevel::ERROR, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)

// Connection diagnostics without a session Context (transport parsing,
// listener admission, and other pre-session paths).
#define LOG_NET_TRACE(fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::TRACE)) \
            acpp::Log::WriteConnection(acpp::LogLevel::TRACE, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_NET_DEBUG(fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::DEBUG)) \
            acpp::Log::WriteConnection(acpp::LogLevel::DEBUG, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_NET_WARN(fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::WARN)) \
            acpp::Log::WriteConnection(acpp::LogLevel::WARN, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)

#define LOG_CONN_EVENT(ctx, event_name, message) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::INFO)) \
            acpp::Log::WriteConnection(acpp::LogLevel::INFO, ctx, (message), (event_name)); \
    } while (0)

}  // namespace acpp
