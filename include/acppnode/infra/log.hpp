#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <format>
#include <optional>
#include <source_location>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace acpp {

enum class LogLevel {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    NONE
};

struct ConnectionLogContext {
    uint64_t conn_id{0};
    std::string inbound_tag{};
    int64_t user_id{0};
    std::string outbound_tag{};
};

struct PanelLogContext {
    std::string_view name;
    std::string_view host;
    int64_t node_id;
    std::string_view type;
};

// Single authority for configured level names; unknown names are rejected
// rather than mapped to a default.
[[nodiscard]] std::optional<LogLevel> ParseLogLevel(std::string_view name) noexcept;

// Console lifecycle records use XrayR logfmt; error and access files use
// Xray text records. Diagnostic macros obey the configured severity.
// Direct WriteConsole(ERROR) keeps fatal startup failures visible even at none.
// Access facts are independent of severity and never contain credentials.
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
        std::source_location location = std::source_location::current());

    static void WriteConnection(
        LogLevel level,
        std::string message,
        std::source_location location = std::source_location::current());

    static void WriteAccess(std::string message);

    static void WriteConnection(
        LogLevel level,
        ConnectionLogContext context,
        std::string message,
        std::source_location location = std::source_location::current());

    template <typename Context>
    static void WriteConnection(
        LogLevel level,
        const Context& context,
        std::string message,
        std::source_location location = std::source_location::current()) {
        ConnectionLogContext log_context;
        if constexpr (std::is_integral_v<Context>) {
            log_context.conn_id = static_cast<uint64_t>(context);
        } else {
            log_context.conn_id = context.conn_id;
        }
        if constexpr (requires { std::string(context.inbound.tag); }) {
            log_context.inbound_tag = std::string(context.inbound.tag);
        }
        if constexpr (requires { static_cast<int64_t>(context.inbound.user_id); }) {
            if (context.inbound.user_id > 0) {
                log_context.user_id = static_cast<int64_t>(context.inbound.user_id);
            }
        }
        if constexpr (requires { std::string_view(context.outbound.tag); }) {
            const std::string_view outbound = context.outbound.tag;
            if (outbound != log_context.inbound_tag) log_context.outbound_tag = outbound;
        }
        WriteConnection(
            level,
            std::move(log_context),
            std::move(message),
            location);
    }

    static void WriteConsole(
        LogLevel level,
        std::string message,
        std::source_location location = std::source_location::current());

    static void WritePanel(
        LogLevel level,
        PanelLogContext context,
        std::string message,
        std::source_location location = std::source_location::current());

    [[nodiscard]] static bool ShouldLog(LogLevel level) noexcept;

private:
    static std::atomic<LogLevel> min_level_;
    static std::atomic_bool initialized_;
};

#define LOG_CONSOLE(fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::INFO)) \
            acpp::Log::WriteConsole(acpp::LogLevel::INFO, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_CONSOLE_WARN(fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::WARN)) \
            acpp::Log::WriteConsole(acpp::LogLevel::WARN, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_CONSOLE_ERROR(fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::ERROR)) \
            acpp::Log::WriteConsole(acpp::LogLevel::ERROR, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_CONSOLE_DEBUG(fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::DEBUG)) \
            acpp::Log::WriteConsole(acpp::LogLevel::DEBUG, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)

#define LOG_PANEL_INFO(ctx, fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::INFO)) \
            acpp::Log::WritePanel(acpp::LogLevel::INFO, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_PANEL_WARN(ctx, fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::WARN)) \
            acpp::Log::WritePanel(acpp::LogLevel::WARN, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_PANEL_ERROR(ctx, fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::ERROR)) \
            acpp::Log::WritePanel(acpp::LogLevel::ERROR, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)
#define LOG_PANEL_DEBUG(ctx, fmt_str, ...) \
    do { \
        if (acpp::Log::ShouldLog(acpp::LogLevel::DEBUG)) \
            acpp::Log::WritePanel(acpp::LogLevel::DEBUG, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__)); \
    } while (0)

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

#define LOG_ACCESS(message) \
    do { \
        acpp::Log::WriteAccess((message)); \
    } while (0)

}  // namespace acpp
