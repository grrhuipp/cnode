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
// Console uses an independent bounded mailbox (256 records, at most 4096
// encoded bytes each); full/oversized/unwritable records are counted and
// reported on stderr. Pipe output is atomic and never waits for a reader.
// Shutdown joins both writers; Flush asynchronously requests file flushing.
// Failed file channels recover on later records with 1–30s bounded backoff.
class Log {
public:
    [[nodiscard]] static bool Init(const std::string& level,
                                   const std::filesystem::path& log_dir,
                                   uint16_t max_days = 15,
                                   const std::filesystem::path& access_path = {},
                                   const std::filesystem::path& error_path = {},
                                   bool rotate_daily = true,
                                   bool gzip = true);

    [[nodiscard]] static std::filesystem::path ResolveTargetPath(
        const std::filesystem::path& log_dir,
        const std::filesystem::path& configured_path,
        std::string_view fallback_prefix,
        bool rotate_daily,
        std::string_view date = "0000-00-00");

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

// 内部宏：只有级别启用时才格式化消息；位置信息由 Write* 的默认实参在调用处取得。
#define CNODE_LOG_IF(level, write, ...) \
    do { \
        if (::Log::ShouldLog(::LogLevel::level)) \
            ::Log::write(::LogLevel::level, __VA_ARGS__); \
    } while (0)

#define LOG_CONSOLE(fmt_str, ...) CNODE_LOG_IF(INFO, WriteConsole, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))
#define LOG_CONSOLE_WARN(fmt_str, ...) CNODE_LOG_IF(WARN, WriteConsole, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))
#define LOG_CONSOLE_ERROR(fmt_str, ...) CNODE_LOG_IF(ERROR, WriteConsole, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))

#define LOG_PANEL_INFO(ctx, fmt_str, ...) CNODE_LOG_IF(INFO, WritePanel, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))
#define LOG_PANEL_WARN(ctx, fmt_str, ...) CNODE_LOG_IF(WARN, WritePanel, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))
#define LOG_PANEL_ERROR(ctx, fmt_str, ...) CNODE_LOG_IF(ERROR, WritePanel, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))
#define LOG_PANEL_DEBUG(ctx, fmt_str, ...) CNODE_LOG_IF(DEBUG, WritePanel, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))

#define LOG_DEBUG(fmt_str, ...) CNODE_LOG_IF(DEBUG, WriteSystem, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))
#define LOG_INFO(fmt_str, ...) CNODE_LOG_IF(INFO, WriteSystem, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))
#define LOG_WARN(fmt_str, ...) CNODE_LOG_IF(WARN, WriteSystem, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))
#define LOG_ERROR(fmt_str, ...) CNODE_LOG_IF(ERROR, WriteSystem, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))

#define LOG_CONN_TRACE(ctx, fmt_str, ...) CNODE_LOG_IF(TRACE, WriteConnection, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))
#define LOG_CONN_DEBUG(ctx, fmt_str, ...) CNODE_LOG_IF(DEBUG, WriteConnection, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))
#define LOG_CONN_WARN(ctx, fmt_str, ...) CNODE_LOG_IF(WARN, WriteConnection, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))
#define LOG_CONN_ERROR(ctx, fmt_str, ...) CNODE_LOG_IF(ERROR, WriteConnection, ctx, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))

// Connection diagnostics without a session Context (transport parsing,
// listener admission, and other pre-session paths).
#define LOG_NET_DEBUG(fmt_str, ...) CNODE_LOG_IF(DEBUG, WriteConnection, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))
#define LOG_NET_WARN(fmt_str, ...) CNODE_LOG_IF(WARN, WriteConnection, std::format(fmt_str __VA_OPT__(,) __VA_ARGS__))

#define LOG_ACCESS(message) \
    do { \
        ::Log::WriteAccess((message)); \
    } while (0)

