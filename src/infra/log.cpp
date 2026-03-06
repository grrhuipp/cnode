#include "acppnode/infra/log.hpp"

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/sinks/async_frontend.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/sources/channel_logger.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/attributes/clock.hpp>
#include <boost/log/attributes/current_thread_id.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/core/null_deleter.hpp>
#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>

#include <filesystem>
#include <format>
#include <iostream>
#include <vector>

namespace logging  = boost::log;
namespace sinks    = boost::log::sinks;
namespace src      = boost::log::sources;
namespace expr     = boost::log::expressions;
namespace attrs    = boost::log::attributes;
namespace keywords = boost::log::keywords;

// 属性关键字声明（必须在命名空间外）
BOOST_LOG_ATTRIBUTE_KEYWORD(attr_severity, "Severity", acpp::LogLevel)
BOOST_LOG_ATTRIBUTE_KEYWORD(attr_channel,  "Channel",  std::string)

namespace acpp {

// 静态成员定义
LogLevel Log::min_level_  = LogLevel::INFO;
bool     Log::initialized_ = false;

namespace {

// ============================================================================
// 类型别名
// ============================================================================
using AppLogger   = src::severity_channel_logger_mt<LogLevel, std::string>;
using PlainLogger = src::channel_logger_mt<std::string>;
using AsyncFileSink   = sinks::asynchronous_sink<sinks::text_file_backend>;
using SyncConsoleSink = sinks::synchronous_sink<sinks::text_ostream_backend>;

// ============================================================================
// 全局日志器（Init 中用 unique_ptr 惰性构造）
// ============================================================================
std::unique_ptr<AppLogger>   g_app_logger;
std::unique_ptr<PlainLogger> g_access_logger;
std::unique_ptr<PlainLogger> g_console_logger;

// 保留 sink 引用，用于 Flush/Shutdown
std::vector<boost::shared_ptr<AsyncFileSink>>  g_file_sinks;
boost::shared_ptr<SyncConsoleSink>             g_console_sink;

std::filesystem::path g_log_dir;
uint16_t g_max_days = 15;

// ============================================================================
// 过期日志文件清理
// ============================================================================
void CleanupOldFiles() {
    if (g_max_days == 0 || g_log_dir.empty()) return;
    try {
        auto now = std::filesystem::file_time_type::clock::now();
        for (const auto& entry : std::filesystem::directory_iterator(g_log_dir)) {
            if (!entry.is_regular_file()) continue;
            auto name = entry.path().filename().string();
            if (name.rfind("app_",    0) == 0 ||
                name.rfind("access_", 0) == 0) {
                auto age  = now - entry.last_write_time();
                auto days = static_cast<uint16_t>(
                    std::chrono::duration_cast<std::chrono::hours>(age).count() / 24);
                if (days > g_max_days) {
                    std::filesystem::remove(entry.path());
                }
            }
        }
    } catch (...) {}
}

// ============================================================================
// 创建异步文件 sink
//   - 按日期命名：prefix_%Y-%m-%d.log
//   - 每日零点轮转
//   - 追加模式（重启后续写同日文件）
// ============================================================================
boost::shared_ptr<AsyncFileSink> MakeAsyncFileSink(
    const std::filesystem::path& log_dir,
    const std::string& prefix)
{
    auto backend = boost::make_shared<sinks::text_file_backend>(
        keywords::file_name = (log_dir / (prefix + "_%Y-%m-%d.log")).string(),
        keywords::open_mode = std::ios::app,
        keywords::time_based_rotation =
            sinks::file::rotation_at_time_point(0, 0, 0)
    );
    // async 前端已批量化写入（队列 → backend），auto_flush 保证每批写入后 fsync
    // 效果：批量写入减少 syscall 次数，同时 tail -f 无明显延迟
    backend->auto_flush(true);

    return boost::make_shared<AsyncFileSink>(backend);
}

}  // anonymous namespace

// ============================================================================
// Log::Init
// ============================================================================
bool Log::Init(const std::string& level,
               const std::filesystem::path& log_dir,
               uint16_t max_days) {
    if (initialized_) return true;

    // 解析日志级别
    if      (level == "trace") min_level_ = LogLevel::TRACE;
    else if (level == "debug") min_level_ = LogLevel::DEBUG;
    else if (level == "info")  min_level_ = LogLevel::INFO;
    else if (level == "warn")  min_level_ = LogLevel::WARN;
    else if (level == "error") min_level_ = LogLevel::ERROR;

    g_log_dir  = log_dir;
    g_max_days = max_days;

    try {
        std::filesystem::create_directories(log_dir);
        CleanupOldFiles();

        // 向 Boost.Log 核心注册全局属性（时间戳 + 线程 ID）
        logging::core::get()->add_global_attribute(
            "TimeStamp", attrs::local_clock());
        logging::core::get()->add_global_attribute(
            "ThreadID",  attrs::current_thread_id());

        // ── app sink ─────────────────────────────────────────────────────────
        // 格式：[timestamp] [level] [tid] message
        {
            auto sink = MakeAsyncFileSink(log_dir, "app");
            sink->set_filter(
                attr_channel == std::string("app") &&
                attr_severity >= min_level_
            );
            sink->set_formatter(
                expr::stream
                    << "[" << expr::format_date_time<boost::posix_time::ptime>(
                               "TimeStamp", "%Y-%m-%d %H:%M:%S.%f") << "]"
                    << " [" << attr_severity << "]"
                    << " [" << expr::attr<attrs::current_thread_id::value_type>(
                               "ThreadID") << "]"
                    << " " << expr::smessage
            );
            logging::core::get()->add_sink(sink);
            g_file_sinks.push_back(sink);
        }

        // ── access sink ──────────────────────────────────────────────────────
        // 格式：message（原样写入，调用方自己拼格式）
        {
            auto sink = MakeAsyncFileSink(log_dir, "access");
            sink->set_filter(attr_channel == std::string("access"));
            sink->set_formatter(expr::stream << expr::smessage);
            logging::core::get()->add_sink(sink);
            g_file_sinks.push_back(sink);
        }

        // ── console sink（同步，立即输出）────────────────────────────────────
        // 格式：[timestamp] [info] message
        {
            auto backend = boost::make_shared<sinks::text_ostream_backend>();
            backend->add_stream(
                boost::shared_ptr<std::ostream>(&std::cout, boost::null_deleter{}));
            backend->auto_flush(true);

            g_console_sink = boost::make_shared<SyncConsoleSink>(backend);
            g_console_sink->set_filter(attr_channel == std::string("console"));
            g_console_sink->set_formatter(
                expr::stream
                    << "[" << expr::format_date_time<boost::posix_time::ptime>(
                               "TimeStamp", "%Y-%m-%d %H:%M:%S.%f") << "]"
                    << " [info] " << expr::smessage
            );
            logging::core::get()->add_sink(g_console_sink);
        }

        // ── 构造各通道日志器 ──────────────────────────────────────────────────
        g_app_logger     = std::make_unique<AppLogger>(keywords::channel = "app");
        g_access_logger  = std::make_unique<PlainLogger>(keywords::channel = "access");
        g_console_logger = std::make_unique<PlainLogger>(keywords::channel = "console");

        initialized_ = true;

        WriteConsole("Log system initialized");
        WriteConsole(std::format("  Level:     {}", level));
        WriteConsole(std::format("  Directory: {}", log_dir.string()));
        WriteConsole(std::format("  Retention: {} days (daily rotation)", max_days));
        WriteConsole("  app.log    - Program state logs");
        WriteConsole("  access.log - Connection logs (access + errors)");

        WriteApp(LogLevel::INFO, std::format(
            "Log system initialized, level={}, dir={}, max_days={}",
            level, log_dir.string(), max_days));

        return true;

    } catch (const std::exception& e) {
        std::cerr << "Log initialization failed: " << e.what() << std::endl;
        return false;
    }
}

// ============================================================================
// Log::Shutdown
// ============================================================================
void Log::Shutdown() {
    if (!initialized_) return;
    initialized_ = false;

    // 先 flush，等异步队列清空
    for (const auto& sink : g_file_sinks) {
        sink->stop();
        logging::core::get()->remove_sink(sink);
    }
    g_file_sinks.clear();

    if (g_console_sink) {
        g_console_sink->flush();
        logging::core::get()->remove_sink(g_console_sink);
        g_console_sink.reset();
    }

    g_app_logger.reset();
    g_access_logger.reset();
    g_console_logger.reset();
}

// ============================================================================
// Log::Flush  —  等待异步队列写完
// ============================================================================
void Log::Flush() {
    for (const auto& sink : g_file_sinks) {
        sink->flush();
    }
}

// ============================================================================
// Write 系列
// ============================================================================
void Log::WriteApp(LogLevel level, const std::string& msg) {
    if (!initialized_ || !g_app_logger) return;
    BOOST_LOG_SEV(*g_app_logger, level) << msg;
}

void Log::WriteAccess(const std::string& msg) {
    if (!initialized_ || !g_access_logger) return;
    BOOST_LOG(*g_access_logger) << msg;
}

void Log::WriteConsole(const std::string& msg) {
    if (!initialized_ || !g_console_logger) {
        // 初始化完成前直接打印（bootstrap 阶段）
        std::cout << msg << std::endl;
        return;
    }
    BOOST_LOG(*g_console_logger) << msg;
}

// ============================================================================
// Log::ShouldLog  —  宏的前置快速过滤，避免无效 std::format 调用
// ============================================================================
bool Log::ShouldLog(LogLevel level) noexcept {
    return level >= min_level_;
}

}  // namespace acpp
