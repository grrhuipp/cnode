#include "acppnode/infra/log.hpp"

#include <concurrentqueue.h>
#include <zlib.h>

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace acpp {

std::atomic<LogLevel> Log::min_level_{LogLevel::INFO};
std::atomic_bool Log::initialized_{false};

namespace {

using namespace std::chrono_literals;

enum class LogChannel {
    App,
    Access
};

struct LogRecord {
    LogChannel channel{LogChannel::App};
    LogLevel level{LogLevel::INFO};
    std::string message;
};

std::mutex g_lifecycle_mutex;
std::mutex g_console_mutex;
std::filesystem::path g_log_dir;
std::filesystem::path g_access_path;
std::filesystem::path g_error_path;
uint16_t g_max_days = 15;
constexpr size_t kAsyncLogQueueSize = 65536;
constexpr auto kLogIdleSleep = 1ms;

std::string TodayDateString() {
    return FormatLocalTime(std::chrono::system_clock::now(), "%Y-%m-%d");
}

bool GzipFile(const std::filesystem::path& src) {
    auto dst = src;
    dst += ".gz";

    std::ifstream in(src, std::ios::binary);
    if (!in) return false;

    gzFile gz = gzopen(dst.string().c_str(), "wb6");
    if (!gz) return false;

    std::array<char, 64 * 1024> buf{};
    while (in.read(buf.data(), static_cast<std::streamsize>(buf.size())) || in.gcount() > 0) {
        if (gzwrite(gz, buf.data(), static_cast<unsigned>(in.gcount())) <= 0) {
            gzclose(gz);
            std::filesystem::remove(dst);
            return false;
        }
    }

    gzclose(gz);
    in.close();
    std::filesystem::remove(src);
    return true;
}

void CleanupOldFiles() {
    if (g_log_dir.empty()) return;

    try {
        const auto now = std::filesystem::file_time_type::clock::now();
        const auto today = TodayDateString();
        const auto today_error_log = std::format("error_{}.log", today);
        const auto today_access_log = std::format("access_{}.log", today);

        for (const auto& entry : std::filesystem::directory_iterator(g_log_dir)) {
            if (!entry.is_regular_file()) continue;

            const auto name = entry.path().filename().string();
            const bool is_log = name.rfind("error_", 0) == 0 || name.rfind("access_", 0) == 0;
            if (!is_log) continue;

            if (g_max_days > 0) {
                const auto age = now - entry.last_write_time();
                const auto days = std::chrono::duration_cast<std::chrono::hours>(age).count() / 24;
                if (days > g_max_days) {
                    std::filesystem::remove(entry.path());
                    continue;
                }
            }

            if (name.ends_with(".log") && name != today_error_log && name != today_access_log) {
                GzipFile(entry.path());
            }
        }
    } catch (...) {
    }
}

std::filesystem::path DailyLogPath(std::string_view prefix) {
    return g_log_dir / std::format("{}_{}.log", prefix, TodayDateString());
}

std::filesystem::path ResolveLogPath(
    const std::filesystem::path& configured_path,
    std::string_view fallback_prefix) {
    if (configured_path.empty()) {
        return DailyLogPath(fallback_prefix);
    }

    if (auto parent = configured_path.parent_path(); !parent.empty()) {
        std::filesystem::create_directories(parent);
    }
    return configured_path;
}

LogLevel ParseLevel(std::string_view level) {
    if (level == "none") return LogLevel::NONE;
    if (level == "trace") return LogLevel::TRACE;
    if (level == "debug") return LogLevel::DEBUG;
    if (level == "info") return LogLevel::INFO;
    if (level == "warning") return LogLevel::WARN;
    if (level == "warn") return LogLevel::WARN;
    if (level == "error") return LogLevel::ERROR;
    return LogLevel::INFO;
}

class AsyncLogBackend {
public:
    AsyncLogBackend() : queue_(kAsyncLogQueueSize) {}

    ~AsyncLogBackend() {
        Stop();
    }

    AsyncLogBackend(const AsyncLogBackend&) = delete;
    AsyncLogBackend& operator=(const AsyncLogBackend&) = delete;

    [[nodiscard]] bool Start(const std::filesystem::path& error_path,
                             const std::filesystem::path& access_path) {
        Stop();

        error_file_.open(error_path, std::ios::out | std::ios::app);
        access_file_.open(access_path, std::ios::out | std::ios::app);
        if (!error_file_ || !access_file_) {
            CloseFiles();
            return false;
        }

        accepting_.store(true, std::memory_order_release);
        running_.store(true, std::memory_order_release);
        writer_ = std::thread([this] { Run(); });
        return true;
    }

    void Stop() {
        accepting_.store(false, std::memory_order_release);
        if (running_.exchange(false, std::memory_order_acq_rel) && writer_.joinable()) {
            writer_.join();
        } else if (writer_.joinable()) {
            writer_.join();
        }
        DrainUntilEmpty();
        ReportDrops();
        FlushFiles();
        CloseFiles();
    }

    void Enqueue(LogChannel channel, LogLevel level, std::string message) {
        if (!accepting_.load(std::memory_order_acquire)) return;

        thread_local moodycamel::ProducerToken producer_token(queue_);
        LogRecord record{channel, level, std::move(message)};
        if (!queue_.try_enqueue(producer_token, std::move(record))) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void RequestFlush() noexcept {
        flush_requested_.store(true, std::memory_order_release);
    }

private:
    void Run() {
        while (running_.load(std::memory_order_acquire)) {
            const bool wrote = DrainAvailable();
            ReportDrops();
            if (flush_requested_.exchange(false, std::memory_order_acq_rel)) {
                FlushFiles();
            }
            if (!wrote) {
                std::this_thread::sleep_for(kLogIdleSleep);
            }
        }

        DrainUntilEmpty();
        ReportDrops();
        FlushFiles();
    }

    bool DrainAvailable() {
        bool wrote = false;
        LogRecord record;
        while (queue_.try_dequeue(record)) {
            WriteRecord(record);
            wrote = true;
        }
        return wrote;
    }

    void DrainUntilEmpty() {
        while (DrainAvailable()) {
        }
    }

    void WriteRecord(const LogRecord& record) {
        switch (record.channel) {
            case LogChannel::App:
                if (error_file_) {
                    error_file_ << '[' << LogLocalNow() << "] [" << record.level << "] "
                                << record.message << '\n';
                    if (record.level >= LogLevel::WARN) {
                        error_file_.flush();
                    }
                }
                break;
            case LogChannel::Access:
                if (access_file_) {
                    access_file_ << record.message << '\n';
                }
                break;
        }
    }

    void ReportDrops() {
        const auto dropped = dropped_.exchange(0, std::memory_order_acq_rel);
        if (dropped == 0 || !error_file_) return;

        error_file_ << '[' << LogLocalNow() << "] [warn] log queue dropped "
                    << dropped << " records\n";
        error_file_.flush();
    }

    void FlushFiles() {
        if (error_file_) error_file_.flush();
        if (access_file_) access_file_.flush();
    }

    void CloseFiles() {
        if (error_file_.is_open()) error_file_.close();
        if (access_file_.is_open()) access_file_.close();
    }

    moodycamel::ConcurrentQueue<LogRecord> queue_;
    std::atomic_bool accepting_{false};
    std::atomic_bool running_{false};
    std::atomic_bool flush_requested_{false};
    std::atomic<uint64_t> dropped_{0};
    std::thread writer_;
    std::ofstream error_file_;
    std::ofstream access_file_;
};

AsyncLogBackend g_async_log_backend;

}  // namespace

bool Log::Init(const std::string& level,
               const std::filesystem::path& log_dir,
               uint16_t max_days,
               const std::filesystem::path& access_path,
               const std::filesystem::path& error_path) {
    {
        std::lock_guard lock(g_lifecycle_mutex);
        if (initialized_.load(std::memory_order_acquire)) return true;

        min_level_.store(ParseLevel(level), std::memory_order_release);
        g_log_dir = log_dir;
        g_access_path = access_path;
        g_error_path = error_path;
        g_max_days = max_days;

        try {
            const bool uses_daily_fallback = g_access_path.empty() || g_error_path.empty();
            if (uses_daily_fallback) {
                std::filesystem::create_directories(g_log_dir);
                CleanupOldFiles();
            }

            if (!g_async_log_backend.Start(ResolveLogPath(g_error_path, "error"),
                                           ResolveLogPath(g_access_path, "access"))) {
                std::cerr << "Log initialization failed: cannot open access/error log files"
                          << std::endl;
                return false;
            }

            initialized_.store(true, std::memory_order_release);
        } catch (const std::exception& e) {
            std::cerr << "Log initialization failed: " << e.what() << std::endl;
            g_async_log_backend.Stop();
            return false;
        }
    }

    WriteConsole("Log system initialized");
    WriteConsole(std::format("  Level:     {}", level));
    WriteConsole(std::format("  Directory: {}", log_dir.string()));
    WriteConsole(std::format("  Retention: {} days (daily rotation)", max_days));
    WriteConsole(std::format("  AccessPath: {}",
                             g_access_path.empty() ? "(daily access_YYYY-MM-DD.log)" : g_access_path.string()));
    WriteConsole(std::format("  ErrorPath:  {}",
                             g_error_path.empty() ? "(daily error_YYYY-MM-DD.log)" : g_error_path.string()));

    WriteApp(LogLevel::INFO, std::format(
        "Log system initialized, level={}, access_path={}, error_path={}, dir={}, max_days={}",
        level,
        g_access_path.empty() ? std::string("(daily)") : g_access_path.string(),
        g_error_path.empty() ? std::string("(daily)") : g_error_path.string(),
        log_dir.string(), max_days));

    return true;
}

void Log::Shutdown() {
    std::lock_guard lifecycle_lock(g_lifecycle_mutex);
    if (!initialized_.exchange(false, std::memory_order_acq_rel)) return;

    g_async_log_backend.Stop();
    {
        std::lock_guard console_lock(g_console_mutex);
        std::cout.flush();
    }
}

void Log::Flush() {
    g_async_log_backend.RequestFlush();
    {
        std::lock_guard console_lock(g_console_mutex);
        std::cout.flush();
    }
}

void Log::WriteApp(LogLevel level, std::string msg) {
    if (!ShouldLog(level)) return;
    if (!initialized_.load(std::memory_order_acquire)) return;

    g_async_log_backend.Enqueue(LogChannel::App, level, std::move(msg));
}

void Log::WriteAccess(std::string msg) {
    if (min_level_.load(std::memory_order_relaxed) == LogLevel::NONE) return;
    if (!initialized_.load(std::memory_order_acquire)) return;

    g_async_log_backend.Enqueue(LogChannel::Access, LogLevel::INFO, std::move(msg));
}

void Log::WriteConsole(const std::string& msg) {
    std::lock_guard lock(g_console_mutex);
    std::cout << '[' << LogLocalNow() << "] [info] " << msg << std::endl;
}

bool Log::ShouldLog(LogLevel level) noexcept {
    const auto min_level = min_level_.load(std::memory_order_relaxed);
    if (min_level == LogLevel::NONE) return false;
    return level >= min_level;
}

}  // namespace acpp
