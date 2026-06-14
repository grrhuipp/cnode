#include "acppnode/infra/log.hpp"

#include <zlib.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <array>
#include <mutex>
#include <vector>

namespace acpp {

LogLevel Log::min_level_{LogLevel::INFO};
bool Log::initialized_{false};

namespace {

std::mutex g_lifecycle_mutex;
std::mutex g_error_mutex;
std::mutex g_access_mutex;
std::mutex g_console_mutex;
std::ofstream g_error_file;
std::ofstream g_access_file;
std::filesystem::path g_log_dir;
std::filesystem::path g_access_path;
std::filesystem::path g_error_path;
uint16_t g_max_days = 15;

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

std::ofstream OpenLogFile(std::string_view prefix) {
    const auto path = g_log_dir / std::format("{}_{}.log", prefix, TodayDateString());
    return std::ofstream(path, std::ios::app);
}

std::ofstream OpenConfiguredLogFile(
    const std::filesystem::path& configured_path,
    std::string_view fallback_prefix) {
    if (configured_path.empty()) {
        return OpenLogFile(fallback_prefix);
    }

    if (auto parent = configured_path.parent_path(); !parent.empty()) {
        std::filesystem::create_directories(parent);
    }
    return std::ofstream(configured_path, std::ios::app);
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

}  // namespace

bool Log::Init(const std::string& level,
               const std::filesystem::path& log_dir,
               uint16_t max_days,
               const std::filesystem::path& access_path,
               const std::filesystem::path& error_path) {
    {
        std::lock_guard lock(g_lifecycle_mutex);
        if (initialized_) return true;

        min_level_ = ParseLevel(level);
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

            g_error_file = OpenConfiguredLogFile(g_error_path, "error");
            g_access_file = OpenConfiguredLogFile(g_access_path, "access");
            if (!g_error_file || !g_access_file) {
                std::cerr << "Log initialization failed: cannot open access/error log files"
                          << std::endl;
                return false;
            }

            initialized_ = true;
        } catch (const std::exception& e) {
            std::cerr << "Log initialization failed: " << e.what() << std::endl;
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
    if (!initialized_) return;

    {
        std::lock_guard error_lock(g_error_mutex);
        if (g_error_file) g_error_file.flush();
        g_error_file.close();
    }
    {
        std::lock_guard access_lock(g_access_mutex);
        if (g_access_file) g_access_file.flush();
        g_access_file.close();
    }
    {
        std::lock_guard console_lock(g_console_mutex);
        std::cout.flush();
    }
    initialized_ = false;
}

void Log::Flush() {
    {
        std::lock_guard error_lock(g_error_mutex);
        if (g_error_file) g_error_file.flush();
    }
    {
        std::lock_guard access_lock(g_access_mutex);
        if (g_access_file) g_access_file.flush();
    }
    {
        std::lock_guard console_lock(g_console_mutex);
        std::cout.flush();
    }
}

void Log::WriteApp(LogLevel level, const std::string& msg) {
    if (!ShouldLog(level)) return;

    std::lock_guard lock(g_error_mutex);
    if (!initialized_ || !g_error_file) return;

    g_error_file << '[' << LogLocalNow() << "] [" << level << "] " << msg << '\n';
    if (level >= LogLevel::WARN) {
        g_error_file.flush();
    }
}

void Log::WriteAccess(const std::string& msg) {
    if (min_level_ == LogLevel::NONE) return;

    std::lock_guard lock(g_access_mutex);
    if (!initialized_ || !g_access_file) return;

    g_access_file << msg << '\n';
}

void Log::WriteConsole(const std::string& msg) {
    std::lock_guard lock(g_console_mutex);
    std::cout << '[' << LogLocalNow() << "] [info] " << msg << std::endl;
}

bool Log::ShouldLog(LogLevel level) noexcept {
    if (min_level_ == LogLevel::NONE) return false;
    return level >= min_level_;
}

}  // namespace acpp
