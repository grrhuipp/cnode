#include "acppnode/infra/log.hpp"

#include "acppnode/common/clock.hpp"

#include <concurrentqueue.h>
#include <zlib.h>

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace acpp {

std::atomic<LogLevel> Log::min_level_{LogLevel::INFO};
std::atomic_bool Log::initialized_{false};

namespace {

using namespace std::chrono_literals;

struct LogRecord {
    LogChannel channel{LogChannel::System};
    LogLevel level{LogLevel::INFO};
    int64_t timestamp_us{0};
    std::string event;
    std::string message;
    std::string source_file;
    uint32_t source_line{0};
    std::optional<ConnectionLogContext> connection;
};

struct LogTarget {
    std::string fallback_prefix;
    std::filesystem::path configured_path;
    std::filesystem::path active_path;
};

struct DailyLogSpec {
    std::filesystem::path directory;
    std::string stem;
    std::string extension{".log"};
};

std::mutex g_lifecycle_mutex;
std::mutex g_console_mutex;
constexpr size_t kAsyncLogQueueSize = 65536;
constexpr auto kLogIdleSleep = 1ms;
constexpr auto kRotationCheckInterval = 1s;

std::string_view LevelName(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::TRACE: return "trace";
        case LogLevel::DEBUG: return "debug";
        case LogLevel::INFO:  return "info";
        case LogLevel::WARN:  return "warn";
        case LogLevel::ERROR: return "error";
        case LogLevel::NONE:  return "none";
    }
    return "?";
}

std::string_view ChannelName(LogChannel channel) noexcept {
    switch (channel) {
        case LogChannel::System: return "system";
        case LogChannel::Connection: return "connection";
    }
    return "unknown";
}

std::tm UtcTime(std::time_t timestamp) noexcept {
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &timestamp);
#else
    gmtime_r(&timestamp, &tm);
#endif
    return tm;
}

std::string FormatLogTimestamp(int64_t timestamp_us) {
    const auto seconds = timestamp_us / 1'000'000;
    const auto micros = timestamp_us % 1'000'000;
    const auto timestamp = static_cast<std::time_t>(seconds);
    const auto tm = UtcTime(timestamp);
    char buffer[32]{};
    const auto written = std::strftime(
        buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &tm);
    if (written == 0) return {};
    return std::format("{}.{:06d}Z", std::string_view(buffer, written), micros);
}

void AppendJsonString(std::string& output, std::string_view value) {
    output.push_back('"');
    for (const unsigned char ch : value) {
        switch (ch) {
            case '"': output.append("\\\""); break;
            case '\\': output.append("\\\\"); break;
            case '\b': output.append("\\b"); break;
            case '\f': output.append("\\f"); break;
            case '\n': output.append("\\n"); break;
            case '\r': output.append("\\r"); break;
            case '\t': output.append("\\t"); break;
            default:
                if (ch < 0x20) {
                    output.append(std::format("\\u{:04x}", ch));
                } else {
                    output.push_back(static_cast<char>(ch));
                }
                break;
        }
    }
    output.push_back('"');
}

std::string ComponentName(std::string_view file) {
    const auto src = file.rfind("src");
    const auto include = file.rfind("include");
    const auto begin = src != std::string_view::npos
        ? src + 4
        : include != std::string_view::npos ? include + 8 : 0;
    auto component = file.substr(begin);
    while (!component.empty() &&
           (component.front() == '/' || component.front() == '\\')) {
        component.remove_prefix(1);
    }
    const auto extension = component.rfind('.');
    if (extension != std::string_view::npos) {
        component = component.substr(0, extension);
    }

    std::string normalized;
    normalized.reserve(component.size());
    for (const char ch : component) {
        normalized.push_back(ch == '/' || ch == '\\' ? '.' : ch);
    }
    return normalized.empty() ? "cnode" : normalized;
}

std::string FormatRecord(const LogRecord& record) {
    std::string output;
    output.reserve(record.message.size() + record.source_file.size() + 256);
    output.append("{\"timestamp\":");
    AppendJsonString(output, FormatLogTimestamp(record.timestamp_us));
    output.append(",\"level\":");
    AppendJsonString(output, LevelName(record.level));
    output.append(",\"channel\":");
    AppendJsonString(output, ChannelName(record.channel));
    output.append(",\"component\":");
    AppendJsonString(output, ComponentName(record.source_file));
    output.append(",\"event\":");
    AppendJsonString(output, record.event);
    if (record.connection) {
        output.append(std::format(
            ",\"conn_id\":{},\"worker_id\":{}",
            record.connection->conn_id,
            record.connection->worker_id));
        output.append(",\"inbound\":");
        AppendJsonString(output, record.connection->inbound);
    }
    output.append(",\"message\":");
    AppendJsonString(output, record.message);
    output.append(std::format(",\"source_line\":{}}}", record.source_line));
    return output;
}

std::string DateString(std::chrono::system_clock::time_point now) {
    return FormatLocalTime(now, "%Y-%m-%d");
}

std::string TodayDateString() {
    return DateString(std::chrono::system_clock::now());
}

bool IsDateString(std::string_view value) noexcept {
    if (value.size() != 10) return false;
    for (size_t i = 0; i < value.size(); ++i) {
        if (i == 4 || i == 7) {
            if (value[i] != '-') return false;
            continue;
        }
        if (value[i] < '0' || value[i] > '9') return false;
    }
    return true;
}

int ParseDigits(std::string_view value, size_t offset, size_t length) noexcept {
    int parsed = 0;
    for (size_t i = 0; i < length; ++i) {
        parsed = parsed * 10 + (value[offset + i] - '0');
    }
    return parsed;
}

std::optional<std::chrono::sys_days> ParseDateDays(std::string_view value) {
    if (!IsDateString(value)) return std::nullopt;

    const int year = ParseDigits(value, 0, 4);
    const int month = ParseDigits(value, 5, 2);
    const int day = ParseDigits(value, 8, 2);
    const auto ymd = std::chrono::year{year} /
        std::chrono::month{static_cast<unsigned>(month)} /
        std::chrono::day{static_cast<unsigned>(day)};
    if (!ymd.ok()) return std::nullopt;
    return std::chrono::sys_days{ymd};
}

std::optional<int64_t> DateAgeDays(std::string_view file_date,
                                   std::string_view today) {
    const auto file_days = ParseDateDays(file_date);
    const auto today_days = ParseDateDays(today);
    if (!file_days || !today_days) return std::nullopt;
    return (*today_days - *file_days).count();
}

void EnsureParentDirectory(const std::filesystem::path& path) {
    if (auto parent = path.parent_path(); !parent.empty()) {
        std::filesystem::create_directories(parent);
    }
}

bool RemovePath(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::remove(path, ec);
    return !ec;
}

bool GzipFile(const std::filesystem::path& src) {
    auto dst = src;
    dst += ".gz";

    std::ifstream in(src, std::ios::binary);
    if (!in) return false;

    std::error_code ec;
    std::filesystem::remove(dst, ec);
    if (ec) return false;

    gzFile gz = gzopen(dst.string().c_str(), "wb6");
    if (!gz) return false;

    auto fail = [&]() {
        gzclose(gz);
        RemovePath(dst);
        return false;
    };

    std::array<char, 64 * 1024> buf{};
    while (in.read(buf.data(), static_cast<std::streamsize>(buf.size())) ||
           in.gcount() > 0) {
        const auto count = in.gcount();
        if (count <= 0) continue;
        const int written = gzwrite(gz, buf.data(), static_cast<unsigned>(count));
        if (written != static_cast<int>(count)) {
            return fail();
        }
    }

    if (in.bad()) return fail();

    const int close_result = gzclose(gz);
    gz = nullptr;
    if (close_result != Z_OK) {
        RemovePath(dst);
        return false;
    }

    in.close();
    if (!RemovePath(src)) {
        return false;
    }
    return true;
}

std::string LogStem(const std::filesystem::path& configured_path,
                    std::string_view fallback_prefix) {
    if (configured_path.empty()) {
        return std::string(fallback_prefix);
    }

    auto path_for_stem = configured_path;
    if (path_for_stem.extension() == ".gz") {
        path_for_stem = path_for_stem.stem();
    }

    auto stem = path_for_stem.stem().string();
    if (stem.empty()) {
        stem = std::string(fallback_prefix);
    }
    return stem;
}

std::string LogExtension(const std::filesystem::path& configured_path) {
    if (configured_path.empty()) {
        return ".log";
    }

    auto path_for_extension = configured_path;
    if (path_for_extension.extension() == ".gz") {
        path_for_extension = path_for_extension.stem();
    }

    auto extension = path_for_extension.extension().string();
    return extension.empty() ? ".log" : extension;
}

std::filesystem::path ResolveConfiguredLogPath(
    const std::filesystem::path& log_dir,
    const std::filesystem::path& configured_path,
    std::string_view fallback_prefix) {
    std::filesystem::path path = configured_path.empty()
        ? std::filesystem::path(std::format("{}.log", fallback_prefix))
        : configured_path;
    if (path.is_absolute()) {
        return path;
    }
    return log_dir / path;
}

DailyLogSpec MakeDailySpec(const std::filesystem::path& log_dir,
                           const std::filesystem::path& configured_path,
                           std::string_view fallback_prefix) {
    const auto resolved_path =
        ResolveConfiguredLogPath(log_dir, configured_path, fallback_prefix);
    DailyLogSpec spec;
    spec.directory = resolved_path.parent_path();
    spec.stem = LogStem(resolved_path, fallback_prefix);
    spec.extension = LogExtension(resolved_path);
    return spec;
}

std::filesystem::path MakeDailyLogPath(const DailyLogSpec& spec,
                                       std::string_view date) {
    const auto filename = std::format("{}_{}{}", spec.stem, date, spec.extension);
    if (spec.directory.empty()) {
        return std::filesystem::path(filename);
    }
    return spec.directory / filename;
}

std::filesystem::path ResolveFixedLogPath(
    const std::filesystem::path& log_dir,
    const std::filesystem::path& configured_path,
    std::string_view fallback_prefix) {
    return ResolveConfiguredLogPath(log_dir, configured_path, fallback_prefix);
}

std::filesystem::path ResolveLogPath(
    const std::filesystem::path& log_dir,
    const std::filesystem::path& configured_path,
    std::string_view fallback_prefix,
    bool rotate_daily,
    std::string_view date) {
    if (!rotate_daily) {
        return ResolveFixedLogPath(log_dir, configured_path, fallback_prefix);
    }
    return MakeDailyLogPath(
        MakeDailySpec(log_dir, configured_path, fallback_prefix), date);
}

std::optional<std::string> ExtractDailyDate(std::string_view filename,
                                            const DailyLogSpec& spec) {
    const std::string prefix = spec.stem + "_";
    if (!filename.starts_with(prefix)) return std::nullopt;

    const std::string plain_suffix = spec.extension;
    const std::string gzip_suffix = spec.extension + ".gz";
    std::string_view date;

    if (filename.ends_with(gzip_suffix)) {
        date = filename.substr(
            prefix.size(), filename.size() - prefix.size() - gzip_suffix.size());
    } else if (filename.ends_with(plain_suffix)) {
        date = filename.substr(
            prefix.size(), filename.size() - prefix.size() - plain_suffix.size());
    } else {
        return std::nullopt;
    }

    if (!IsDateString(date)) return std::nullopt;
    return std::string(date);
}

void CleanupManagedFiles(const std::vector<DailyLogSpec>& specs,
                         std::string_view today,
                         uint16_t max_days,
                         bool gzip_enabled) {
    try {
        for (const auto& spec : specs) {
            const auto dir = spec.directory.empty()
                ? std::filesystem::path(".")
                : spec.directory;
            if (!std::filesystem::exists(dir) ||
                !std::filesystem::is_directory(dir)) {
                continue;
            }

            for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                if (!entry.is_regular_file()) continue;

                const auto name = entry.path().filename().string();
                const auto file_date = ExtractDailyDate(name, spec);
                if (!file_date) continue;

                if (max_days > 0) {
                    const auto age_days = DateAgeDays(*file_date, today);
                    if (age_days && *age_days > max_days) {
                        RemovePath(entry.path());
                        continue;
                    }
                }

                if (gzip_enabled &&
                    *file_date != today &&
                    name.ends_with(spec.extension)) {
                    GzipFile(entry.path());
                }
            }
        }
    } catch (...) {
    }
}

void WriteStderrFallback(LogLevel level, const std::string& msg) {
    std::lock_guard lock(g_console_mutex);
    LogRecord record{
        .channel = LogChannel::System,
        .level = level,
        .timestamp_us = NowMicros(),
        .event = "logging.fallback",
        .message = msg,
        .source_file = "src/infra/log.cpp",
    };
    std::cerr << FormatRecord(record) << std::endl;
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

    [[nodiscard]] bool Start(const std::filesystem::path& log_dir,
                             const std::filesystem::path& error_path,
                             const std::filesystem::path& access_path,
                             uint16_t max_days,
                             bool rotate_daily,
                             bool gzip_enabled) {
        Stop();

        log_dir_ = log_dir;
        max_days_ = max_days;
        rotate_daily_ = rotate_daily;
        gzip_enabled_ = gzip_enabled;
        current_date_ = TodayDateString();
        next_rotation_check_ = std::chrono::steady_clock::now() +
            kRotationCheckInterval;
        error_target_ = LogTarget{
            .fallback_prefix = "error",
            .configured_path = error_path,
            .active_path = {},
        };
        access_target_ = LogTarget{
            .fallback_prefix = "access",
            .configured_path = access_path,
            .active_path = {},
        };

        if (rotate_daily_) {
            CleanupManagedFiles(DailySpecs(), current_date_, max_days_, gzip_enabled_);
        }

        const auto resolved_error_path = ResolveTargetPath(error_target_, current_date_);
        const auto resolved_access_path = ResolveTargetPath(access_target_, current_date_);
        if (!OpenFiles(resolved_error_path, resolved_access_path)) {
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

    void Enqueue(LogRecord record) {
        if (!accepting_.load(std::memory_order_acquire)) return;

        thread_local moodycamel::ProducerToken producer_token(queue_);
        if (!queue_.try_enqueue(producer_token, std::move(record))) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void RequestFlush() noexcept {
        flush_requested_.store(true, std::memory_order_release);
    }

    const std::filesystem::path& ErrorPath() const noexcept {
        return error_target_.active_path;
    }

    const std::filesystem::path& AccessPath() const noexcept {
        return access_target_.active_path;
    }

private:
    std::vector<DailyLogSpec> DailySpecs() const {
        return {
            MakeDailySpec(
                log_dir_, error_target_.configured_path, error_target_.fallback_prefix),
            MakeDailySpec(
                log_dir_, access_target_.configured_path, access_target_.fallback_prefix),
        };
    }

    std::filesystem::path ResolveTargetPath(
        const LogTarget& target,
        std::string_view date) const {
        return ResolveLogPath(
            log_dir_, target.configured_path, target.fallback_prefix, rotate_daily_, date);
    }

    [[nodiscard]] bool OpenFiles(const std::filesystem::path& error_path,
                                 const std::filesystem::path& access_path) {
        EnsureParentDirectory(error_path);
        EnsureParentDirectory(access_path);

        std::ofstream error_file(error_path, std::ios::out | std::ios::app);
        std::ofstream access_file(access_path, std::ios::out | std::ios::app);
        if (!error_file || !access_file) {
            return false;
        }

        error_file_ = std::move(error_file);
        access_file_ = std::move(access_file);
        error_target_.active_path = error_path;
        access_target_.active_path = access_path;
        return true;
    }

    void Run() {
        while (running_.load(std::memory_order_acquire)) {
            MaybeRotate();
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

    void MaybeRotate() {
        if (!rotate_daily_) return;

        const auto now = std::chrono::steady_clock::now();
        if (now < next_rotation_check_) return;
        next_rotation_check_ = now + kRotationCheckInterval;

        const auto today = TodayDateString();
        if (today != current_date_) {
            RotateToDate(today);
        }
    }

    void RotateToDate(std::string_view date) {
        const auto old_error_path = error_target_.active_path;
        const auto old_access_path = access_target_.active_path;
        const auto new_error_path = ResolveTargetPath(error_target_, date);
        const auto new_access_path = ResolveTargetPath(access_target_, date);

        FlushFiles();
        CloseFiles();

        if (!OpenFiles(new_error_path, new_access_path)) {
            WriteStderrFallback(
                LogLevel::ERROR,
                std::format("log rotation failed date={} access={} error={}",
                            date, new_access_path.string(), new_error_path.string()));
            if (!OpenFiles(old_error_path, old_access_path)) {
                WriteStderrFallback(
                    LogLevel::ERROR,
                    std::format("log reopen failed access={} error={}",
                                old_access_path.string(), old_error_path.string()));
            }
            return;
        }

        current_date_ = std::string(date);
        WriteBackendLine(
            LogLevel::INFO,
            std::format("logging rotated date={} access={} error={}",
                        date, new_access_path.string(), new_error_path.string()));

        CompressClosedFile(old_error_path);
        if (old_access_path != old_error_path) {
            CompressClosedFile(old_access_path);
        }
        CleanupManagedFiles(DailySpecs(), current_date_, max_days_, gzip_enabled_);
    }

    void CompressClosedFile(const std::filesystem::path& path) {
        if (!gzip_enabled_ || path.empty()) return;
        if (path == error_target_.active_path || path == access_target_.active_path) return;

        std::error_code ec;
        if (!std::filesystem::is_regular_file(path, ec) || ec) return;

        if (!GzipFile(path)) {
            WriteBackendLine(
                LogLevel::WARN,
                std::format("log gzip failed file={}", path.string()));
        }
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
            case LogChannel::System:
                if (error_file_) {
                    error_file_ << FormatRecord(record) << '\n';
                    if (record.level >= LogLevel::WARN) {
                        error_file_.flush();
                    }
                }
                break;
            case LogChannel::Connection:
                if (access_file_) {
                    access_file_ << FormatRecord(record) << '\n';
                }
                break;
        }
    }

    void WriteBackendLine(LogLevel level, std::string msg) {
        if (error_file_) {
            LogRecord record{
                .channel = LogChannel::System,
                .level = level,
                .timestamp_us = NowMicros(),
                .event = "logging.backend",
                .message = std::move(msg),
                .source_file = "src/infra/log.cpp",
            };
            error_file_ << FormatRecord(record) << '\n';
            if (level >= LogLevel::WARN) {
                error_file_.flush();
            }
            return;
        }
        WriteStderrFallback(level, msg);
    }

    void ReportDrops() {
        const auto dropped = dropped_.exchange(0, std::memory_order_acq_rel);
        if (dropped == 0 || !error_file_) return;

        LogRecord record{
            .channel = LogChannel::System,
            .level = LogLevel::WARN,
            .timestamp_us = NowMicros(),
            .event = "logging.queue_dropped",
            .message = std::format("records={}", dropped),
            .source_file = "src/infra/log.cpp",
        };
        error_file_ << FormatRecord(record) << '\n';
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
    std::filesystem::path log_dir_;
    uint16_t max_days_{15};
    bool rotate_daily_{true};
    bool gzip_enabled_{true};
    std::string current_date_;
    std::chrono::steady_clock::time_point next_rotation_check_{};
    LogTarget error_target_{
        .fallback_prefix = "error",
        .configured_path = {},
        .active_path = {},
    };
    LogTarget access_target_{
        .fallback_prefix = "access",
        .configured_path = {},
        .active_path = {},
    };
    std::ofstream error_file_;
    std::ofstream access_file_;
};

AsyncLogBackend g_async_log_backend;

}  // namespace

bool Log::Init(const std::string& level,
               const std::filesystem::path& log_dir,
               uint16_t max_days,
               const std::filesystem::path& access_path,
               const std::filesystem::path& error_path,
               bool rotate_daily,
               bool gzip) {
    {
        std::lock_guard lock(g_lifecycle_mutex);
        if (initialized_.load(std::memory_order_acquire)) return true;

        min_level_.store(ParseLevel(level), std::memory_order_release);

        try {
            if (!g_async_log_backend.Start(
                    log_dir, error_path, access_path, max_days, rotate_daily, gzip)) {
                std::cerr << "Log initialization failed: cannot open access/error log files"
                          << std::endl;
                return false;
            }

            const auto resolved_error_path = g_async_log_backend.ErrorPath();
            const auto resolved_access_path = g_async_log_backend.AccessPath();
            const auto rotation = rotate_daily ? "daily" : "fixed";
            const auto compression = (rotate_daily && gzip) ? "gzip" : "none";

            initialized_.store(true, std::memory_order_release);
            WriteConsole(LogLevel::INFO, std::format(
                "logging level={} access={} error={} rotation={} compression={} retention={}d",
                level,
                resolved_access_path.string(),
                resolved_error_path.string(),
                rotation,
                compression,
                max_days));
            WriteSystem(LogLevel::INFO, std::format(
                "logging initialized level={} access={} error={} dir={} rotation={} compression={} retention_days={}",
                level,
                resolved_access_path.string(),
                resolved_error_path.string(),
                log_dir.string(),
                rotation,
                compression,
                max_days));
        } catch (const std::exception& e) {
            std::cerr << "Log initialization failed: " << e.what() << std::endl;
            g_async_log_backend.Stop();
            return false;
        }
    }

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

void Log::WriteSystem(LogLevel level,
                      std::string message,
                      std::string_view event,
                      std::source_location location) {
    if (!ShouldLog(level)) return;
    if (!initialized_.load(std::memory_order_acquire)) {
        if (level >= LogLevel::WARN) {
            WriteStderrFallback(level, message);
        }
        return;
    }

    g_async_log_backend.Enqueue(LogRecord{
        .channel = LogChannel::System,
        .level = level,
        .timestamp_us = NowMicros(),
        .event = std::string(event),
        .message = std::move(message),
        .source_file = location.file_name(),
        .source_line = location.line(),
    });
}

void Log::WriteConnection(LogLevel level,
                          std::string message,
                          std::string_view event,
                          std::source_location location) {
    if (!ShouldLog(level)) return;
    if (!initialized_.load(std::memory_order_acquire)) return;

    g_async_log_backend.Enqueue(LogRecord{
        .channel = LogChannel::Connection,
        .level = level,
        .timestamp_us = NowMicros(),
        .event = std::string(event),
        .message = std::move(message),
        .source_file = location.file_name(),
        .source_line = location.line(),
    });
}

void Log::WriteConnection(LogLevel level,
                          ConnectionLogContext context,
                          std::string message,
                          std::string_view event,
                          std::source_location location) {
    if (!ShouldLog(level)) return;
    if (!initialized_.load(std::memory_order_acquire)) return;

    g_async_log_backend.Enqueue(LogRecord{
        .channel = LogChannel::Connection,
        .level = level,
        .timestamp_us = NowMicros(),
        .event = std::string(event),
        .message = std::move(message),
        .source_file = location.file_name(),
        .source_line = location.line(),
        .connection = std::move(context),
    });
}

void Log::WriteConsole(LogLevel level,
                       std::string message,
                       std::string_view event,
                       std::source_location location) {
    std::lock_guard lock(g_console_mutex);
    if (message.empty()) {
        std::cout << std::endl;
        return;
    }
    LogRecord record{
        .channel = LogChannel::System,
        .level = level,
        .timestamp_us = NowMicros(),
        .event = std::string(event),
        .message = std::move(message),
        .source_file = location.file_name(),
        .source_line = location.line(),
    };
    std::cout << FormatRecord(record) << std::endl;
}

bool Log::ShouldLog(LogLevel level) noexcept {
    const auto min_level = min_level_.load(std::memory_order_relaxed);
    if (min_level == LogLevel::NONE) return false;
    return level >= min_level;
}

}  // namespace acpp
