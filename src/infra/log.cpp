#include "infra/log.hpp"

#include "common/clock.hpp"

#include <concurrentqueue.h>
#include <lightweightsemaphore.h>
#include <zlib.h>

#include <cerrno>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <limits>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>


std::atomic<LogLevel> Log::min_level_{LogLevel::INFO};
std::atomic_bool Log::initialized_{false};

namespace {

using namespace std::chrono_literals;

enum class LogChannel {
    Error,
    Access,
    Console
};

struct LogRecord {
    LogChannel channel{LogChannel::Error};
    LogLevel level{LogLevel::INFO};
    int64_t timestamp_us{0};
    std::string message;
    std::string_view source_file;
    std::optional<ConnectionLogContext> connection;
};

struct LogTarget {
    std::string fallback_prefix;
    std::filesystem::path configured_path;
    std::filesystem::path active_path;
    bool failed{false};
    bool close_failure_reported{false};
    std::chrono::seconds retry_delay{1};
    uint64_t discarded{0};
    std::chrono::steady_clock::time_point retry_at{};
};

struct DailyLogSpec {
    std::filesystem::path directory;
    std::string stem;
    std::string extension{".log"};
};

std::mutex g_lifecycle_mutex;
// The writer drains continuously. Keep a bounded burst window without paying
// for 65K preallocated LogRecord slots throughout the process lifetime.
constexpr size_t kAsyncLogQueueCapacity = 8 * 1024;
constexpr size_t kWriterBatchSize = 64;
// Retry delay after a daily rotation fails to open the new files; the old
// files stay active until a retry succeeds.
constexpr auto kRotationRetryDelay = 1s;

std::string_view LevelName(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::TRACE: return "Debug";
        case LogLevel::DEBUG: return "Debug";
        case LogLevel::INFO:  return "Info";
        case LogLevel::WARN:  return "Warning";
        case LogLevel::ERROR: return "Error";
        case LogLevel::NONE:  return "None";
    }
    return "?";
}

std::string FormatLogTimestamp(int64_t timestamp_us) {
    const auto seconds = timestamp_us / 1'000'000;
    const auto timestamp = static_cast<std::time_t>(seconds);
    const auto tm = LocalTime(timestamp);
    char buffer[32]{};
    const auto written = std::strftime(
        buffer, sizeof(buffer), "%Y/%m/%d %H:%M:%S", &tm);
    if (written == 0) return {};
    return std::format("{}.{:06}", std::string_view(buffer, written),
                       timestamp_us % 1'000'000);
}

std::string FormatConsoleTimestamp(int64_t timestamp_us) {
    const auto tm = LocalTime(static_cast<std::time_t>(timestamp_us / 1'000'000));
    char buffer[48]{};
    const auto written = std::strftime(
        buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S%z", &tm);
    if (written == 0) return {};
    std::string result(buffer, written);
    if (result.size() >= 5 &&
        (result[result.size() - 5] == '+' || result[result.size() - 5] == '-')) {
        result.insert(result.size() - 2, 1, ':');
    }
    return result;
}

std::string_view ConsoleLevelName(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::TRACE: return "trace";
        case LogLevel::DEBUG: return "debug";
        case LogLevel::INFO: return "info";
        case LogLevel::WARN: return "warning";
        case LogLevel::ERROR: return "error";
        case LogLevel::NONE: return "none";
    }
    return "unknown";
}

size_t FindPathSegment(std::string_view file, std::string_view name) {
    size_t pos = file.rfind(name);
    while (pos != std::string_view::npos) {
        const bool left_ok =
            pos == 0 || file[pos - 1] == '/' || file[pos - 1] == '\\';
        const auto end = pos + name.size();
        const bool right_ok =
            end == file.size() || file[end] == '/' || file[end] == '\\';
        if (left_ok && right_ok) {
            return pos;
        }
        if (pos == 0) {
            break;
        }
        pos = file.rfind(name, pos - 1);
    }
    return std::string_view::npos;
}

std::string_view AfterMarker(std::string_view file, std::string_view name) {
    const auto pos = FindPathSegment(file, name);
    if (pos == std::string_view::npos) {
        return {};
    }
    auto rest = file.substr(pos + name.size());
    while (!rest.empty() && (rest.front() == '/' || rest.front() == '\\')) {
        rest.remove_prefix(1);
    }
    return rest;
}

std::string_view TransportInternetComponent(std::string_view relative) {
    constexpr std::string_view kPrefix = "transport/internet/";
    if (!relative.starts_with(kPrefix)) {
        return {};
    }
    const auto leaf = relative.substr(kPrefix.size());
    if (leaf.starts_with("tcp")) {
        return "transport/internet/tcp";
    }
    if (leaf.starts_with("udp")) {
        return "transport/internet/udp";
    }
    if (leaf.starts_with("tls") || leaf.starts_with("ssl")) {
        return "transport/internet/tls";
    }
    if (leaf.starts_with("reality")) {
        return "transport/internet/reality";
    }
    if (leaf.starts_with("ws") || leaf.find("websocket") != std::string_view::npos) {
        return "transport/internet/websocket";
    }
    if (leaf.starts_with("grpc")) {
        return "transport/internet/grpc";
    }
    if (leaf.starts_with("xhttp")) {
        return "transport/internet/xhttp";
    }
    if (leaf.find("httpupgrade") != std::string_view::npos ||
        leaf.find("http_upgrade") != std::string_view::npos) {
        return "transport/internet/httpupgrade";
    }
    return "transport/internet";
}

std::string ComponentName(std::string_view file) {
    auto relative = AfterMarker(file, "src");
    if (relative.empty()) {
        relative = AfterMarker(file, "include");
    }
    if (relative.empty()) {
        relative = file;
    }
    if (relative.starts_with("acppnode") &&
        (relative.size() == 8 || relative[8] == '/' || relative[8] == '\\')) {
        relative.remove_prefix(8);
        while (!relative.empty() &&
               (relative.front() == '/' || relative.front() == '\\')) {
            relative.remove_prefix(1);
        }
    }

    const auto extension = relative.rfind('.');
    if (extension != std::string_view::npos) {
        relative = relative.substr(0, extension);
    }

    std::string normalized;
    normalized.reserve(relative.size());
    for (const char ch : relative) {
        normalized.push_back(ch == '\\' ? '/' : ch);
    }
    if (normalized.empty()) {
        return "cnode";
    }

    if (const auto transport = TransportInternetComponent(normalized);
        !transport.empty()) {
        return std::string(transport);
    }

    size_t parts = 1;
    for (const char ch : normalized) {
        if (ch == '/') {
            ++parts;
        }
    }
    if (parts >= 3) {
        const auto slash = normalized.rfind('/');
        if (slash != std::string::npos && slash > 0) {
            normalized.resize(slash);
        }
    }
    return normalized;
}

std::string EscapeLogText(std::string_view text, bool quoted = false) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(text.size() + (quoted ? 2 : 0));
    if (quoted) result.push_back('"');
    for (const unsigned char ch : text) {
        switch (ch) {
            case '\n': result.append("\\n"); break;
            case '\r': result.append("\\r"); break;
            case '\t': result.append("\\t"); break;
            case '"': result.append(quoted ? "\\\"" : "\""); break;
            case '\\': result.append(quoted ? "\\\\" : "\\"); break;
            default:
                if (ch < 0x20 || ch == 0x7f) {
                    result.append("\\x");
                    result.push_back(hex[ch >> 4]);
                    result.push_back(hex[ch & 0x0f]);
                } else {
                    result.push_back(static_cast<char>(ch));
                }
                break;
        }
    }
    if (quoted) result.push_back('"');
    return result;
}

std::string ConsoleField(std::string_view value) {
    const bool quote = value.empty() || value.find_first_not_of(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-") !=
        std::string_view::npos;
    return EscapeLogText(value, quote);
}

std::string PanelOrigin(std::string_view host) {
    const auto scheme_end = host.find("://");
    if (scheme_end == std::string_view::npos) return "<invalid host>";
    const auto scheme = host.substr(0, scheme_end);
    if (scheme != "https" && scheme != "http") return "<invalid host>";
    auto authority = host.substr(scheme_end + 3);
    authority = authority.substr(0, authority.find_first_of("/?#"));
    if (const auto credentials = authority.rfind('@'); credentials != std::string_view::npos) {
        authority.remove_prefix(credentials + 1);
    }
    if (authority.empty() || authority.find_first_of("\r\n\t\\ ") != std::string_view::npos)
        return "<invalid host>";
    return std::format("{}://{}", scheme, authority);
}

std::string FormatConsoleRecord(const LogRecord& record,
                                const PanelLogContext* panel = nullptr) {
    auto line = std::format("time=\"{}\" level={} msg={}",
        FormatConsoleTimestamp(record.timestamp_us), ConsoleLevelName(record.level),
        EscapeLogText(record.message, true));
    if (panel) {
        if (!panel->host.empty()) line.append(" Host=").append(ConsoleField(PanelOrigin(panel->host)));
        if (panel->node_id > 0) line.append(std::format(" ID={}", panel->node_id));
        if (!panel->name.empty()) line.append(" Name=").append(ConsoleField(panel->name));
        if (!panel->type.empty()) line.append(" Type=").append(ConsoleField(panel->type));
    }
    return line;
}

std::string FormatRecord(const LogRecord& record) {
    if (record.channel == LogChannel::Console) return FormatConsoleRecord(record);
    const auto timestamp = FormatLogTimestamp(record.timestamp_us);
    const auto message = EscapeLogText(record.message);
    if (record.channel == LogChannel::Access) {
        return std::format("{} {}", timestamp, message);
    }
    auto line = std::format("{} [{}] ", timestamp, LevelName(record.level));
    if (record.connection && record.connection->conn_id != 0) {
        line.append(std::format("[{}] ", record.connection->conn_id));
    }
    line.append(ComponentName(record.source_file)).append(": ");
    if (record.connection) {
        const auto& context = *record.connection;
        if (!context.inbound_tag.empty()) {
            line.push_back('[');
            line.append(EscapeLogText(context.inbound_tag));
            if (!context.outbound_tag.empty() && context.inbound_tag != context.outbound_tag) {
                line.append(" -> ").append(EscapeLogText(context.outbound_tag));
            }
            line.append("] ");
        } else if (!context.outbound_tag.empty()) {
            line.append("[outbound ").append(EscapeLogText(context.outbound_tag)).append("] ");
        }
        if (context.user_id > 0) line.append(std::format("user:{} ", context.user_id));
    }
    line.append(message);
    return line;
}

std::string DateString(std::chrono::system_clock::time_point now) {
    return FormatLocalTime(now, "%Y-%m-%d");
}

// Next local day boundary; tm_isdst = -1 lets mktime resolve DST changes.
// The writer compares it against the system clock before every batch, so a
// clock step still rotates before the next record is written.
std::chrono::system_clock::time_point NextLocalMidnight(
    std::chrono::system_clock::time_point now) {
    auto tm = LocalTime(std::chrono::system_clock::to_time_t(now));
    tm.tm_mday += 1;
    tm.tm_hour = 0;
    tm.tm_min = 0;
    tm.tm_sec = 0;
    tm.tm_isdst = -1;
    const auto midnight = std::mktime(&tm);
    if (midnight == static_cast<std::time_t>(-1)) {
        return now + kRotationRetryDelay;
    }
    return std::chrono::system_clock::from_time_t(midnight);
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
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
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

std::filesystem::path ResolveLogPath(
    const std::filesystem::path& log_dir,
    const std::filesystem::path& configured_path,
    std::string_view fallback_prefix,
    bool rotate_daily,
    std::string_view date) {
    if (!rotate_daily) {
        return ResolveConfiguredLogPath(log_dir, configured_path, fallback_prefix);
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
        if (filename.size() - prefix.size() < gzip_suffix.size()) {
            return std::nullopt;
        }
        date = filename.substr(
            prefix.size(), filename.size() - prefix.size() - gzip_suffix.size());
    } else if (filename.ends_with(plain_suffix)) {
        if (filename.size() - prefix.size() < plain_suffix.size()) {
            return std::nullopt;
        }
        date = filename.substr(
            prefix.size(), filename.size() - prefix.size() - plain_suffix.size());
    } else {
        return std::nullopt;
    }

    if (!IsDateString(date)) return std::nullopt;
    return std::string(date);
}

// Console owns separate nonblocking open descriptions: setting O_NONBLOCK on
// dup(stdout) would also change the caller's descriptor. Linux is the supported
// runtime; /proc/self/fd reopens pipes and terminals without that side effect.
// Pipe records are at most PIPE_BUF, hence a full pipe loses a whole record,
// never a prefix. No console write or join waits for a reader.
class AsyncConsole {
    static constexpr size_t kCapacity = 256;
    static constexpr size_t kMaxRecordBytes = 4096;
    struct Record {
        std::string line;
        bool error{false};
    };
    struct Output {
        int fd{-1};
        dev_t device{};
        ino_t inode{};
        size_t atomic_limit{kMaxRecordBytes};
        bool failed{false};
        bool partial_write{false};
        bool socket{false};
    };

public:
    AsyncConsole() : queue_(kCapacity) {}
    ~AsyncConsole() { Stop(); }

    void Start() {
        if (running_.load(std::memory_order_acquire)) return;
        pending_.store(0, std::memory_order_relaxed);
        dropped_.store(0, std::memory_order_relaxed);
        unreported_drops_ = 0;
        Open(stdout_, STDOUT_FILENO);
        Open(stderr_, STDERR_FILENO);
        // stdout/stderr frequently alias the same journald socket. A partial
        // record retires the underlying sink, not just the logical channel:
        // a diagnostic must never be appended through the other descriptor.
        error_output_ = SameSink(stdout_, stderr_) ? &stdout_ : &stderr_;
        running_.store(true, std::memory_order_release);
        try {
            writer_ = std::thread([this] { Run(); });
        } catch (...) {
            running_.store(false, std::memory_order_release);
            Close();
            throw;
        }
        accepting_.store(true, std::memory_order_release);
    }

    void Stop() {
        accepting_.store(false, std::memory_order_release);
        auto producers = producers_.load(std::memory_order_acquire);
        while (producers != 0) {
            producers_.wait(producers, std::memory_order_acquire);
            producers = producers_.load(std::memory_order_acquire);
        }
        running_.store(false, std::memory_order_release);
        wakeup_.signal();
        if (writer_.joinable()) writer_.join();
        if (stdout_.fd >= 0 || stderr_.fd >= 0) {
            auto next_report = std::chrono::steady_clock::time_point{};
            DrainAvailable();
            ReportDrops(next_report, true);
        }
        Close();
    }

    void Enqueue(std::string line, bool error) {
        line.push_back('\n');
        {
            producers_.fetch_add(1, std::memory_order_acq_rel);
            struct ReleaseProducer {
                std::atomic<size_t>& count;
                ~ReleaseProducer() {
                    if (count.fetch_sub(1, std::memory_order_acq_rel) == 1) count.notify_all();
                }
            } release{producers_};
            if (accepting_.load(std::memory_order_acquire)) {
                if (line.size() > kMaxRecordBytes) {
                    dropped_.fetch_add(1, std::memory_order_relaxed);
                    wakeup_.signal();
                    return;
                }
                const auto previous = pending_.fetch_add(1, std::memory_order_acq_rel);
                if (previous >= kCapacity || !queue_.enqueue(Record{std::move(line), error})) {
                    pending_.fetch_sub(1, std::memory_order_acq_rel);
                    dropped_.fetch_add(1, std::memory_order_relaxed);
                }
                wakeup_.signal();
                return;
            }
        }
        // Startup/after-shutdown failures still have a bounded diagnostic
        // path even when the logging threads were never started.
        Output output;
        Open(output, error ? STDERR_FILENO : STDOUT_FILENO);
        const auto written = Send(output, line);
        if (!written) Emergency("console startup write-failure: record dropped", output);
        if (output.fd >= 0) ::close(output.fd);
    }

private:
    static bool SameSink(const Output& left, const Output& right) {
        return left.fd >= 0 && right.fd >= 0 &&
               left.device == right.device && left.inode == right.inode;
    }

    static void Open(Output& output, int fd) {
        output = Output{};
        struct stat status{};
        if (::fstat(fd, &status) != 0) return;
        output.device = status.st_dev;
        output.inode = status.st_ino;
        output.socket = S_ISSOCK(status.st_mode);
        if (output.socket || S_ISREG(status.st_mode)) {
            // MSG_DONTWAIT preserves socket flags. Regular files must share
            // the caller's offset so direct emergency writes cannot overwrite
            // console records; O_NONBLOCK does not make file I/O asynchronous.
            output.fd = ::fcntl(fd, F_DUPFD_CLOEXEC, 3);
        } else {
            const auto path = std::format("/proc/self/fd/{}", fd);
            output.fd = ::open(path.c_str(), O_WRONLY | O_APPEND | O_NONBLOCK | O_CLOEXEC);
        }
        if (output.fd < 0) return;
        if (S_ISFIFO(status.st_mode)) {
            const auto limit = ::fpathconf(output.fd, _PC_PIPE_BUF);
            if (limit > 0) output.atomic_limit =
                std::min(kMaxRecordBytes, static_cast<size_t>(limit));
        }
    }

    static bool Send(Output& output, std::string_view line) {
        if (output.fd < 0 || output.failed || line.size() > output.atomic_limit) return false;
        if (output.socket) {
            const auto count = ::send(output.fd, line.data(), line.size(),
                                      MSG_DONTWAIT | MSG_NOSIGNAL);
            if (count == static_cast<ssize_t>(line.size())) return true;
            output.partial_write = count > 0;
            if (count > 0 || (count < 0 && errno != EAGAIN &&
                             errno != EWOULDBLOCK && errno != EINTR)) {
                output.failed = true;
            }
            return false;
        }
        sigset_t signals, previous, pending;
        sigemptyset(&signals);
        sigaddset(&signals, SIGPIPE);
        if (pthread_sigmask(SIG_BLOCK, &signals, &previous) != 0) return false;
        sigpending(&pending);
        const auto count = ::write(output.fd, line.data(), line.size());
        const auto error = errno;
        if (count < 0 && error == EPIPE && !sigismember(&pending, SIGPIPE)) {
            timespec timeout{};
            sigtimedwait(&signals, nullptr, &timeout);
        }
        pthread_sigmask(SIG_SETMASK, &previous, nullptr);
        if (count == static_cast<ssize_t>(line.size())) return true;
        if (count > 0) {
            // Non-pipe targets may accept a prefix. Retire the sink rather than
            // concatenate a later record onto it; report the truncation on the
            // independent diagnostic output.
            output.failed = true;
            output.partial_write = true;
        } else if (count < 0 && error != EAGAIN && error != EWOULDBLOCK && error != EINTR) {
            output.failed = true;
        }
        return false;
    }

    static void Emergency(std::string_view text, const Output& failed_output) {
        Output output;
        Open(output, STDERR_FILENO);
        if (failed_output.partial_write && SameSink(output, failed_output)) {
            ::close(output.fd);
            return;
        }
        if (output.fd >= 0) {
            LogRecord record{
                .channel = LogChannel::Console,
                .level = LogLevel::ERROR,
                .timestamp_us = NowMicros(),
                .message = std::string(text),
                .source_file = {},
                .connection = std::nullopt,
            };
            Send(output, FormatConsoleRecord(record) + '\n');
            ::close(output.fd);
        }
    }

    void DrainAvailable() {
        Record record;
        while (queue_.try_dequeue(record)) {
            pending_.fetch_sub(1, std::memory_order_release);
            auto& output = record.error ? *error_output_ : stdout_;
            if (!Send(output, record.line)) {
                dropped_.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    void ReportDrops(std::chrono::steady_clock::time_point& next_report, bool force) {
        const auto dropped = dropped_.exchange(0, std::memory_order_acq_rel);
        unreported_drops_ += dropped;
        const auto now = std::chrono::steady_clock::now();
        if (unreported_drops_ != 0 && (force || now >= next_report)) {
            next_report = now + 1s;
            LogRecord diagnostic{
                .channel = LogChannel::Console,
                .level = LogLevel::WARN,
                .timestamp_us = NowMicros(),
                .message = std::format(
                    "console queue/write-failure dropped {} records; stdout_failed={} stderr_failed={} stdout_partial_record={} stderr_partial_record={}",
                    unreported_drops_, stdout_.failed, error_output_->failed,
                    stdout_.partial_write, error_output_->partial_write),
                .source_file = {},
                .connection = std::nullopt,
            };
            auto line = FormatConsoleRecord(diagnostic) + '\n';
            if (Send(*error_output_, line)) unreported_drops_ = 0;
        }
    }

    void Run() {
        auto next_report = std::chrono::steady_clock::time_point{};
        while (running_.load(std::memory_order_acquire)) {
            std::int64_t wait_us = -1;
            if (unreported_drops_ > 0 || dropped_.load(std::memory_order_relaxed) > 0) {
                const auto remaining = next_report - std::chrono::steady_clock::now();
                wait_us = remaining <= std::chrono::steady_clock::duration::zero()
                    ? 0
                    : std::chrono::ceil<std::chrono::microseconds>(remaining).count();
            }
            wakeup_.waitMany(
                std::numeric_limits<moodycamel::LightweightSemaphore::ssize_t>::max(),
                wait_us);
            DrainAvailable();
            ReportDrops(next_report, !running_.load(std::memory_order_acquire));
        }
        DrainAvailable();
        ReportDrops(next_report, true);
    }

    void Close() {
        if (stdout_.fd >= 0) ::close(std::exchange(stdout_.fd, -1));
        if (stderr_.fd >= 0) ::close(std::exchange(stderr_.fd, -1));
        dropped_.store(0, std::memory_order_relaxed);
        unreported_drops_ = 0;
    }

    moodycamel::ConcurrentQueue<Record> queue_;
    moodycamel::LightweightSemaphore wakeup_{0, 0};
    std::atomic_bool accepting_{false};
    std::atomic_bool running_{false};
    std::atomic<size_t> pending_{0};
    std::atomic<size_t> producers_{0};
    std::atomic<uint64_t> dropped_{0};
    uint64_t unreported_drops_{0};
    Output stdout_;
    Output stderr_;
    Output* error_output_{&stderr_};
    std::thread writer_;
};

AsyncConsole g_console;

void WriteStderrFallback(LogLevel level, const std::string& msg) {
    LogRecord record{
        .channel = LogChannel::Console,
        .level = level,
        .timestamp_us = NowMicros(),
        .message = msg,
        .source_file = "src/infra/log.cpp",
        .connection = std::nullopt,
    };
    g_console.Enqueue(FormatConsoleRecord(record), true);
}

class AsyncLogBackend {
public:
    AsyncLogBackend() : queue_(kAsyncLogQueueCapacity) {}

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
        const auto now = std::chrono::system_clock::now();
        current_date_ = DateString(now);
        next_rotation_at_ = NextLocalMidnight(now);
        pending_.store(0, std::memory_order_relaxed);
        dropped_.store(0, std::memory_order_relaxed);
        pending_drops_ = 0;
        next_drop_report_ = {};
        flush_requested_.store(false, std::memory_order_relaxed);
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
        error_target_.discarded = 0;
        access_target_.discarded = 0;

        const auto resolved_error_path = ResolveTargetPath(error_target_, current_date_);
        const auto resolved_access_path = ResolveTargetPath(access_target_, current_date_);
        if (Log::ResolveTargetPath(
                log_dir_, error_path, error_target_.fallback_prefix, rotate_daily_, current_date_) ==
            Log::ResolveTargetPath(
                log_dir_, access_path, access_target_.fallback_prefix, rotate_daily_, current_date_)) {
            return false;
        }
        if (!OpenFiles(resolved_error_path, resolved_access_path)) {
            CloseFiles();
            return false;
        }

        if (rotate_daily_) {
            CleanupManagedFiles();
        }

        running_.store(true, std::memory_order_release);
        try {
            writer_ = std::thread([this] { Run(); });
        } catch (...) {
            running_.store(false, std::memory_order_release);
            CloseFiles();
            throw;
        }
        accepting_.store(true, std::memory_order_release);
        return true;
    }

    void Stop() {
        accepting_.store(false, std::memory_order_release);
        auto producers = producers_.load(std::memory_order_acquire);
        while (producers != 0) {
            producers_.wait(producers, std::memory_order_acquire);
            producers = producers_.load(std::memory_order_acquire);
        }
        if (running_.exchange(false, std::memory_order_acq_rel)) {
            writer_wakeup_.signal();
        }
        if (writer_.joinable()) {
            writer_.join();
        }
        std::array<LogRecord, kWriterBatchSize> batch;
        DrainAvailable(batch);
        ReportDrops();
        FlushFiles();
        CloseFiles();
    }

    void Enqueue(LogRecord record) {
        producers_.fetch_add(1, std::memory_order_acq_rel);
        struct ReleaseProducer {
            std::atomic<size_t>& count;
            ~ReleaseProducer() {
                if (count.fetch_sub(1, std::memory_order_acq_rel) == 1) count.notify_all();
            }
        } release{producers_};
        if (!accepting_.load(std::memory_order_acquire)) return;

        if (pending_.fetch_add(1, std::memory_order_acq_rel) >= kAsyncLogQueueCapacity ||
            !queue_.enqueue(std::move(record))) {
            pending_.fetch_sub(1, std::memory_order_acq_rel);
            dropped_.fetch_add(1, std::memory_order_relaxed);
            writer_wakeup_.signal();
            return;
        }
        writer_wakeup_.signal();
    }

    void RequestFlush() {
        flush_requested_.store(true, std::memory_order_release);
        writer_wakeup_.signal();
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
        error_target_.failed = false;
        access_target_.failed = false;
        return true;
    }

    // Each successful enqueue, flush request, and shutdown posts one semaphore
    // count after publishing its state; the writer consumes every pending count
    // per wakeup and then drains the queue, so no posted record is left behind.
    void Run() {
        std::array<LogRecord, kWriterBatchSize> batch;
        while (running_.load(std::memory_order_acquire)) {
            writer_wakeup_.waitMany(
                std::numeric_limits<moodycamel::LightweightSemaphore::ssize_t>::max(),
                IdleWaitMicros());
            MaybeRotate();
            DrainAvailable(batch);
            ReportDrops();
            if (flush_requested_.exchange(false, std::memory_order_acq_rel)) {
                FlushFiles();
            }
        }

        DrainAvailable(batch);
        ReportDrops();
        FlushFiles();
    }

    // Fixed-path logging has no deadline unless rate-limited drop reporting is pending.
    std::int64_t IdleWaitMicros() const {
        std::int64_t wait_us = -1;
        if (rotate_daily_) {
            const auto remaining = next_rotation_at_ - std::chrono::system_clock::now();
            wait_us = remaining <= std::chrono::system_clock::duration::zero()
                ? 0
                : std::chrono::ceil<std::chrono::microseconds>(remaining).count();
        }
        if (pending_drops_ > 0 || dropped_.load(std::memory_order_relaxed) > 0) {
            const auto remaining = next_drop_report_ - std::chrono::steady_clock::now();
            const std::int64_t drop_wait_us =
                remaining <= std::chrono::steady_clock::duration::zero()
                    ? 0
                    : std::chrono::ceil<std::chrono::microseconds>(remaining).count();
            wait_us = wait_us < 0 ? drop_wait_us : std::min(wait_us, drop_wait_us);
        }
        return wait_us;
    }

    void MaybeRotate() {
        if (!rotate_daily_) return;

        const auto now = std::chrono::system_clock::now();
        if (now < next_rotation_at_) return;

        const auto today = DateString(now);
        if (today == current_date_ || RotateToDate(today)) {
            next_rotation_at_ = NextLocalMidnight(now);
        } else {
            next_rotation_at_ = now + kRotationRetryDelay;
        }
    }

    [[nodiscard]] bool RotateToDate(std::string_view date) {
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
            return false;
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
        CleanupManagedFiles();
        return true;
    }

    // Retention and compression sweep over the date-suffixed files of both
    // targets; failures are reported, never silently dropped.
    void CleanupManagedFiles() {
        try {
            for (const auto& spec : DailySpecs()) {
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

                    if (max_days_ > 0) {
                        const auto age_days = DateAgeDays(*file_date, current_date_);
                        if (age_days && *age_days > max_days_) {
                            if (!RemovePath(entry.path())) {
                                WriteBackendLine(
                                    LogLevel::WARN,
                                    std::format("log retention remove failed file={}",
                                                entry.path().string()));
                            }
                            continue;
                        }
                    }

                    if (gzip_enabled_ &&
                        *file_date != current_date_ &&
                        name.ends_with(spec.extension) &&
                        !GzipFile(entry.path())) {
                        WriteBackendLine(
                            LogLevel::WARN,
                            std::format("log gzip failed file={}", entry.path().string()));
                    }
                }
            }
        } catch (const std::exception& e) {
            WriteBackendLine(
                LogLevel::WARN,
                std::format("log cleanup failed error={}", e.what()));
        }
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

    void DrainAvailable(std::span<LogRecord> batch) {
        size_t count = 0;
        while ((count = queue_.try_dequeue_bulk(batch.begin(), batch.size())) > 0) {
            pending_.fetch_sub(count, std::memory_order_acq_rel);
            for (auto& record : batch.first(count)) {
                WriteRecord(record);
                record = LogRecord{};
            }
        }
    }

    void SinkFailure(LogTarget& target, std::string_view operation) {
        if (target.failed) return;
        target.failed = true;
        target.retry_delay = 1s;
        target.retry_at = std::chrono::steady_clock::now() + 1s;
        WriteStderrFallback(LogLevel::ERROR, std::format(
            "log channel={} write-failure operation={} path={}; sink disabled pending recovery",
            target.fallback_prefix, operation, target.active_path.string()));
    }

    // Real records trigger one reopen after an exponentially backed-off
    // deadline (capped at 30s). Never permanently abandon a recoverable disk,
    // poll an idle sink, or write synthetic recovery records to the access log.
    bool Recover(std::ofstream& file, LogTarget& target) {
        if (!running_.load(std::memory_order_acquire) ||
            std::chrono::steady_clock::now() < target.retry_at) return false;
        target.retry_at = std::chrono::steady_clock::now() + target.retry_delay;
        target.retry_delay = std::min(target.retry_delay * 2, 30s);
        CloseFile(file, target);
        file.clear();
        file.open(target.active_path, std::ios::out | std::ios::app);
        return static_cast<bool>(file);
    }

    bool WriteLine(std::ofstream& file, LogTarget& target, const LogRecord& record) {
        const bool recovering = target.failed;
        if (recovering && !Recover(file, target)) {
            ++target.discarded;
            return false;
        }
        if (!file.is_open()) {
            SinkFailure(target, "not-open");
            ++target.discarded;
            return false;
        }
        file << FormatRecord(record) << '\n';
        if (!file) {
            SinkFailure(target, "write");
            ++target.discarded;
            return false;
        }
        if (recovering || record.level >= LogLevel::WARN) {
            file.flush();
            if (!file) {
                SinkFailure(target, "flush");
                ++target.discarded;
                return false;
            }
        }
        if (recovering) {
            target.failed = false;
            target.close_failure_reported = false;
            WriteStderrFallback(LogLevel::WARN, std::format(
                "log channel={} recovered; discarded={}",
                target.fallback_prefix, target.discarded));
            target.discarded = 0;
        }
        return true;
    }

    void WriteRecord(const LogRecord& record) {
        switch (record.channel) {
            case LogChannel::Error:
                WriteLine(error_file_, error_target_, record);
                break;
            case LogChannel::Access:
                WriteLine(access_file_, access_target_, record);
                break;
            case LogChannel::Console:
                break;
        }
    }

    void WriteBackendLine(LogLevel level, std::string msg) {
        LogRecord record{
            .channel = LogChannel::Error,
            .level = level,
            .timestamp_us = NowMicros(),
            .message = std::move(msg),
            .source_file = "src/infra/log.cpp",
            .connection = std::nullopt,
        };
        if (!WriteLine(error_file_, error_target_, record)) {
            WriteStderrFallback(level, record.message);
        }
    }

    void ReportDrops() {
        pending_drops_ += dropped_.exchange(0, std::memory_order_acq_rel);
        const auto now = std::chrono::steady_clock::now();
        if (pending_drops_ == 0 ||
            (running_.load(std::memory_order_acquire) && now < next_drop_report_)) return;
        next_drop_report_ = now + 1s;
        WriteBackendLine(LogLevel::WARN, std::format(
            "log queue dropped {} records", std::exchange(pending_drops_, 0)));
    }

    void FlushFile(std::ofstream& file, LogTarget& target) {
        if (!file.is_open() || target.failed) return;
        file.flush();
        if (!file) SinkFailure(target, "flush");
    }

    void FlushFiles() {
        FlushFile(error_file_, error_target_);
        FlushFile(access_file_, access_target_);
    }

    void CloseFile(std::ofstream& file, LogTarget& target) {
        if (!file.is_open()) return;
        file.clear();
        file.close();
        if (!file && !target.close_failure_reported) {
            target.close_failure_reported = true;
            if (target.failed) {
                WriteStderrFallback(LogLevel::ERROR, std::format(
                    "log channel={} write-failure operation=close path={}",
                    target.fallback_prefix, target.active_path.string()));
            } else {
                SinkFailure(target, "close");
            }
        }
    }

    void CloseFiles() {
        CloseFile(error_file_, error_target_);
        CloseFile(access_file_, access_target_);
        for (auto* target : {&error_target_, &access_target_}) {
            if (target->discarded == 0) continue;
            WriteStderrFallback(LogLevel::WARN, std::format(
                "log channel={} unavailable; discarded {} records",
                target->fallback_prefix, std::exchange(target->discarded, 0)));
        }
    }

    moodycamel::ConcurrentQueue<LogRecord> queue_;
    moodycamel::LightweightSemaphore writer_wakeup_{0, 0};
    std::atomic_bool accepting_{false};
    std::atomic_bool running_{false};
    std::atomic_bool flush_requested_{false};
    std::atomic<size_t> pending_{0};
    std::atomic<size_t> producers_{0};
    std::atomic<uint64_t> dropped_{0};
    uint64_t pending_drops_{0};
    std::chrono::steady_clock::time_point next_drop_report_{};
    std::thread writer_;
    std::filesystem::path log_dir_;
    uint16_t max_days_{15};
    bool rotate_daily_{true};
    bool gzip_enabled_{true};
    std::string current_date_;
    std::chrono::system_clock::time_point next_rotation_at_{};
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

std::optional<LogLevel> ParseLogLevel(std::string_view name) noexcept {
    if (name == "none") return LogLevel::NONE;
    if (name == "trace") return LogLevel::TRACE;
    if (name == "debug") return LogLevel::DEBUG;
    if (name == "info") return LogLevel::INFO;
    if (name == "warning" || name == "warn") return LogLevel::WARN;
    if (name == "error") return LogLevel::ERROR;
    return std::nullopt;
}

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

        const auto min_level = ParseLogLevel(level);
        if (!min_level) {
            WriteConsole(LogLevel::ERROR,
                         std::format("Failed to initialize logging > unsupported level '{}'", level));
            return false;
        }
        min_level_.store(*min_level, std::memory_order_release);

        try {
            g_console.Start();
            if (!g_async_log_backend.Start(
                    log_dir, error_path, access_path, max_days, rotate_daily, gzip)) {
                WriteConsole(LogLevel::ERROR,
                             "Failed to initialize logging > cannot open access/error log files");
                g_console.Stop();
                return false;
            }

            const auto resolved_error_path = g_async_log_backend.ErrorPath();
            const auto resolved_access_path = g_async_log_backend.AccessPath();
            const auto rotation = rotate_daily ? "daily" : "fixed";
            const auto compression = (rotate_daily && gzip) ? "gzip" : "none";

            initialized_.store(true, std::memory_order_release);
            WriteConsole(LogLevel::INFO, std::format(
                "Logging initialized: level {}; access {}; error {}; directory {}; "
                "{} rotation; compression {}; retention {} days",
                level, resolved_access_path.string(), resolved_error_path.string(),
                log_dir.string(), rotation, compression, max_days));
        } catch (const std::exception& e) {
            WriteConsole(LogLevel::ERROR,
                         std::format("Failed to initialize logging > {}", e.what()));
            g_async_log_backend.Stop();
            initialized_.store(false, std::memory_order_release);
            g_console.Stop();
            return false;
        }
    }

    return true;
}

void Log::Shutdown() {
    std::lock_guard lifecycle_lock(g_lifecycle_mutex);
    initialized_.store(false, std::memory_order_release);
    g_async_log_backend.Stop();
    g_console.Stop();
}

void Log::Flush() {
    g_async_log_backend.RequestFlush();
}

void Log::WriteSystem(LogLevel level,
                      std::string message,
                      std::source_location location) {
    if (!ShouldLog(level)) return;
    if (!initialized_.load(std::memory_order_acquire)) {
        if (level >= LogLevel::WARN) {
            WriteStderrFallback(level, message);
        }
        return;
    }

    g_async_log_backend.Enqueue(LogRecord{
        .channel = LogChannel::Error,
        .level = level,
        .timestamp_us = NowMicros(),
        .message = std::move(message),
        .source_file = location.file_name(),
        .connection = std::nullopt,
    });
}

void Log::WriteConnection(LogLevel level,
                          std::string message,
                          std::source_location location) {
    if (!ShouldLog(level)) return;
    if (!initialized_.load(std::memory_order_acquire)) return;

    g_async_log_backend.Enqueue(LogRecord{
        .channel = LogChannel::Error,
        .level = level,
        .timestamp_us = NowMicros(),
        .message = std::move(message),
        .source_file = location.file_name(),
        .connection = std::nullopt,
    });
}

void Log::WriteConnection(LogLevel level,
                          ConnectionLogContext context,
                          std::string message,
                          std::source_location location) {
    if (!ShouldLog(level)) return;
    if (!initialized_.load(std::memory_order_acquire)) return;

    g_async_log_backend.Enqueue(LogRecord{
        .channel = LogChannel::Error,
        .level = level,
        .timestamp_us = NowMicros(),
        .message = std::move(message),
        .source_file = location.file_name(),
        .connection = std::move(context),
    });
}

void Log::WriteAccess(std::string message) {
    if (!initialized_.load(std::memory_order_acquire)) return;
    g_async_log_backend.Enqueue(LogRecord{
        .channel = LogChannel::Access,
        .level = LogLevel::INFO,
        .timestamp_us = NowMicros(),
        .message = std::move(message),
        .source_file = {},
        .connection = std::nullopt,
    });
}

void Log::WriteConsole(LogLevel level,
                       std::string message,
                       std::source_location location) {
    // Fatal startup callers use this direct API even with logging disabled;
    // ordinary diagnostic macros perform the configured severity check first.
    if (level != LogLevel::ERROR && !ShouldLog(level)) return;
    if (message.empty()) return;
    const int64_t timestamp_us = NowMicros();
    if (level >= LogLevel::WARN && ShouldLog(level) &&
        initialized_.load(std::memory_order_acquire)) {
        g_async_log_backend.Enqueue(LogRecord{
            .channel = LogChannel::Error,
            .level = level,
            .timestamp_us = timestamp_us,
            .message = message,
            .source_file = location.file_name(),
            .connection = std::nullopt,
        });
    }
    LogRecord record{
        .channel = LogChannel::Console,
        .level = level,
        .timestamp_us = timestamp_us,
        .message = std::move(message),
        .source_file = location.file_name(),
        .connection = std::nullopt,
    };
    g_console.Enqueue(FormatConsoleRecord(record), level == LogLevel::ERROR);
}

void Log::WritePanel(LogLevel level,
                     PanelLogContext context,
                     std::string message,
                     std::source_location location) {
    if (!ShouldLog(level)) return;
    const bool initialized = initialized_.load(std::memory_order_acquire);
    if (level < LogLevel::INFO && !initialized) return;
    const int64_t timestamp_us = NowMicros();
    if ((level < LogLevel::INFO || level >= LogLevel::WARN) && initialized) {
        auto diagnostic = context.node_id > 0
            ? std::format("[{}/{}] {}", context.name, context.node_id, message)
            : std::format("[{}] {}", context.name, message);
        if (!context.host.empty()) {
            diagnostic.append(" Host=").append(ConsoleField(PanelOrigin(context.host)));
        }
        if (!context.type.empty()) {
            diagnostic.append(" Type=").append(ConsoleField(context.type));
        }
        g_async_log_backend.Enqueue(LogRecord{
            .channel = LogChannel::Error,
            .level = level,
            .timestamp_us = timestamp_us,
            .message = std::move(diagnostic),
            .source_file = location.file_name(),
            .connection = std::nullopt,
        });
    }
    if (level < LogLevel::INFO) return;
    LogRecord record{
        .channel = LogChannel::Console,
        .level = level,
        .timestamp_us = timestamp_us,
        .message = std::move(message),
        .source_file = location.file_name(),
        .connection = std::nullopt,
    };
    g_console.Enqueue(FormatConsoleRecord(record, &context), level == LogLevel::ERROR);
}

std::filesystem::path Log::ResolveTargetPath(
    const std::filesystem::path& log_dir,
    const std::filesystem::path& configured_path,
    std::string_view fallback_prefix,
    bool rotate_daily,
    std::string_view date) {
    return ResolveLogPath(
        log_dir, configured_path, fallback_prefix, rotate_daily, date).lexically_normal();
}

bool Log::ShouldLog(LogLevel level) noexcept {
    const auto min_level = min_level_.load(std::memory_order_relaxed);
    if (min_level == LogLevel::NONE) return false;
    return level >= min_level;
}

