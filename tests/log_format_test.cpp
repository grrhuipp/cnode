#include <gtest/gtest.h>

#include "infra/log.hpp"

#include <array>
#include <cstdio>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

void Expect(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

std::vector<std::string> ReadLines(const std::filesystem::path& path) {
    std::ifstream input(path);
    Expect(input.is_open(), "log file was not created");
    std::vector<std::string> lines;
    for (std::string line; std::getline(input, line);) {
        Expect(!line.empty(), "blank log record");
        for (const unsigned char ch : line) {
            Expect(ch >= 0x20 && ch != 0x7f, "raw control character in log record");
        }
        lines.push_back(std::move(line));
    }
    return lines;
}

const std::string& FindLine(const std::vector<std::string>& lines,
                            std::string_view marker) {
    for (const auto& line : lines) {
        if (line.find(marker) != std::string::npos) return line;
    }
    throw std::runtime_error("missing log event: " + std::string(marker));
}

bool Contains(const std::vector<std::string>& lines, std::string_view marker) {
    for (const auto& line : lines) {
        if (line.find(marker) != std::string::npos) return true;
    }
    return false;
}

void CheckTimestamp(std::string_view line) {
    Expect(line.size() > 26 && line[4] == '/' && line[7] == '/' &&
           line[10] == ' ' && line[13] == ':' && line[16] == ':' && line[19] == '.',
           "core timestamp must include microseconds");
    Expect(line.substr(20, 6).find_first_not_of("0123456789") == std::string_view::npos,
           "invalid microsecond timestamp");
}

struct StreamCapture {
    FILE* file{std::tmpfile()};
    int target;
    int previous;

    explicit StreamCapture(int descriptor)
        : target(descriptor), previous(::dup(descriptor)) {
        if (!file || previous < 0 || ::dup2(::fileno(file), target) < 0)
            throw std::runtime_error("cannot capture console descriptor");
    }
    ~StreamCapture() {
        ::Log::Shutdown();
        ::dup2(previous, target);
        ::close(previous);
        std::fclose(file);
    }
    std::string Text() const {
        std::string text;
        std::array<char, 4096> buffer;
        off_t offset = 0;
        for (;;) {
            const auto count = ::pread(::fileno(file), buffer.data(), buffer.size(), offset);
            if (count == 0) return text;
            Expect(count > 0, "cannot read captured console");
            text.append(buffer.data(), static_cast<size_t>(count));
            offset += count;
        }
    }
};

void CheckConsoleFileOffset(const std::filesystem::path& directory) {
    StreamCapture capture(STDOUT_FILENO);
    Expect(::Log::Init("info", directory, 1, "access.log", "error.log", false, false),
           "cannot initialize redirected console");
    ::Log::WriteConsole(::LogLevel::INFO, "async console offset");
    ::Log::Shutdown();
    const auto before_direct = capture.Text();
    Expect(before_direct.find("async console offset") != std::string::npos,
           "redirected console record missing");
    constexpr std::string_view marker = "direct emergency output\n";
    Expect(::write(STDOUT_FILENO, marker.data(), marker.size()) ==
               static_cast<ssize_t>(marker.size()), "direct console write failed");
    Expect(capture.Text() == before_direct + std::string(marker),
           "direct output overwrote asynchronous console records");
    ::Log::WriteConsole(::LogLevel::INFO, "after-shutdown console offset");
    const auto before_second_direct = capture.Text();
    Expect(before_second_direct.starts_with(before_direct + std::string(marker)) &&
               before_second_direct.find("after-shutdown console offset") != std::string::npos,
           "after-shutdown console output overwrote existing records");
    Expect(::write(STDOUT_FILENO, marker.data(), marker.size()) ==
               static_cast<ssize_t>(marker.size()), "second direct console write failed");
    Expect(capture.Text() == before_second_direct + std::string(marker),
           "direct output overwrote after-shutdown console records");
}

void CheckBlockedConsole(const std::filesystem::path& directory) {
    int pipe[2];
    Expect(::pipe(pipe) == 0, "cannot create stdout pipe");
    Expect(::fcntl(pipe[1], F_SETPIPE_SZ, 4096) == 4096, "cannot size stdout pipe");
    const auto child = ::fork();
    Expect(child >= 0, "cannot fork console regression");
    if (child == 0) {
        ::alarm(4);
        ::dup2(pipe[1], STDOUT_FILENO);
        ::close(pipe[1]);
        // Retain the read descriptor without consuming bytes: EAGAIN, not EPIPE.
        if (!::Log::Init("info", directory, 1, "access.log", "error.log", false, false))
            ::_exit(2);
        const std::string message(512, 'x');
        for (int i = 0; i < 20000; ++i)
            ::Log::WriteConsole(::LogLevel::INFO, message);
        ::Log::WriteAccess("access survives blocked stdout");
        ::Log::Shutdown();
        ::_exit(0);
    }
    ::close(pipe[1]);
    int status = 0;
    Expect(::waitpid(child, &status, 0) == child, "cannot join console regression");
    ::close(pipe[0]);
    Expect(WIFEXITED(status) && WEXITSTATUS(status) == 0,
           "blocked stdout stalled producer or shutdown");
    Expect(Contains(ReadLines(directory / "access.log"), "access survives"),
           "blocked stdout affected file writer");
}

void CheckSocketConsole(const std::filesystem::path& directory) {
    int sockets[2];
    Expect(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0,
           "cannot create journald-style socket");
    const int saved = ::dup(STDOUT_FILENO);
    Expect(saved >= 0 && ::dup2(sockets[0], STDOUT_FILENO) >= 0, "cannot redirect socket stdout");
    const int flags = ::fcntl(sockets[0], F_GETFL);
    const bool initialized = ::Log::Init(
        "info", directory, 1, "access.log", "error.log", false, false);
    ::Log::WriteConsole(::LogLevel::INFO, "journald console record");
    ::Log::Shutdown();
    const bool unchanged = ::fcntl(sockets[0], F_GETFL) == flags;
    ::dup2(saved, STDOUT_FILENO);
    ::close(saved);
    ::close(sockets[0]);
    std::string received;
    std::array<char, 4096> bytes;
    ssize_t count;
    while ((count = ::read(sockets[1], bytes.data(), bytes.size())) > 0)
        received.append(bytes.data(), static_cast<size_t>(count));
    ::close(sockets[1]);
    Expect(initialized && unchanged && received.find("journald console record") != std::string::npos,
           "journald console lost record or changed caller descriptor flags");
}

void CheckAliasedSocketPartialRecord(const std::filesystem::path& directory) {
    int sockets[2];
    Expect(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0,
           "cannot create aliased console socket");
    const int send_buffer = 512;
    Expect(::setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF,
                       &send_buffer, sizeof(send_buffer)) == 0,
           "cannot constrain aliased console socket");
    const std::string prefix(128, 'p');
    Expect(::send(sockets[0], prefix.data(), prefix.size(), MSG_NOSIGNAL) == 128,
           "cannot prefill aliased console socket");
    const int saved_stdout = ::dup(STDOUT_FILENO);
    const int saved_stderr = ::dup(STDERR_FILENO);
    Expect(saved_stdout >= 0 && saved_stderr >= 0 &&
           ::dup2(sockets[0], STDOUT_FILENO) >= 0 &&
           ::dup2(sockets[0], STDERR_FILENO) >= 0, "cannot alias console descriptors");
    // Warning suppresses the initialization info record, leaving the socket's
    // controlled free space for this single large, valid logfmt record.
    const bool initialized = ::Log::Init(
        "warning", directory, 1, "access.log", "error.log", false, false);
    ::Log::WriteConsole(::LogLevel::WARN, std::string(4000, 'x'));
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    int available = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        if (::ioctl(sockets[1], FIONREAD, &available) != 0 || available > 128) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    std::array<char, 8192> bytes;
    const auto first_count = ::recv(sockets[1], bytes.data(), bytes.size(), MSG_DONTWAIT);
    const bool partial = first_count > 128 &&
        bytes[static_cast<size_t>(first_count - 1)] != '\n';
    // Draining restores writability. The stderr alias must nevertheless stay
    // retired: neither this event nor the drop warning may follow the prefix.
    ::Log::WriteConsole(::LogLevel::ERROR, "must-not-follow-partial-record");
    ::Log::Shutdown();
    ::dup2(saved_stdout, STDOUT_FILENO);
    ::dup2(saved_stderr, STDERR_FILENO);
    ::close(saved_stdout);
    ::close(saved_stderr);
    ::close(sockets[0]);
    std::string after_partial;
    ssize_t count;
    while ((count = ::read(sockets[1], bytes.data(), bytes.size())) > 0)
        after_partial.append(bytes.data(), static_cast<size_t>(count));
    ::close(sockets[1]);
    Expect(initialized && partial, "aliased socket did not exercise a partial console record");
    Expect(after_partial.empty(), "stderr alias appended output to a partial stdout record");
    Expect(Contains(ReadLines(directory / "error.log"), "must-not-follow-partial-record"),
           "retiring aliased console sink affected the independent error file");
}

struct SessionLogContext {
    struct {
        std::string_view tag;
        int64_t user_id = 0;
    } inbound;
    struct {
        std::string_view tag;
    } outbound;
    uint64_t conn_id = 0;
};

}  // namespace

TEST(LogFormat, Contract) {
    const auto directory = std::filesystem::temp_directory_path() /
        ("cnode-log-format-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    try {
        StreamCapture console(STDOUT_FILENO);
        StreamCapture errors(STDERR_FILENO);
        Expect(::Log::Init("trace", directory, 1,
                              "access.log", "error.log", false, false),
               "logger initialization failed");
        std::string injection = "diagnostic injection\nforged\r\t\x1b";
        injection.push_back('\0');
        ::Log::WriteSystem(::LogLevel::WARN, injection);
        ::Log::WriteConnection(::LogLevel::WARN,
            SessionLogContext{
                .inbound = {.tag = "vless-in", .user_id = 123},
                .outbound = {.tag = "direct"},
                .conn_id = (1ull << 32) | 7},
            "authenticated outbound failure");
        ::Log::WriteConnection(::LogLevel::WARN,
            SessionLogContext{
                .inbound = {.tag = "vless-in", .user_id = 0},
                .outbound = {},
                .conn_id = (2ull << 32) | 7},
            "authentication failed from 192.0.2.10:52000 > invalid credential");
        ::Log::WriteConnection(::LogLevel::DEBUG, uint64_t{0},
                                  "diagnostic without connection identity");
        const ::PanelLogContext panel{
            .name = "main panel", .host = "https://login:password@panel.example.com:8443/api?key=secret#private",
            .node_id = 1041, .type = "Vless"};
        ::Log::WritePanel(::LogLevel::INFO, panel, "node ready");
        ::Log::WritePanel(::LogLevel::WARN, panel, "panel request failed");
        ::Log::WriteConsole(::LogLevel::ERROR, "fatal startup failure");
        ::Log::WriteConsole(::LogLevel::INFO, "quoted \"value\"\\path\nnext");
        ::Log::WriteAccess("from 192.0.2.10:52000 accepted tcp:example.com:443 [vless-in -> direct] user:123");
        ::Log::WriteAccess("rejected invalid input\nforged-access\x1b");
        ::Log::Shutdown();

        const auto diagnostics = ReadLines(directory / "error.log");
        const auto access = ReadLines(directory / "access.log");
        for (const auto& line : diagnostics) CheckTimestamp(line);
        for (const auto& line : access) CheckTimestamp(line);
        const auto& escaped = FindLine(diagnostics, "diagnostic injection");
        Expect(escaped.find("\\nforged\\r\\t\\x1b\\x00") != std::string::npos,
               "diagnostic controls were not escaped");
        const auto& authenticated = FindLine(diagnostics, "authenticated outbound failure");
        Expect(authenticated.find("[4294967303]") != std::string::npos &&
               authenticated.find("[vless-in -> direct] user:123") != std::string::npos,
               "authenticated route or full worker connection identity was lost");
        const auto& rejected = FindLine(diagnostics, "authentication failed from");
        Expect(rejected.find("[8589934599]") != std::string::npos &&
               rejected.find("[vless-in]") != std::string::npos &&
               rejected.find("user:") == std::string::npos,
               "pre-authentication identity must not claim a user or collapse worker IDs");
        Expect(FindLine(diagnostics, "without connection identity").find("[0]") == std::string::npos,
               "missing connection identity must not be fabricated");
        Expect(Contains(diagnostics, "panel request failed") &&
               Contains(diagnostics, "fatal startup failure") &&
               !Contains(diagnostics, "node ready") && !Contains(diagnostics, "accepted tcp:"),
               "diagnostic file routing changed");
        Expect(access.size() == 2 && !Contains(access, "[Warning]") &&
               FindLine(access, "invalid input").find("\\nforged-access\\x1b") != std::string::npos,
               "access facts must stay separate and resist record injection");
        const auto console_text = console.Text();
        Expect(console_text.find("time=\"") != std::string::npos &&
               console_text.find("level=info msg=\"node ready\"") != std::string::npos &&
               console_text.find("Host=\"https://panel.example.com:8443\" ID=1041 Name=\"main panel\" Type=Vless") != std::string::npos,
               "console panel identity or logfmt structure missing");
        Expect(console_text.find("msg=\"quoted \\\"value\\\"\\\\path\\nnext\"") != std::string::npos,
               "console quoted values must be escaped");
        Expect(console_text.find("authentication failed") == std::string::npos &&
               console_text.find("panel request failed") != std::string::npos &&
               errors.Text().find("level=error msg=\"fatal startup failure\"") != std::string::npos,
               "console lifecycle/error routing changed");
        for (const auto secret : {"login", "password", "/api", "secret", "private"}) {
            Expect(console_text.find(secret) == std::string::npos &&
                   errors.Text().find(secret) == std::string::npos &&
                   !Contains(diagnostics, secret), "panel URL credentials leaked");
        }

        Expect(::Log::Init("warning", directory / "filtered", 1,
                              "access.log", "error.log", false, false),
               "filtered logger initialization failed");
        ::Log::WriteConsole(::LogLevel::INFO, "hidden console event");
        ::Log::WriteSystem(::LogLevel::DEBUG, "hidden diagnostic event");
        ::Log::WriteSystem(::LogLevel::WARN, "visible warning");
        ::Log::WriteAccess("accepted despite diagnostic severity");
        ::Log::Shutdown();
        const auto filtered = ReadLines(directory / "filtered/error.log");
        Expect(filtered.size() == 1 && Contains(filtered, "visible warning") &&
               console.Text().find("hidden console event") == std::string::npos,
               "configured severity must filter console and diagnostic records");
        Expect(Contains(ReadLines(directory / "filtered/access.log"), "accepted despite"),
               "diagnostic filtering must not discard access facts");

        Expect(::Log::Init("none", directory / "disabled", 1,
                              "access.log", "error.log", false, false),
               "disabled logger initialization failed");
        LOG_CONSOLE_ERROR("hidden ordinary error");
        ::Log::WriteConsole(::LogLevel::ERROR, "unconditional fatal startup failure");
        ::Log::WriteAccess("rejected despite disabled diagnostics");
        ::Log::Shutdown();
        Expect(ReadLines(directory / "disabled/error.log").empty() &&
               errors.Text().find("hidden ordinary error") == std::string::npos &&
               errors.Text().find("unconditional fatal startup failure") != std::string::npos,
               "fatal startup failures must remain visible without enabling ordinary diagnostics");
        Expect(Contains(ReadLines(directory / "disabled/access.log"), "rejected despite"),
               "disabled diagnostics must preserve access facts");

        Expect(::Log::Init("info", directory / "failed-error", 1,
                              "access.log", "/dev/full", false, false),
               "cannot initialize failing error sink");
        for (int i = 0; i < 100; ++i)
            ::Log::WriteSystem(::LogLevel::WARN, "unwritable error record");
        ::Log::WriteAccess("healthy access channel");
        ::Log::Shutdown();
        Expect(errors.Text().find("channel=error write-failure") != std::string::npos &&
               Contains(ReadLines(directory / "failed-error/access.log"), "healthy access"),
               "error sink failure was silent or affected access channel");

        Expect(::Log::Init("info", directory / "failed-access", 1,
                              "/dev/full", "error.log", false, false),
               "cannot initialize failing access sink");
        ::Log::WriteAccess("unwritable access record");
        ::Log::WriteSystem(::LogLevel::WARN, "healthy error channel");
        ::Log::Shutdown();
        Expect(errors.Text().find("channel=access write-failure") != std::string::npos &&
               Contains(ReadLines(directory / "failed-access/error.log"), "healthy error"),
               "access sink flush failure was silent or affected error channel");

        CheckBlockedConsole(directory / "blocked-console");
        CheckSocketConsole(directory / "socket-console");
        CheckAliasedSocketPartialRecord(directory / "aliased-socket-console");
        CheckConsoleFileOffset(directory / "console-file-offset");
    } catch (const std::exception& error) {
        ::Log::Shutdown();
        std::filesystem::remove_all(directory);
        std::cerr << error.what() << '\n';
        FAIL() << error.what();
    }
    std::filesystem::remove_all(directory);
}
