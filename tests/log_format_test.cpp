#include <gtest/gtest.h>

#include "infra/log.hpp"
#include "infra/config_types.hpp"
#include "common/session.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <memory>
#include <signal.h>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

struct Descriptor {
    explicit Descriptor(int fd) noexcept : value(fd) {}
    ~Descriptor() { Close(); }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    void Close() noexcept {
        if (const int fd = std::exchange(value, -1); fd >= 0) ::close(fd);
    }
    int value;
};

struct ConsoleRestore {
    Descriptor output{::dup(STDOUT_FILENO)};
    Descriptor error{::dup(STDERR_FILENO)};
    ConsoleRestore() {
        if (output.value < 0 || error.value < 0)
            throw std::runtime_error("cannot save console descriptors");
    }
    ~ConsoleRestore() { Restore(); }
    void Restore() noexcept {
        ::infra::Log::Shutdown();
        if (output.value >= 0) ::dup2(output.value, STDOUT_FILENO);
        if (error.value >= 0) ::dup2(error.value, STDERR_FILENO);
        output.Close();
        error.Close();
    }
};

struct StreamCapture {
    std::unique_ptr<FILE, decltype(&std::fclose)> file{std::tmpfile(), &std::fclose};
    int target;
    Descriptor previous;
    explicit StreamCapture(int descriptor)
        : target(descriptor), previous(::dup(descriptor)) {
        if (!file || previous.value < 0 || ::dup2(::fileno(file.get()), target) < 0)
            throw std::runtime_error("cannot capture console descriptor");
    }
    ~StreamCapture() {
        ::infra::Log::Shutdown();
        ::dup2(previous.value, target);
    }
    std::string Text() const {
        std::string text;
        std::array<char, 4096> buffer;
        off_t offset = 0;
        for (;;) {
            const auto count = ::pread(::fileno(file.get()), buffer.data(), buffer.size(), offset);
            if (count == 0) return text;
            if (count < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error("cannot read captured console");
            }
            text.append(buffer.data(), static_cast<size_t>(count));
            offset += count;
        }
    }
};

std::vector<std::string> ReadLines(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input.is_open()) throw std::runtime_error("log file was not created");
    std::vector<std::string> lines;
    for (std::string line; std::getline(input, line);) {
        EXPECT_FALSE(line.empty()) << "blank log record";
        for (const unsigned char ch : line) {
            EXPECT_GE(ch, 0x20) << "raw control character in log record";
            EXPECT_NE(ch, 0x7f) << "raw control character in log record";
        }
        lines.push_back(std::move(line));
    }
    EXPECT_FALSE(input.bad());
    return lines;
}

const std::string& FindLine(const std::vector<std::string>& lines, std::string_view marker) {
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

class LogFormat : public testing::Test {
protected:
    const std::filesystem::path directory = std::filesystem::temp_directory_path() /
        ("cnode-log-format-" + std::to_string(::getpid()) + "-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    infra::LogConfig config{
        .level = infra::LogLevel::TRACE, .log_dir = directory,
        .access_path = "access.log", .error_path = "error.log", .max_days = 1,
        .rotate_daily = false, .gzip = false};
    void TearDown() override {
        ::infra::Log::Shutdown();
        std::filesystem::remove_all(directory);
    }
};

TEST_F(LogFormat, EscapesControlCharactersWithoutForgingRecords) {
    std::string console_text;
    {
        StreamCapture console(STDOUT_FILENO);
        if (!::infra::Log::Init(config)) throw std::runtime_error("logger initialization failed");
        std::string injection = "diagnostic injection\nforged\r\t\x1b";
        injection.push_back('\0');
        ::infra::Log::WriteSystem(infra::LogLevel::WARN, injection);
        ::infra::Log::WriteAccess("rejected invalid input\nforged-access\x1b");
        ::infra::Log::WriteConsole(infra::LogLevel::INFO, "quoted \"value\"\\path\nnext");
        ::infra::Log::Shutdown();
        console_text = console.Text();
    }
    const auto diagnostics = ReadLines(directory / "error.log");
    const auto access = ReadLines(directory / "access.log");
    ASSERT_EQ(diagnostics.size(), 1U);
    ASSERT_EQ(access.size(), 1U);
    EXPECT_NE(diagnostics.front().find("\\nforged\\r\\t\\x1b\\x00"), std::string::npos);
    EXPECT_NE(access.front().find("\\nforged-access\\x1b"), std::string::npos);
    EXPECT_NE(console_text.find("msg=\"quoted \\\"value\\\"\\\\path\\nnext\""), std::string::npos);
}

TEST_F(LogFormat, ConnectionIdentityPreservesWorkerBitsAndAuthenticationPhase) {
    ASSERT_TRUE(::infra::Log::Init(config));
    common::Context authenticated_ctx;
    authenticated_ctx.inbound.tag = "vless-in";
    authenticated_ctx.inbound.user_id = 123;
    authenticated_ctx.outbound.tag = "direct";
    authenticated_ctx.conn_id = (1ull << 32) | 7;
    ::infra::Log::WriteConnection(infra::LogLevel::WARN,
        authenticated_ctx,
        "authenticated outbound failure");
    common::Context unauthenticated_ctx;
    unauthenticated_ctx.inbound.tag = "vless-in";
    unauthenticated_ctx.inbound.user_id = 0;
    unauthenticated_ctx.conn_id = (2ull << 32) | 7;
    ::infra::Log::WriteConnection(infra::LogLevel::WARN,
        unauthenticated_ctx,
        "authentication failed from 192.0.2.10:52000 > invalid credential");
    ::infra::Log::WriteConnection(infra::LogLevel::DEBUG, uint64_t{0}, "diagnostic without connection identity");
    ::infra::Log::Shutdown();
    const auto diagnostics = ReadLines(directory / "error.log");
    const auto& authenticated = FindLine(diagnostics, "authenticated outbound failure");
    EXPECT_NE(authenticated.find("[4294967303]"), std::string::npos);
    EXPECT_NE(authenticated.find("[vless-in -> direct] user:123"), std::string::npos);
    const auto& rejected = FindLine(diagnostics, "authentication failed from");
    EXPECT_NE(rejected.find("[8589934599]"), std::string::npos);
    EXPECT_NE(rejected.find("[vless-in]"), std::string::npos);
    EXPECT_EQ(rejected.find("user:"), std::string::npos);
    EXPECT_EQ(FindLine(diagnostics, "without connection identity").find("[0]"), std::string::npos);
}

TEST_F(LogFormat, RedactsPanelUrlSecretsAcrossConsoleAndDiagnosticSinks) {
    std::string console_text, error_text;
    {
        StreamCapture console(STDOUT_FILENO), errors(STDERR_FILENO);
        if (!::infra::Log::Init(config)) throw std::runtime_error("logger initialization failed");
        const infra::PanelLogContext panel{
            .name = "main panel",
            .host = "https://login:password@panel.example.com:8443/api?key=secret#private",
            .node_id = 1041, .type = "Vless"};
        ::infra::Log::WritePanel(infra::LogLevel::INFO, panel, "node ready");
        ::infra::Log::WritePanel(infra::LogLevel::WARN, panel, "panel request failed");
        ::infra::Log::Shutdown();
        console_text = console.Text();
        error_text = errors.Text();
    }
    const auto diagnostics = ReadLines(directory / "error.log");
    EXPECT_NE(console_text.find("Host=\"https://panel.example.com:8443\""), std::string::npos);
    EXPECT_NE(console_text.find("ID=1041 Name=\"main panel\" Type=Vless"), std::string::npos);
    EXPECT_TRUE(Contains(diagnostics, "panel request failed"));
    for (const auto secret : {"login", "password", "/api", "secret", "private"}) {
        SCOPED_TRACE(secret);
        EXPECT_EQ(console_text.find(secret), std::string::npos);
        EXPECT_EQ(error_text.find(secret), std::string::npos);
        EXPECT_FALSE(Contains(diagnostics, secret));
    }
}

TEST_F(LogFormat, RoutesAccessDiagnosticsAndLifecycleEventsToSeparateSinks) {
    std::string console_text, error_text;
    {
        StreamCapture console(STDOUT_FILENO), errors(STDERR_FILENO);
        if (!::infra::Log::Init(config)) throw std::runtime_error("logger initialization failed");
        ::infra::Log::WriteSystem(infra::LogLevel::WARN, "diagnostic-only event");
        ::infra::Log::WriteConsole(infra::LogLevel::INFO, "ordinary lifecycle event");
        ::infra::Log::WriteConsole(infra::LogLevel::ERROR, "fatal startup failure");
        ::infra::Log::WriteAccess("accepted tcp:example.com:443");
        ::infra::Log::Shutdown();
        console_text = console.Text();
        error_text = errors.Text();
    }
    const auto diagnostics = ReadLines(directory / "error.log");
    const auto access = ReadLines(directory / "access.log");
    EXPECT_TRUE(Contains(diagnostics, "diagnostic-only event"));
    EXPECT_TRUE(Contains(diagnostics, "fatal startup failure"));
    EXPECT_FALSE(Contains(diagnostics, "ordinary lifecycle event"));
    EXPECT_FALSE(Contains(diagnostics, "accepted tcp:"));
    EXPECT_TRUE(Contains(access, "accepted tcp:"));
    EXPECT_FALSE(Contains(access, "diagnostic-only event"));
    EXPECT_EQ(console_text.find("diagnostic-only event"), std::string::npos);
    EXPECT_NE(console_text.find("ordinary lifecycle event"), std::string::npos);
    EXPECT_NE(error_text.find("fatal startup failure"), std::string::npos);
}

TEST_F(LogFormat, SeverityFilteringDoesNotDiscardAccessFacts) {
    std::string console_text;
    {
        StreamCapture console(STDOUT_FILENO);
        config.level = infra::LogLevel::WARN;
        if (!::infra::Log::Init(config)) throw std::runtime_error("logger initialization failed");
        ::infra::Log::WriteConsole(infra::LogLevel::INFO, "hidden console event");
        ::infra::Log::WriteSystem(infra::LogLevel::DEBUG, "hidden diagnostic event");
        ::infra::Log::WriteSystem(infra::LogLevel::WARN, "visible warning");
        ::infra::Log::WriteAccess("accepted despite diagnostic severity");
        ::infra::Log::Shutdown();
        console_text = console.Text();
    }
    const auto diagnostics = ReadLines(directory / "error.log");
    EXPECT_TRUE(Contains(diagnostics, "visible warning"));
    EXPECT_FALSE(Contains(diagnostics, "hidden diagnostic event"));
    EXPECT_EQ(console_text.find("hidden console event"), std::string::npos);
    EXPECT_TRUE(Contains(ReadLines(directory / "access.log"), "accepted despite"));
}

TEST_F(LogFormat, DisabledDiagnosticsPreserveAccessFactsAndUnconditionalFatalErrors) {
    std::string error_text;
    {
        StreamCapture errors(STDERR_FILENO);
        config.level = infra::LogLevel::NONE;
        if (!::infra::Log::Init(config)) throw std::runtime_error("logger initialization failed");
        LOG_CONSOLE_ERROR("hidden ordinary error");
        ::infra::Log::WriteConsole(infra::LogLevel::ERROR, "unconditional fatal startup failure");
        ::infra::Log::WriteAccess("rejected despite disabled diagnostics");
        ::infra::Log::Shutdown();
        error_text = errors.Text();
    }
    EXPECT_TRUE(ReadLines(directory / "error.log").empty());
    EXPECT_EQ(error_text.find("hidden ordinary error"), std::string::npos);
    EXPECT_NE(error_text.find("unconditional fatal startup failure"), std::string::npos);
    EXPECT_TRUE(Contains(ReadLines(directory / "access.log"), "rejected despite"));
}

TEST_F(LogFormat, ErrorSinkFailureIsReportedWithoutLosingAccessRecords) {
    std::string error_text;
    {
        StreamCapture errors(STDERR_FILENO);
        config.error_path = "/dev/full";
        if (!::infra::Log::Init(config)) throw std::runtime_error("logger initialization failed");
        for (int i = 0; i < 100; ++i) ::infra::Log::WriteSystem(infra::LogLevel::WARN, "unwritable error record");
        ::infra::Log::WriteAccess("healthy access channel");
        ::infra::Log::Shutdown();
        error_text = errors.Text();
    }
    EXPECT_NE(error_text.find("channel=error"), std::string::npos);
    EXPECT_TRUE(Contains(ReadLines(directory / "access.log"), "healthy access"));
}

TEST_F(LogFormat, AccessSinkFailureIsReportedWithoutLosingDiagnosticRecords) {
    std::string error_text;
    {
        StreamCapture errors(STDERR_FILENO);
        config.access_path = "/dev/full";
        if (!::infra::Log::Init(config)) throw std::runtime_error("logger initialization failed");
        ::infra::Log::WriteAccess("unwritable access record");
        ::infra::Log::WriteSystem(infra::LogLevel::WARN, "healthy error channel");
        ::infra::Log::Shutdown();
        error_text = errors.Text();
    }
    EXPECT_NE(error_text.find("channel=access"), std::string::npos);
    EXPECT_TRUE(Contains(ReadLines(directory / "error.log"), "healthy error"));
}

TEST_F(LogFormat, RedirectedConsoleAndDirectWritesShareTheFileOffsetAfterShutdown) {
    std::string before_direct, before_second_direct, after_second_direct;
    constexpr std::string_view marker = "direct emergency output\n";
    {
        StreamCapture capture(STDOUT_FILENO);
        config.level = infra::LogLevel::INFO;
        if (!::infra::Log::Init(config)) throw std::runtime_error("logger initialization failed");
        ::infra::Log::WriteConsole(infra::LogLevel::INFO, "async console offset");
        ::infra::Log::Shutdown();
        before_direct = capture.Text();
        if (::write(STDOUT_FILENO, marker.data(), marker.size()) != static_cast<ssize_t>(marker.size()))
            throw std::runtime_error("direct console write failed");
        ::infra::Log::WriteConsole(infra::LogLevel::INFO, "after-shutdown console offset");
        before_second_direct = capture.Text();
        if (::write(STDOUT_FILENO, marker.data(), marker.size()) != static_cast<ssize_t>(marker.size()))
            throw std::runtime_error("second direct console write failed");
        after_second_direct = capture.Text();
    }
    EXPECT_NE(before_direct.find("async console offset"), std::string::npos);
    EXPECT_TRUE(before_second_direct.starts_with(before_direct + std::string(marker)));
    EXPECT_NE(before_second_direct.find("after-shutdown console offset"), std::string::npos);
    EXPECT_EQ(after_second_direct, before_second_direct + std::string(marker));
}

TEST_F(LogFormat, BlockedConsoleDoesNotStallProducersShutdownOrAccessWriter) {
    int pipe[2];
    ASSERT_EQ(::pipe(pipe), 0);
    Descriptor input(pipe[0]), output(pipe[1]);
    ASSERT_EQ(::fcntl(output.value, F_SETPIPE_SZ, 4096), 4096);
    const auto child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        ::alarm(4);
        if (::dup2(output.value, STDOUT_FILENO) < 0) ::_exit(2);
        output.Close();
        // Retain the read descriptor without consuming bytes: EAGAIN, not EPIPE.
        config.level = infra::LogLevel::INFO;
        if (!::infra::Log::Init(config)) ::_exit(2);
        const std::string message(512, 'x');
        for (int i = 0; i < 20000; ++i) ::infra::Log::WriteConsole(infra::LogLevel::INFO, message);
        ::infra::Log::WriteAccess("access survives blocked stdout");
        ::infra::Log::Shutdown();
        ::_exit(0);
    }
    output.Close();
    int status = 0;
    pid_t joined;
    do { joined = ::waitpid(child, &status, 0); } while (joined < 0 && errno == EINTR);
    ASSERT_EQ(joined, child);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
    EXPECT_TRUE(Contains(ReadLines(directory / "access.log"), "access survives"));
}

TEST_F(LogFormat, SocketConsolePreservesCallerDescriptorFlagsAndDeliversRecords) {
    int sockets[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
    Descriptor output(sockets[0]), input(sockets[1]);
    ConsoleRestore restore;
    ASSERT_GE(::dup2(output.value, STDOUT_FILENO), 0);
    const int flags = ::fcntl(output.value, F_GETFL);
    config.level = infra::LogLevel::INFO;
    const bool initialized = ::infra::Log::Init(config);
    ::infra::Log::WriteConsole(infra::LogLevel::INFO, "journald console record");
    ::infra::Log::Shutdown();
    const int final_flags = ::fcntl(output.value, F_GETFL);
    restore.Restore();
    output.Close();
    std::string received;
    std::array<char, 4096> bytes;
    ssize_t count;
    while ((count = ::read(input.value, bytes.data(), bytes.size())) > 0)
        received.append(bytes.data(), static_cast<size_t>(count));
    EXPECT_TRUE(initialized);
    EXPECT_EQ(count, 0);
    EXPECT_EQ(final_flags, flags);
    EXPECT_NE(received.find("journald console record"), std::string::npos);
}

TEST_F(LogFormat, PartialConsoleRecordRetiresBothAliasesWithoutAffectingErrorFile) {
    int sockets[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
    Descriptor output(sockets[0]), input(sockets[1]);
    const int send_buffer = 512;
    ASSERT_EQ(::setsockopt(output.value, SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)), 0);
    const std::string prefix(128, 'p');
    ASSERT_EQ(::send(output.value, prefix.data(), prefix.size(), MSG_NOSIGNAL), 128);
    ConsoleRestore restore;
    ASSERT_GE(::dup2(output.value, STDOUT_FILENO), 0);
    ASSERT_GE(::dup2(output.value, STDERR_FILENO), 0);
    // Suppress startup info so only the controlled record occupies the socket.
    config.level = infra::LogLevel::WARN;
    const bool initialized = ::infra::Log::Init(config);
    ::infra::Log::WriteConsole(infra::LogLevel::WARN, std::string(4000, 'x'));
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    int available = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        if (::ioctl(input.value, FIONREAD, &available) != 0 || available > 128) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    std::array<char, 8192> bytes;
    const auto first_count = ::recv(input.value, bytes.data(), bytes.size(), MSG_DONTWAIT);
    const bool partial = first_count > 128 && bytes[static_cast<size_t>(first_count - 1)] != '\n';
    // Draining restores writability, but neither alias may append to the prefix.
    ::infra::Log::WriteConsole(infra::LogLevel::ERROR, "must-not-follow-partial-record");
    ::infra::Log::Shutdown();
    restore.Restore();
    output.Close();
    std::string after_partial;
    ssize_t count;
    while ((count = ::read(input.value, bytes.data(), bytes.size())) > 0)
        after_partial.append(bytes.data(), static_cast<size_t>(count));
    EXPECT_TRUE(initialized);
    EXPECT_TRUE(partial);
    EXPECT_EQ(count, 0);
    EXPECT_TRUE(after_partial.empty());
    EXPECT_TRUE(Contains(ReadLines(directory / "error.log"), "must-not-follow-partial-record"));
}

}  // namespace
