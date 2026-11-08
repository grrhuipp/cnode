#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "support.hpp"

#include <openssl/err.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <climits>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace cnode::e2e {
namespace {
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;

[[noreturn]] void SystemError(std::string_view operation, int error = errno) {
    throw std::system_error(error, std::generic_category(), std::string(operation));
}

Deadline Expires(Milliseconds timeout) {
    if (timeout < Milliseconds::zero()) throw std::invalid_argument("negative I/O timeout");
    return Clock::now() + timeout;
}

void CheckDeadline(Deadline deadline) {
    if (Clock::now() >= deadline) throw std::runtime_error("E2E operation deadline exceeded");
}

void Ready(int fd, short events, Deadline deadline) {
    for (;;) {
        CheckDeadline(deadline);
        const auto left = std::chrono::ceil<Milliseconds>(deadline - Clock::now()).count();
        pollfd descriptor{fd, events, 0};
        const int result = ::poll(&descriptor, 1, static_cast<int>(std::clamp<int64_t>(left, 1, INT_MAX)));
        if (result < 0) {
            if (errno == EINTR) continue;
            SystemError("poll");
        }
        if (result == 0) continue;
        if (descriptor.revents & POLLNVAL) SystemError("poll invalid descriptor", EBADF);
        // HUP/ERR must reach recv/SSL_get_error so EOF and the real error survive.
        if (descriptor.revents & (events | POLLHUP | POLLERR)) return;
    }
}

struct Address {
    sockaddr_storage storage{};
    socklen_t size = 0;
    int family = AF_UNSPEC;
    const sockaddr* Get() const { return reinterpret_cast<const sockaddr*>(&storage); }
};

Address NumericAddress(std::string_view text, uint16_t port) {
    Address result;
    const std::string host(text == "localhost" ? "127.0.0.1" : text);
    auto* ipv4 = reinterpret_cast<sockaddr_in*>(&result.storage);
    if (::inet_pton(AF_INET, host.c_str(), &ipv4->sin_addr) == 1) {
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(port);
        result.family = AF_INET;
        result.size = sizeof(sockaddr_in);
        return result;
    }
    auto* ipv6 = reinterpret_cast<sockaddr_in6*>(&result.storage);
    if (::inet_pton(AF_INET6, host.c_str(), &ipv6->sin6_addr) == 1) {
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(port);
        result.family = AF_INET6;
        result.size = sizeof(sockaddr_in6);
        return result;
    }
    throw std::invalid_argument("socket address must be numeric IPv4/IPv6 or localhost: " + host);
}

Socket NewSocket(int family, int type) {
    const int fd = ::socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) SystemError("socket");
    return Socket(fd);
}

size_t Receive(int fd, std::span<char> bytes, Deadline deadline) {
    if (bytes.empty()) return 0;
    for (;;) {
        CheckDeadline(deadline);
        const auto count = ::recv(fd, bytes.data(), bytes.size(), MSG_DONTWAIT);
        if (count >= 0) return static_cast<size_t>(count);
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) Ready(fd, POLLIN, deadline);
        else SystemError("recv");
    }
}

std::string TlsError(std::string_view operation, int kind) {
    std::string message(operation);
    message += " (SSL error " + std::to_string(kind) + ")";
    while (const auto error = ERR_get_error()) {
        std::array<char, 256> buffer{};
        ERR_error_string_n(error, buffer.data(), buffer.size());
        message += ": ";
        message += buffer.data();
    }
    return message;
}

// SSL's socket BIO does not use MSG_NOSIGNAL. Block SIGPIPE only in the calling
// thread, consuming only a newly generated signal before restoring its mask.
class BlockSigpipe {
public:
    BlockSigpipe() {
        sigemptyset(&set_);
        sigaddset(&set_, SIGPIPE);
        const int error = pthread_sigmask(SIG_BLOCK, &set_, &old_);
        if (error != 0) SystemError("pthread_sigmask", error);
        sigset_t pending;
        sigpending(&pending);
        pending_ = sigismember(&pending, SIGPIPE) == 1;
    }
    ~BlockSigpipe() {
        if (!pending_) {
            timespec zero{};
            while (::sigtimedwait(&set_, nullptr, &zero) < 0 && errno == EINTR) {}
        }
        pthread_sigmask(SIG_SETMASK, &old_, nullptr);
    }
private:
    sigset_t set_{}, old_{};
    bool pending_ = false;
};

bool TlsRetry(SSL* ssl, int result, Deadline deadline, std::string_view operation) {
    const int systemError = errno;
    const int error = SSL_get_error(ssl, result);
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        Ready(SSL_get_fd(ssl), error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline);
        return true;
    }
    if (error == SSL_ERROR_ZERO_RETURN) return false;
    if (error == SSL_ERROR_SYSCALL) {
        if (systemError == EINTR) return true;
        if (systemError != 0) SystemError(operation, systemError);
        if (result == 0 && ERR_peek_error() == 0) return false;
    }
    throw std::runtime_error(TlsError(operation, error));
}

size_t TlsReceive(SSL* ssl, std::span<char> bytes, Deadline deadline) {
    if (bytes.empty()) return 0;
    BlockSigpipe block;
    for (;;) {
        CheckDeadline(deadline);
        ERR_clear_error();
        errno = 0;
        const int count = SSL_read(ssl, bytes.data(), static_cast<int>(std::min(bytes.size(), static_cast<size_t>(INT_MAX))));
        if (count > 0) return static_cast<size_t>(count);
        if (!TlsRetry(ssl, count, deadline, "SSL_read")) return 0;
    }
}

int ExitCode(int status) {
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    throw std::runtime_error("child returned a nonterminal wait status");
}

std::string HostEncoding(std::string_view host, uint8_t domainType, uint8_t ipv6Type) {
    std::array<unsigned char, 16> address{};
    const std::string name(host);
    if (::inet_pton(AF_INET, name.c_str(), address.data()) == 1)
        return std::string(1, '\1') + std::string(reinterpret_cast<const char*>(address.data()), 4);
    if (::inet_pton(AF_INET6, name.c_str(), address.data()) == 1)
        return std::string(1, static_cast<char>(ipv6Type)) + std::string(reinterpret_cast<const char*>(address.data()), 16);
    if (host.empty() || host.size() > 255) throw std::invalid_argument("invalid wire hostname length");
    return std::string(1, static_cast<char>(domainType)) + std::string(1, static_cast<char>(host.size())) + name;
}
} // namespace

std::filesystem::path Binary() { return CNODE_TEST_BINARY; }
std::filesystem::path SourceRoot() { return CNODE_TEST_SOURCE_DIR; }

std::string ReadFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot read " + path.string());
    std::string result{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    if (input.bad()) throw std::runtime_error("failed reading " + path.string());
    return result;
}

void WriteFile(const std::filesystem::path& path, std::string_view content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("cannot write " + path.string());
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    output.close();
    if (!output) throw std::runtime_error("failed writing " + path.string());
}

void WriteJson(const std::filesystem::path& root, std::string_view name, const Json& value) {
    WriteFile(root / name, value.dump(2) + "\n");
}

void Configure(const std::filesystem::path& root, Json inbound, Json outbound, unsigned workers) {
    std::filesystem::create_directories(root);
    inbound["tag"] = "fin-in";
    inbound["routingEnabled"] = true;
    outbound["tag"] = "fin-out";
    WriteJson(root, "config.json", {{"workers", workers},
        {"timeouts", {{"handshake", 5}, {"connIdle", 15}, {"write", 5}, {"uplinkOnly", 10}, {"downlinkOnly", 10}}},
        {"log", {{"enable", false}, {"logDir", (root / "logs").string()}}}});
    WriteJson(root, "inbounds.json", Json::array({inbound}));
    WriteJson(root, "outbounds.json", Json::array({outbound}));
    WriteJson(root, "routing.json", {{"rules", Json::array({{{"type", "field"},
        {"inboundTag", Json::array({"fin-in"})}, {"outboundTag", "fin-out"}}})}});
}

Json TlsSettings(bool server) {
    const auto fixture = SourceRoot() / "tests/fixtures/anytls-pool";
    Json settings = server ? Json{{"certificates", Json::array({{
        {"certificateFile", (fixture / "cert.pem").string()}, {"keyFile", (fixture / "key.pem").string()}}})}}
        : Json{{"serverName", "localhost"}, {"allowInsecure", true}};
    return {{"network", "tcp"}, {"security", "tls"}, {"tlsSettings", std::move(settings)}};
}

void Until(const std::function<bool()>& condition, Milliseconds timeout) {
    const auto deadline = Expires(timeout);
    while (!condition()) {
        CheckDeadline(deadline);
        std::this_thread::sleep_until(std::min(deadline, Clock::now() + 10ms));
    }
}

TempDir::TempDir() {
    const auto root = Binary().parent_path() / "e2e-artifacts";
    std::filesystem::create_directories(root);
    std::string pattern = (root / "cnode-e2e-XXXXXX").string();
    char* directory = ::mkdtemp(pattern.data());
    if (!directory) SystemError("mkdtemp");
    path_ = directory;
}

TempDir::~TempDir() {
    if (::testing::Test::HasFailure() || std::uncaught_exceptions() != 0) {
        std::cerr << "E2E artifacts retained at " << path_ << '\n';
        return;
    }
    std::error_code error;
    std::filesystem::remove_all(path_, error);
    if (error) std::cerr << "Cannot remove E2E artifacts " << path_ << ": " << error.message() << '\n';
}

Child::Child(std::vector<std::string> argv, const std::filesystem::path& log,
             const std::filesystem::path& cwd) : log_(log) {
    if (argv.empty()) throw std::invalid_argument("empty child command");
    // Opening the log before spawning makes every startup error observable.
    const int logfile = ::open(log.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (logfile < 0) SystemError("open child log");
    Socket logOwner(logfile);
    posix_spawn_file_actions_t actions;
    int error = posix_spawn_file_actions_init(&actions);
    if (error != 0) SystemError("spawn file actions", error);
    struct ActionsGuard {
        posix_spawn_file_actions_t* actions;
        ~ActionsGuard() { posix_spawn_file_actions_destroy(actions); }
    } actionsGuard{&actions};
    auto checked = [](int result) { if (result != 0) SystemError("spawn setup", result); };
    checked(posix_spawn_file_actions_adddup2(&actions, logfile, STDOUT_FILENO));
    checked(posix_spawn_file_actions_adddup2(&actions, logfile, STDERR_FILENO));
    checked(posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0));
    if (!cwd.empty()) checked(posix_spawn_file_actions_addchdir_np(&actions, cwd.c_str()));
    posix_spawnattr_t attributes;
    checked(posix_spawnattr_init(&attributes));
    struct AttributesGuard {
        posix_spawnattr_t* attributes;
        ~AttributesGuard() { posix_spawnattr_destroy(attributes); }
    } attributesGuard{&attributes};
    sigset_t empty, defaults;
    sigemptyset(&empty);
    sigemptyset(&defaults);
    sigaddset(&defaults, SIGPIPE);
    checked(posix_spawnattr_setsigmask(&attributes, &empty));
    checked(posix_spawnattr_setsigdefault(&attributes, &defaults));
    checked(posix_spawnattr_setpgroup(&attributes, 0));
    checked(posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF));
    std::vector<char*> arguments;
    arguments.reserve(argv.size() + 1);
    for (auto& argument : argv) arguments.push_back(argument.data());
    arguments.push_back(nullptr);
    pid_t child = -1;
    error = posix_spawnp(&child, arguments.front(), &actions, &attributes, arguments.data(), environ);
    if (error != 0) SystemError("spawn " + argv.front(), error);
    pid_ = child;
}

Child::~Child() {
    try { Stop(1s); }
    catch (const std::exception& error) {
        ADD_FAILURE() << "Child cleanup failed: " << error.what() << "; log: " << log_;
    }
}

bool Child::Running() {
    if (reaped_ || pid_ < 0) return false;
    siginfo_t information{};
    if (::waitid(P_PID, static_cast<id_t>(pid_), &information, WEXITED | WNOHANG | WNOWAIT) < 0) {
        if (errno == EINTR) return true;
        SystemError("waitid");
    }
    if (information.si_pid == 0) return true;
    // Keep the exited leader unreaped until its group has been killed. Its
    // reserved PID prevents a reused process-group ID from being signalled.
    if (::kill(-pid_, SIGKILL) < 0 && errno != ESRCH) SystemError("kill child descendants");
    int status = 0;
    const auto result = ::waitpid(pid_, &status, WNOHANG);
    if (result == 0) return true;
    if (result < 0) {
        if (errno == EINTR) return true;
        SystemError("waitpid");
    }
    status_ = ExitCode(status);
    reaped_ = true;
    return false;
}

Child::MemorySnapshot Child::ReadMemorySnapshot() {
    if (!Running()) throw std::runtime_error("cannot sample memory of an exited child");
    const auto directory = "/proc/" + std::to_string(pid_) + "/";
    MemorySnapshot snapshot{};
    struct Field {
        std::string_view name;
        uint64_t& bytes;
        bool found = false;
    };
    const auto read_fields = [&](std::string_view filename, std::span<Field> fields) {
        const auto path = directory + std::string(filename);
        std::ifstream input(path);
        if (!input.is_open()) throw std::runtime_error("cannot open child memory data: " + path);
        const auto parse = [&](std::string_view text, Field& field) {
            const auto invalid = [&] {
                throw std::runtime_error("invalid or duplicate child memory field in " + path + ": " + std::string(text));
            };
            if (field.found) invalid();
            auto value = text.substr(field.name.size());
            const auto trim = [](std::string_view content) {
                const auto first = content.find_first_not_of(" \t");
                if (first == std::string_view::npos) return std::string_view{};
                return content.substr(first, content.find_last_not_of(" \t") - first + 1);
            };
            value = trim(value);
            if (value.empty()) invalid();
            uint64_t kib = 0;
            const auto result = std::from_chars(value.data(), value.data() + value.size(), kib);
            if (result.ec != std::errc{} || result.ptr == value.data() + value.size() ||
                (*result.ptr != ' ' && *result.ptr != '\t') ||
                trim(value.substr(static_cast<size_t>(result.ptr - value.data()))) != "kB" ||
                kib > std::numeric_limits<uint64_t>::max() / 1024) invalid();
            field.bytes = kib * 1024; // Linux procfs labels binary KiB as "kB".
            field.found = true;
        };
        std::string line;
        while (std::getline(input, line)) {
            for (auto& field : fields) {
                if (line.starts_with(field.name)) {
                    parse(line, field);
                    break;
                }
            }
        }
        if (input.bad() || !input.eof())
            throw std::runtime_error("cannot read child memory data: " + path);
        for (const auto& field : fields) {
            if (!field.found)
                throw std::runtime_error("missing child memory field " + std::string(field.name) + " in " + path);
        }
    };
    Field status_fields[] = {
        {"VmRSS:", snapshot.vm_rss_bytes},
        {"VmHWM:", snapshot.vm_hwm_bytes}};
    read_fields("status", status_fields);
    Field rollup_fields[] = {
        {"Rss:", snapshot.smaps_rollup_rss_bytes},
        {"Pss:", snapshot.smaps_rollup_pss_bytes},
        {"Anonymous:", snapshot.smaps_rollup_anonymous_bytes},
        {"AnonHugePages:", snapshot.smaps_rollup_anon_huge_pages_bytes},
        {"FilePmdMapped:", snapshot.smaps_rollup_file_pmd_mapped_bytes}};
    read_fields("smaps_rollup", rollup_fields);
    if (!Running()) throw std::runtime_error("child exited while sampling memory: " + directory);
    return snapshot;
}

int Child::Wait(Milliseconds timeout) {
    Until([this] { return !Running(); }, timeout);
    return status_;
}

void Child::Signal(int signal) {
    if (!Running()) return;
    if (::kill(-pid_, signal) < 0 && errno != ESRCH) SystemError("kill child group");
}

int Child::Stop(Milliseconds timeout) {
    if (!Running()) return status_;
    Signal(SIGTERM);
    const auto deadline = Expires(timeout);
    while (Running() && Clock::now() < deadline)
        std::this_thread::sleep_until(std::min(deadline, Clock::now() + 10ms));
    Signal(SIGKILL);
    return Wait(5s);
}

void Child::WaitForLog(std::string_view text, Milliseconds timeout) {
    Until([&] {
        if (ReadFile(log_).find(text) != std::string::npos) return true;
        if (!Running()) throw std::runtime_error("child exited before log marker: " + std::string(text) + "\n" + ReadFile(log_));
        return false;
    }, timeout);
}

Socket::Socket(int fd) : fd_(fd) {
    if (fd_ < 0) throw std::invalid_argument("invalid socket descriptor");
    const int flags = ::fcntl(fd_, F_GETFL);
    const int descriptorFlags = ::fcntl(fd_, F_GETFD);
    if (flags < 0 || descriptorFlags < 0 ||
        ::fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0 ||
        ::fcntl(fd_, F_SETFD, descriptorFlags | FD_CLOEXEC) < 0) {
        const int error = errno;
        Close();
        SystemError("adopt nonblocking descriptor", error);
    }
}
Socket::~Socket() { Close(); }
Socket::Socket(Socket&& other) noexcept : fd_(other.Release()) {}
Socket& Socket::operator=(Socket&& other) noexcept {
    if (this != &other) { Close(); fd_ = other.Release(); }
    return *this;
}
int Socket::Release() noexcept { return std::exchange(fd_, -1); }
void Socket::Close() noexcept { if (fd_ >= 0) ::close(Release()); }

Socket Socket::Listen(uint16_t port, std::string_view address) {
    const auto endpoint = NumericAddress(address, port);
    auto socket = NewSocket(endpoint.family, SOCK_STREAM);
    const int one = 1;
    if (::setsockopt(socket.Fd(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) SystemError("SO_REUSEADDR");
    if (endpoint.family == AF_INET6 && ::setsockopt(socket.Fd(), IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) < 0)
        SystemError("IPV6_V6ONLY");
    if (::bind(socket.Fd(), endpoint.Get(), endpoint.size) < 0) SystemError("bind listener");
    if (::listen(socket.Fd(), 64) < 0) SystemError("listen");
    return socket;
}

Socket Socket::Connect(uint16_t port, std::string_view address, Milliseconds timeout) {
    const auto deadline = Expires(timeout);
    const auto endpoint = NumericAddress(address, port);
    auto socket = NewSocket(endpoint.family, SOCK_STREAM);
    if (::connect(socket.Fd(), endpoint.Get(), endpoint.size) < 0) {
        if (errno != EINPROGRESS && errno != EINTR) SystemError("connect");
        Ready(socket.Fd(), POLLOUT, deadline);
        int error = 0;
        socklen_t size = sizeof(error);
        if (::getsockopt(socket.Fd(), SOL_SOCKET, SO_ERROR, &error, &size) < 0) SystemError("connect SO_ERROR");
        if (error != 0) SystemError("connect", error);
    }
    return socket;
}

Socket Socket::BindUdp(uint16_t port, std::string_view address) {
    const auto endpoint = NumericAddress(address, port);
    auto socket = NewSocket(endpoint.family, SOCK_DGRAM);
    if (::bind(socket.Fd(), endpoint.Get(), endpoint.size) < 0) SystemError("bind UDP");
    return socket;
}

Socket Socket::Accept(Milliseconds timeout) const {
    const auto deadline = Expires(timeout);
    for (;;) {
        CheckDeadline(deadline);
        const int fd = ::accept4(fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd >= 0) return Socket(fd);
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) Ready(fd_, POLLIN, deadline);
        else SystemError("accept");
    }
}

uint16_t Socket::Port() const {
    sockaddr_storage address{};
    socklen_t size = sizeof(address);
    if (::getsockname(fd_, reinterpret_cast<sockaddr*>(&address), &size) < 0) SystemError("getsockname");
    if (address.ss_family == AF_INET) return ntohs(reinterpret_cast<const sockaddr_in*>(&address)->sin_port);
    if (address.ss_family == AF_INET6) return ntohs(reinterpret_cast<const sockaddr_in6*>(&address)->sin6_port);
    throw std::runtime_error("socket has no IP port");
}

void Socket::ShutdownWrite() {
    if (::shutdown(fd_, SHUT_WR) < 0 && errno != ENOTCONN) SystemError("shutdown write");
}

void Socket::Write(std::string_view bytes, Milliseconds timeout) {
    const auto deadline = Expires(timeout);
    while (!bytes.empty()) {
        CheckDeadline(deadline);
        const auto count = ::send(fd_, bytes.data(), bytes.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
        if (count > 0) bytes.remove_prefix(static_cast<size_t>(count));
        else if (count == 0) throw std::runtime_error("zero-byte socket write");
        else if (errno == EINTR) continue;
        else if (errno == EAGAIN || errno == EWOULDBLOCK) Ready(fd_, POLLOUT, deadline);
        else SystemError("send");
    }
}

std::string Socket::Read(size_t maximum, Milliseconds timeout) {
    const auto deadline = Expires(timeout);
    std::string result(maximum, '\0');
    result.resize(Receive(fd_, std::span<char>(result), deadline));
    return result;
}
std::string Socket::ReadExact(size_t count, Milliseconds timeout) {
    const auto deadline = Expires(timeout);
    std::string result(count, '\0');
    size_t offset = 0;
    while (offset != count) {
        const auto received = Receive(fd_, std::span<char>(result).subspan(offset), deadline);
        if (received == 0) throw std::runtime_error("unexpected EOF reading exact socket payload");
        offset += received;
    }
    return result;
}

void Socket::SendTo(std::string_view bytes, uint16_t port, std::string_view address) {
    const auto deadline = Expires(5s);
    const auto endpoint = NumericAddress(address, port);
    for (;;) {
        CheckDeadline(deadline);
        const auto count = ::sendto(fd_, bytes.data(), bytes.size(), MSG_NOSIGNAL | MSG_DONTWAIT, endpoint.Get(), endpoint.size);
        if (count >= 0) {
            if (static_cast<size_t>(count) != bytes.size()) throw std::runtime_error("partial UDP send");
            return;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) Ready(fd_, POLLOUT, deadline);
        else SystemError("sendto");
    }
}

TlsContext::TlsContext(bool server) {
    context_ = SSL_CTX_new(TLS_method());
    if (!context_) throw std::runtime_error(TlsError("SSL_CTX_new", 0));
    try {
        if (SSL_CTX_set_min_proto_version(context_, TLS1_2_VERSION) != 1)
            throw std::runtime_error(TlsError("TLS minimum version", 0));
        SSL_CTX_set_verify(context_, SSL_VERIFY_NONE, nullptr);
        if (server) {
            const auto fixture = SourceRoot() / "tests/fixtures/anytls-pool";
            if (SSL_CTX_use_certificate_chain_file(context_, (fixture / "cert.pem").c_str()) != 1 ||
                SSL_CTX_use_PrivateKey_file(context_, (fixture / "key.pem").c_str(), SSL_FILETYPE_PEM) != 1 ||
                SSL_CTX_check_private_key(context_) != 1)
                throw std::runtime_error(TlsError("load test TLS certificate", 0));
        }
    } catch (...) { SSL_CTX_free(context_); context_ = nullptr; throw; }
}
TlsContext::~TlsContext() { SSL_CTX_free(context_); }

TlsSocket::TlsSocket(Socket socket, TlsContext& context, bool server, Milliseconds timeout)
    : socket_(std::move(socket)), ssl_(SSL_new(context.Get())) {
    if (!ssl_) throw std::runtime_error(TlsError("SSL_new", 0));
    try {
        const int flags = ::fcntl(socket_.Fd(), F_GETFL);
        if (flags < 0 || ::fcntl(socket_.Fd(), F_SETFL, flags | O_NONBLOCK) < 0) SystemError("TLS nonblocking socket");
        if (SSL_set_fd(ssl_, socket_.Fd()) != 1) throw std::runtime_error(TlsError("SSL_set_fd", 0));
        if (server) SSL_set_accept_state(ssl_);
        else {
            SSL_set_connect_state(ssl_);
            if (SSL_set_tlsext_host_name(ssl_, "localhost") != 1)
                throw std::runtime_error(TlsError("TLS server name", 0));
        }
        const auto deadline = Expires(timeout);
        BlockSigpipe block;
        for (;;) {
            CheckDeadline(deadline);
            ERR_clear_error();
            errno = 0;
            const int result = SSL_do_handshake(ssl_);
            if (result == 1) break;
            if (!TlsRetry(ssl_, result, deadline, "TLS handshake")) throw std::runtime_error("EOF during TLS handshake");
        }
    } catch (...) { SSL_free(ssl_); ssl_ = nullptr; throw; }
}
TlsSocket::~TlsSocket() { Close(); }
void TlsSocket::Close() noexcept { SSL_free(std::exchange(ssl_, nullptr)); socket_.Close(); }

void TlsSocket::Write(std::string_view bytes, Milliseconds timeout) {
    const auto deadline = Expires(timeout);
    BlockSigpipe block;
    while (!bytes.empty()) {
        CheckDeadline(deadline);
        ERR_clear_error();
        errno = 0;
        const int count = SSL_write(ssl_, bytes.data(), static_cast<int>(std::min(bytes.size(), static_cast<size_t>(INT_MAX))));
        if (count > 0) bytes.remove_prefix(static_cast<size_t>(count));
        else if (!TlsRetry(ssl_, count, deadline, "SSL_write")) throw std::runtime_error("EOF during TLS write");
    }
}
std::string TlsSocket::Read(size_t maximum, Milliseconds timeout) {
    const auto deadline = Expires(timeout);
    std::string result(std::min(maximum, static_cast<size_t>(INT_MAX)), '\0');
    result.resize(TlsReceive(ssl_, std::span<char>(result), deadline));
    return result;
}
std::string TlsSocket::ReadExact(size_t count, Milliseconds timeout) {
    const auto deadline = Expires(timeout);
    std::string result(count, '\0');
    size_t offset = 0;
    while (offset != count) {
        const auto received = TlsReceive(ssl_, std::span<char>(result).subspan(offset), deadline);
        if (received == 0) throw std::runtime_error("unexpected EOF reading exact TLS payload");
        offset += received;
    }
    return result;
}
void TlsSocket::ShutdownWrite() {
    const auto deadline = Expires(5s);
    BlockSigpipe block;
    for (;;) {
        CheckDeadline(deadline);
        ERR_clear_error();
        errno = 0;
        const int result = SSL_shutdown(ssl_);
        // Zero means close_notify was sent; do not wait for the peer's half.
        if (result >= 0) break;
        if (!TlsRetry(ssl_, result, deadline, "SSL_shutdown")) break;
    }
    socket_.ShutdownWrite();
}

PeerThread::PeerThread(std::function<void()> task)
    : thread_([this, task = std::move(task)] {
        try { task(); } catch (...) { error_ = std::current_exception(); }
    }) {}
PeerThread::~PeerThread() {
    if (thread_.joinable()) thread_.join();
    if (error_) {
        try { std::rethrow_exception(error_); }
        catch (const std::exception& error) { ADD_FAILURE() << "Unobserved peer exception: " << error.what(); }
        catch (...) { ADD_FAILURE() << "Unobserved nonstandard peer exception"; }
    }
}
void PeerThread::Join() {
    if (thread_.joinable()) thread_.join();
    if (auto error = std::exchange(error_, nullptr)) std::rethrow_exception(error);
}

std::string BigEndian(uint64_t value, size_t width) {
    if (width > sizeof(value)) throw std::invalid_argument("integer wire width exceeds 64 bits");
    std::string result(width, '\0');
    for (size_t index = width; index != 0; --index) {
        result[index - 1] = static_cast<char>(value & 0xff);
        value >>= 8;
    }
    return result;
}
uint64_t ReadBigEndian(std::string_view bytes) {
    if (bytes.size() > sizeof(uint64_t)) throw std::invalid_argument("integer wire width exceeds 64 bits");
    uint64_t value = 0;
    for (const unsigned char byte : bytes) value = (value << 8) | byte;
    return value;
}
std::string UuidBytes(std::string_view uuid) {
    if (uuid.size() != 36) throw std::invalid_argument("invalid UUID length");
    auto hex = [](char digit) -> unsigned {
        if (digit >= '0' && digit <= '9') return static_cast<unsigned>(digit - '0');
        if (digit >= 'a' && digit <= 'f') return static_cast<unsigned>(digit - 'a' + 10);
        if (digit >= 'A' && digit <= 'F') return static_cast<unsigned>(digit - 'A' + 10);
        throw std::invalid_argument("invalid UUID hex digit");
    };
    std::string result;
    result.reserve(16);
    for (size_t offset = 0; offset < uuid.size();) {
        if (offset == 8 || offset == 13 || offset == 18 || offset == 23) {
            if (uuid[offset++] != '-') throw std::invalid_argument("invalid UUID separator");
        } else {
            result.push_back(static_cast<char>((hex(uuid[offset]) << 4) | hex(uuid[offset + 1])));
            offset += 2;
        }
    }
    return result;
}
std::string VlessRequest(uint16_t port, std::string_view payload, uint8_t command,
                         std::string_view host, std::string_view user) {
    return std::string(1, '\0') + UuidBytes(user) + std::string(1, '\0') + std::string(1, static_cast<char>(command)) +
           BigEndian(port, 2) + HostEncoding(host, 2, 3) + std::string(payload);
}
std::string SocksAddress(uint16_t port, std::string_view host) { return HostEncoding(host, 3, 4) + BigEndian(port, 2); }
std::string AnyTlsFrame(uint8_t command, uint32_t stream, std::string_view payload) {
    if (payload.size() > UINT16_MAX) throw std::invalid_argument("AnyTLS frame exceeds 65535 bytes");
    return std::string(1, static_cast<char>(command)) + BigEndian(stream, 4) + BigEndian(payload.size(), 2) + std::string(payload);
}
AnyTlsRecord ReadAnyTls(TlsSocket& socket, Milliseconds timeout) {
    const auto deadline = Expires(timeout);
    const auto header = socket.ReadExact(7, timeout);
    const auto remaining = std::chrono::duration_cast<Milliseconds>(deadline - Clock::now());
    CheckDeadline(deadline);
    return {static_cast<uint8_t>(header[0]), static_cast<uint32_t>(ReadBigEndian(std::string_view(header).substr(1, 4))),
            socket.ReadExact(static_cast<size_t>(ReadBigEndian(std::string_view(header).substr(5, 2))), remaining)};
}
void AnyTlsAuthenticate(TlsSocket& socket, std::string_view password, uint16_t padding) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    SHA256(reinterpret_cast<const unsigned char*>(password.data()), password.size(), digest.data());
    socket.Write(std::string(reinterpret_cast<const char*>(digest.data()), digest.size()) + BigEndian(padding, 2) + std::string(padding, '\0'));
}
void ReadAnyTlsAuthentication(TlsSocket& socket, std::string_view password) {
    const auto deadline = Expires(5s);
    const auto header = socket.ReadExact(34);
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    SHA256(reinterpret_cast<const unsigned char*>(password.data()), password.size(), digest.data());
    if (std::memcmp(header.data(), digest.data(), digest.size()) != 0) throw std::runtime_error("AnyTLS authentication digest mismatch");
    CheckDeadline(deadline);
    socket.ReadExact(static_cast<size_t>(ReadBigEndian(std::string_view(header).substr(32))),
                     std::chrono::duration_cast<Milliseconds>(deadline - Clock::now()));
}
} // namespace cnode::e2e
