#pragma once

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>

#include <chrono>
#include <atomic>
#include <cstdint>
#include <cstddef>
#include <exception>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <utility>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <poll.h>
#include <sys/socket.h>

namespace cnode::e2e {
using Json = nlohmann::json;
using namespace std::chrono_literals;
using Milliseconds = std::chrono::milliseconds;

std::filesystem::path Binary();
std::filesystem::path SourceRoot();
std::string ReadFile(const std::filesystem::path& path);
void WriteFile(const std::filesystem::path& path, std::string_view content);
void WriteJson(const std::filesystem::path& root, std::string_view name, const Json& value);
void Configure(const std::filesystem::path& root, Json inbound, Json outbound, unsigned workers = 1);
Json TlsSettings(bool server);
void Until(const std::function<bool()>& condition, Milliseconds timeout = 5s);

class TempDir {
public:
    TempDir();
    ~TempDir();
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    const std::filesystem::path& Path() const noexcept { return path_; }
private:
    std::filesystem::path path_;
};

class Child {
public:
    Child(std::vector<std::string> argv, const std::filesystem::path& log,
          const std::filesystem::path& cwd = {});
    ~Child();
    Child(const Child&) = delete;
    Child& operator=(const Child&) = delete;
    struct MemorySnapshot {
        uint64_t vm_rss_bytes;
        uint64_t vm_hwm_bytes;
        uint64_t smaps_rollup_rss_bytes;
        uint64_t smaps_rollup_pss_bytes;
        uint64_t smaps_rollup_anonymous_bytes;
        uint64_t smaps_rollup_anon_huge_pages_bytes;
        uint64_t smaps_rollup_file_pmd_mapped_bytes;
    };
    // Linux /proc status and smaps_rollup for this live process, not descendants
    // or the harness. VmRSS is current RSS; VmHWM is its lifetime high-water mark
    // at sampling. Both are kernel RSS accounting estimates, not PSS.
    // Rollup sums per-mapping accounting at sampling, not a peak. Its PSS
    // apportions shared resident pages; neither source measures private memory.
    // The two reads and the rollup mapping walk are not an atomic snapshot.
    // Throws if the child exits or any required field cannot be read/parsed.
    MemorySnapshot ReadMemorySnapshot();
    bool Running();
    // Wait/Stop return the exit code, or 128 + signal for signal termination.
    int Wait(Milliseconds timeout = 5s);
    void Signal(int signal);
    int Stop(Milliseconds timeout = 5s);
    void WaitForLog(std::string_view text, Milliseconds timeout = 10s);
    const std::filesystem::path& LogPath() const noexcept { return log_; }
private:
    int pid_ = -1;
    int status_ = -1;
    bool reaped_ = false;
    std::filesystem::path log_;
};

class Socket {
public:
    Socket() = default;
    explicit Socket(int fd);
    ~Socket();
    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    // Local socket addresses are numeric IPv4/IPv6 (or localhost): no
    // unbounded resolver call is hidden inside an I/O deadline.
    static Socket Listen(uint16_t port = 0, std::string_view address = "127.0.0.1");
    static Socket Connect(uint16_t port, std::string_view address = "127.0.0.1", Milliseconds timeout = 5s);
    static Socket BindUdp(uint16_t port = 0, std::string_view address = "127.0.0.1");
    Socket Accept(Milliseconds timeout = 5s) const;
    uint16_t Port() const;
    int Fd() const noexcept { return fd_; }
    int Release() noexcept;
    void Close() noexcept;
    void ShutdownWrite();
    void Write(std::string_view bytes, Milliseconds timeout = 5s);
    std::string Read(size_t maximum = 65536, Milliseconds timeout = 5s);
    std::string ReadExact(size_t count, Milliseconds timeout = 5s);
    void SendTo(std::string_view bytes, uint16_t port, std::string_view address = "127.0.0.1");
private:
    int fd_ = -1;
};

class TlsContext {
public:
    explicit TlsContext(bool server);
    ~TlsContext();
    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;
    SSL_CTX* Get() const noexcept { return context_; }
private:
    SSL_CTX* context_ = nullptr;
};

class TlsSocket {
public:
    TlsSocket(Socket socket, TlsContext& context, bool server, Milliseconds timeout = 5s);
    ~TlsSocket();
    TlsSocket(const TlsSocket&) = delete;
    TlsSocket& operator=(const TlsSocket&) = delete;
    void Write(std::string_view bytes, Milliseconds timeout = 5s);
    std::string Read(size_t maximum = 65536, Milliseconds timeout = 5s);
    std::string ReadExact(size_t count, Milliseconds timeout = 5s);
    void ShutdownWrite();
    void Close() noexcept;
    int Fd() const noexcept { return socket_.Fd(); }
    SSL* Get() const noexcept { return ssl_; }
private:
    Socket socket_;
    SSL* ssl_ = nullptr;
};

// Each peer thread is joined; exceptions are observed explicitly by Join().
class PeerThread {
public:
    explicit PeerThread(std::function<void()> task);
    ~PeerThread();
    PeerThread(const PeerThread&) = delete;
    PeerThread& operator=(const PeerThread&) = delete;
    void Join();
private:
    std::exception_ptr error_;
    std::thread thread_;
};

// Every accepted handler is a real TCP destination, not a proxy substitute.
class Targets {
    Socket listener_ = Socket::Listen();
    std::atomic<bool> stop_{false};
    std::mutex mutex_;
    std::set<int> active_;
    std::vector<std::unique_ptr<PeerThread>> handlers_;
    std::unique_ptr<PeerThread> accept_;
public:
    explicit Targets(std::function<void(Socket&)> handler) {
        accept_ = std::make_unique<PeerThread>([this, handler = std::move(handler)] {
            while (!stop_) {
                pollfd item{listener_.Fd(), POLLIN, 0};
                if (poll(&item, 1, 25) <= 0) continue;
                auto socket = std::make_shared<Socket>(listener_.Accept());
                { std::lock_guard lock(mutex_); active_.insert(socket->Fd()); }
                handlers_.push_back(std::make_unique<PeerThread>([this, handler, socket] {
                    try { handler(*socket); }
                    catch (...) { if (!stop_) { std::lock_guard lock(mutex_); active_.erase(socket->Fd()); throw; } }
                    std::lock_guard lock(mutex_); active_.erase(socket->Fd());
                }));
            }
        });
    }
    ~Targets() { try { Join(); } catch (...) { ADD_FAILURE() << "unobserved destination peer failure"; } }
    uint16_t Port() const { return listener_.Port(); }
    void Join() {
        if (!accept_) return;
        stop_ = true;
        accept_->Join(); accept_.reset();
        { std::lock_guard lock(mutex_); for (int fd : active_) shutdown(fd, SHUT_RDWR); }
        std::exception_ptr error;
        for (auto& handler : handlers_) { try { handler->Join(); } catch (...) { if (!error) error = std::current_exception(); } }
        handlers_.clear();
        if (error) std::rethrow_exception(error);
    }
};

inline constexpr std::string_view UserId = "b831381d-6324-4d53-ad4f-8cda48b30811";
std::string UuidBytes(std::string_view uuid = UserId);
std::string VlessRequest(uint16_t port, std::string_view payload = {}, uint8_t command = 1,
                         std::string_view host = "127.0.0.1", std::string_view user = UserId);
std::string SocksAddress(uint16_t port, std::string_view host = "127.0.0.1");
std::string AnyTlsFrame(uint8_t command, uint32_t stream, std::string_view payload = {});
struct AnyTlsRecord { uint8_t command; uint32_t stream; std::string payload; };
AnyTlsRecord ReadAnyTls(TlsSocket& socket, Milliseconds timeout = 5s);
void AnyTlsAuthenticate(TlsSocket& socket, std::string_view password, uint16_t padding = 0);
void ReadAnyTlsAuthentication(TlsSocket& socket, std::string_view password);
std::string BigEndian(uint64_t value, size_t width);
uint64_t ReadBigEndian(std::string_view bytes);
} // namespace cnode::e2e
