#include "quic_peer.hpp"

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace cnode::e2e::quic {
namespace {

#if defined(__x86_64__)
constexpr uint32_t kAuditArch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
constexpr uint32_t kAuditArch = AUDIT_ARCH_AARCH64;
#else
constexpr uint32_t kAuditArch = 0;
#endif

// Linux 5.5 UAPI; the toolchain sysroot may carry older kernel headers.
constexpr uint32_t kContinueSyscall = 1u << 0;  // SECCOMP_USER_NOTIF_FLAG_CONTINUE

// 回环设备在发送路径上立即释放 socket 发送缓冲，内核拥塞导致的 EAGAIN 无法在
// 本机自然出现。本夹具以 seccomp 用户通知拦截 cnode 进程对 HY2 监听 socket 的
// sendto/sendmsg，按需回以 EAGAIN（等价于发送缓冲已满），其余调用原样执行。
// 过滤器安装在测试主线程，随 posix_spawn 继承给 cnode；监督线程先于过滤器创建，
// 自身不受拦截。
class UdpSendFault final {
public:
    UdpSendFault() : supervisor_([this] { Supervise(); }) {
        try {
            if (kAuditArch == 0) throw std::runtime_error("unsupported seccomp architecture");
            if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
                throw std::system_error(errno, std::generic_category(), "PR_SET_NO_NEW_PRIVS");
            std::array<sock_filter, 8> instructions{{
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kAuditArch, 1, 0),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendto, 2, 0),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendmsg, 1, 0),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
            }};
            sock_fprog program{static_cast<unsigned short>(instructions.size()), instructions.data()};
            const auto listener = ::syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
            if (listener < 0)
                throw std::system_error(errno, std::generic_category(), "seccomp user notification");
            listener_.store(static_cast<int>(listener), std::memory_order_release);
        } catch (...) {
            stop_.store(true);
            supervisor_.join();
            throw;
        }
    }

    ~UdpSendFault() {
        stop_.store(true);
        supervisor_.join();
        if (const int listener = listener_.load(); listener >= 0) ::close(listener);
    }

    UdpSendFault(const UdpSendFault&) = delete;
    UdpSendFault& operator=(const UdpSendFault&) = delete;

    // Every UDP socket bound to |port| in this network namespace; only those
    // held by another process (cnode) are failed.
    void Fail(uint16_t port) {
        inodes_ = BoundUdpInodes(port);
        if (inodes_.empty()) throw std::runtime_error("no UDP socket bound to the HY2 port");
        failing_.store(true, std::memory_order_release);
    }
    void Restore() noexcept { failing_.store(false, std::memory_order_release); }
    [[nodiscard]] uint64_t Injected() const noexcept { return injected_.load(); }

private:
    static std::vector<std::string> BoundUdpInodes(uint16_t port) {
        std::ifstream table("/proc/net/udp");
        std::string line;
        std::getline(table, line);
        char suffix[8];
        std::snprintf(suffix, sizeof(suffix), ":%04X", port);
        std::vector<std::string> inodes;
        while (std::getline(table, line)) {
            std::istringstream fields(line);
            std::string slot, local, remote, state, queues, timer, retransmits, uid, timeout, inode;
            fields >> slot >> local >> remote >> state >> queues >> timer >> retransmits >> uid >> timeout >> inode;
            if (local.ends_with(suffix)) inodes.push_back("socket:[" + inode + "]");
        }
        return inodes;
    }

    bool ShouldFail(const seccomp_notif& request) const {
        if (!failing_.load(std::memory_order_acquire)) return false;
        const auto thread = std::to_string(request.pid);
        if (::access(("/proc/self/task/" + thread).c_str(), F_OK) == 0) return false;
        const auto link = "/proc/" + thread + "/fd/" + std::to_string(request.data.args[0]);
        std::array<char, 64> target{};
        const auto length = ::readlink(link.c_str(), target.data(), target.size() - 1);
        if (length <= 0) return false;
        const std::string_view socket(target.data(), static_cast<size_t>(length));
        return std::find(inodes_.begin(), inodes_.end(), socket) != inodes_.end();
    }

    void Supervise() noexcept {
        while (!stop_.load()) {
            const int listener = listener_.load(std::memory_order_acquire);
            if (listener < 0) {
                std::this_thread::sleep_for(Milliseconds(1));
                continue;
            }
            pollfd item{listener, POLLIN, 0};
            if (::poll(&item, 1, 20) <= 0) continue;
            seccomp_notif request{};
            if (::ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &request) != 0) continue;
            seccomp_notif_resp response{};
            response.id = request.id;
            if (ShouldFail(request)) {
                response.error = -EAGAIN;
                injected_.fetch_add(1);
            } else {
                response.flags = kContinueSyscall;
            }
            // ENOENT: the calling thread was interrupted or exited meanwhile.
            (void)::ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response);
        }
    }

    std::vector<std::string> inodes_;
    std::atomic<int> listener_{-1};
    std::atomic<bool> stop_{false};
    std::atomic<bool> failing_{false};
    std::atomic<uint64_t> injected_{0};
    std::thread supervisor_;
};

// All QUIC connections of a Worker share its HY2 socket's send queue. While the
// kernel refuses that socket's sends, the queue fills; afterwards every
// connection must resume on its original QUIC connection, none torn down.
TEST(QuicSendBackpressure, FullSocketQueueKeepsEveryConnection) {
    UdpSendFault fault;  // Outlives every filtered thread, cnode included.
    TempDir root;
    Targets target([](Socket& socket) {
        for (;;) {
            const auto bytes = socket.Read(65536, 30s);
            if (bytes.empty()) break;
            socket.Write(bytes);
        }
    });
    auto reservation = Socket::ReserveUdp();
    const auto port = reservation.Port();
    Configure(root.Path(), HysteriaInbound(port),
        {{"protocol", "freedom"}, {"settings", Json::object()}});
    Child server({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    server.WaitForServerStart();

    // Enough connections that their congestion windows, ACKs and PTO probes
    // exceed the socket queue several times over while sends are refused.
    constexpr size_t kConnections = 96;
    const std::string address = "127.0.0.1:" + std::to_string(target.Port());
    std::vector<std::unique_ptr<Peer>> peers;
    std::vector<int64_t> streams;
    std::vector<std::string> expected;
    for (size_t index = 0; index < kConnections; ++index) {
        peers.push_back(std::make_unique<Peer>(port));
        expected.push_back("ready-" + std::to_string(index));
        streams.push_back(peers.back()->Open(address, expected.back()));
        peers.back()->WaitPayload(streams.back(), expected.back());
    }

    fault.Fail(port);
    const std::string payload = Pattern(48 * 1024);
    for (size_t index = 0; index < kConnections; ++index) {
        expected[index] += payload;
        peers[index]->Send(streams[index], payload);
    }
    const auto blocked_until = std::chrono::steady_clock::now() + 2s;
    while (std::chrono::steady_clock::now() < blocked_until) {
        for (auto& peer : peers) peer->Pump(Milliseconds(0));
        std::this_thread::sleep_for(Milliseconds(1));
    }
    EXPECT_GT(fault.Injected(), 0u) << "no HY2 socket send was refused";
    fault.Restore();

    const auto deadline = std::chrono::steady_clock::now() + 20s;
    auto complete = [&](size_t index) { return peers[index]->PayloadEquals(streams[index], expected[index]); };
    for (;;) {
        bool all = true;
        for (size_t index = 0; index < kConnections; ++index) {
            if (complete(index)) continue;
            all = false;
            peers[index]->Pump(Milliseconds(0));
        }
        if (all || std::chrono::steady_clock::now() >= deadline) break;
        std::this_thread::sleep_for(Milliseconds(1));
    }
    size_t stalled = 0;
    for (size_t index = 0; index < kConnections; ++index) {
        if (complete(index)) continue;
        if (++stalled <= 4)
            ADD_FAILURE() << "connection " << index << " stalled: " << peers[index]->DescribeStream(streams[index]);
    }
    EXPECT_EQ(stalled, 0u) << "connections torn down by a full shared socket queue";
    // The same QUIC connections still carry new streams.
    for (size_t index = 0; index < kConnections && stalled == 0; ++index) {
        const auto fresh = peers[index]->Open(address, "after-" + std::to_string(index));
        peers[index]->WaitPayload(fresh, "after-" + std::to_string(index));
    }
    peers.clear();
    EXPECT_EQ(server.Stop(), 0);
    target.Join();
}

}  // namespace
}  // namespace cnode::e2e::quic
