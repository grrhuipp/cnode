#pragma once

#include "acppnode/app/udp_endpoint_key.hpp"
#include "acppnode/app/proxyman/inbound/udp_handler.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/error.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {
struct TargetAddress;
class UDPSession;
}  // namespace acpp

namespace acpp::proxyman::inbound {

// ============================================================================
// UdpWorker - per-Worker UDP inbound worker
//
// 对齐 xray-core app/proxyman/inbound udpWorker 的职责起点：绑定 tag 和
// Shadowsocks inbound Handler 实例。SO_REUSEPORT socket 与回包队列会继续从
// Worker 迁入这里；当前先把协议实例生命周期从 Worker map 中抽离。
// ============================================================================
class UdpWorker final {
public:
    class PendingUdpReply;
    struct PendingUdpReplyDeleter {
        void operator()(PendingUdpReply* reply) const noexcept;
    };
    using PendingUdpReplyPtr =
        std::unique_ptr<PendingUdpReply, PendingUdpReplyDeleter>;

    struct UdpClientSendResult {
        ErrorCode error = ErrorCode::OUTBOUND_CONNECTION_FAILED;
        bool found = false;
        int64_t user_id = 0;
    };

    UdpWorker(std::string tag, std::unique_ptr<UdpHandler> proxy);
    ~UdpWorker() noexcept;

    UdpWorker(const UdpWorker&) = delete;
    UdpWorker& operator=(const UdpWorker&) = delete;
    UdpWorker(UdpWorker&&) noexcept;
    UdpWorker& operator=(UdpWorker&&) noexcept;

    [[nodiscard]] std::string_view Tag() const noexcept;

    void Close() noexcept;

    void SetBanTrackingEnabled(bool enabled) noexcept;

    [[nodiscard]] bool EnqueueReply(const std::string& socket_key,
                                    udp::endpoint endpoint,
                                    buf::MultiBuffer payload);
    [[nodiscard]] bool EnqueueReply(const std::string& socket_key,
                                    udp::endpoint endpoint,
                                    buf::BufferGuard payload);
    [[nodiscard]] PendingUdpReplyPtr BeginReplySend(const std::string& socket_key);
    [[nodiscard]] static const std::vector<net::const_buffer>&
    ReplySendBuffers(const PendingUdpReply& reply) noexcept;
    [[nodiscard]] static const udp::endpoint&
    ReplyEndpoint(const PendingUdpReply& reply) noexcept;
    [[nodiscard]] bool CompleteReplySend(const std::string& socket_key);
    void ClearReplyQueue(const std::string& socket_key);

    [[nodiscard]] bool HasClientSession(const std::string& socket_key,
                                        const UdpEndpointKey& client_key) const noexcept;
    void UpsertClientSession(const std::string& socket_key,
                             const UdpEndpointKey& client_key,
                             UDPSession& session,
                             uint64_t response_callback,
                             int64_t user_id,
                             std::chrono::steady_clock::time_point now);
    [[nodiscard]] net::awaitable<UdpClientSendResult>
    SendToClientSession(const std::string& socket_key,
                        const UdpEndpointKey& client_key,
                        const TargetAddress& target,
                        buf::MultiBuffer payload,
                        std::chrono::steady_clock::time_point now,
                        std::chrono::seconds idle_timeout);
    void CleanupIdleClientSessions(const std::string& socket_key,
                                   std::chrono::steady_clock::time_point now,
                                   std::chrono::seconds idle_timeout);
    void CleanupClientSessions(const std::string& socket_key);
    void CleanupAllClientSessions();

    [[nodiscard]] udp::socket* MakeSocket(net::io_context& io_context);
    [[nodiscard]] udp::socket* AttachSocket(const std::string& socket_key, udp::socket* socket);
    [[nodiscard]] udp::socket* FindSocket(const std::string& socket_key) noexcept;
    [[nodiscard]] const udp::socket* FindSocket(const std::string& socket_key) const noexcept;
    [[nodiscard]] std::vector<std::string> SocketKeys() const;
    void CloseSocket(const std::string& socket_key) noexcept;
    void CloseAllSockets() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::proxyman::inbound
