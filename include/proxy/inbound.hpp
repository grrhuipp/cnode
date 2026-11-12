#pragma once

#include "app/relay.hpp"
#include "common/asio_types.hpp"
#include "common/error.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/hash.hpp"
#include "common/target_address.hpp"
#include <openssl/mem.h>

#include <tl/expected.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_map>

namespace app {

class ConnectionLimiter;
struct ConnectionFamily;

}  // namespace app
namespace transport {

class AsyncStream;

}  // namespace transport
namespace infra {

struct TimeoutsConfig;

}  // namespace infra

namespace session {
struct Context;
}

namespace proxyman::inbound {
struct ReceiverSettings;
}

namespace routing {
class Dispatcher;
}

namespace proxyman::inbound {
class ProtocolSettings;
}

// Native datagram response view. Borrowed bytes and target are valid only
// during encoding; a queued response must own its resulting payload.
namespace proxy {

struct UDPPacketView {
    const common::TargetAddress& target;
    std::span<const uint8_t> data;
};

// Protocol-owned encoder. Ingress owns delivery, never protocol key/state.
class InboundDatagramResponse {
public:
    virtual ~InboundDatagramResponse() noexcept = default;
    [[nodiscard]] virtual buf::MultiBuffer Encode(UDPPacketView packet) = 0;
};



struct InboundDatagramOwner {
    static constexpr size_t kMaxBytes = 32;

    InboundDatagramOwner() = default;
    InboundDatagramOwner(const InboundDatagramOwner&) = default;
    InboundDatagramOwner& operator=(const InboundDatagramOwner&) = default;
    InboundDatagramOwner(InboundDatagramOwner&&) noexcept = default;
    InboundDatagramOwner& operator=(InboundDatagramOwner&&) noexcept = default;
    ~InboundDatagramOwner() noexcept {
        OPENSSL_cleanse(bytes.data(), bytes.size());
    }

    [[nodiscard]] bool Assign(std::span<const uint8_t> value) noexcept {
        if (value.empty() || value.size() > bytes.size()) {
            size = 0;
            return false;
        }
        std::copy(value.begin(), value.end(), bytes.begin());
        size = static_cast<uint8_t>(value.size());
        return true;
    }

    [[nodiscard]] bool Same(const InboundDatagramOwner& other) const noexcept {
        return size == other.size &&
            CRYPTO_memcmp(bytes.data(), other.bytes.data(), size) == 0;
    }

    std::array<uint8_t, kMaxBytes> bytes{};
    uint8_t size = 0;
};

struct InboundDatagramAssociationPolicy;
enum class InboundDatagramCheck : uint8_t { Inspect, Commit };

// The open protocol boundary for replay/path continuity. The directory retains
// this state after relay closure, independently of the expired session owner.
class InboundDatagramAssociation {
public:
    using Clock = std::chrono::steady_clock;
    explicit InboundDatagramAssociation(const InboundDatagramAssociationPolicy& policy) noexcept
        : policy_(policy) {}
    virtual ~InboundDatagramAssociation() noexcept = default;
    [[nodiscard]] virtual bool Check(uint64_t packet_id, uint32_t worker,
        const udp::endpoint& endpoint, InboundDatagramCheck check,
        Clock::time_point now = Clock::now()) noexcept = 0;
    [[nodiscard]] const InboundDatagramAssociationPolicy& Policy() const noexcept { return policy_; }
    [[nodiscard]] Clock::time_point ProtectedUntil() const noexcept { return protected_until_; }
    bool claimed = true;
protected:
    void ProtectUntil(Clock::time_point deadline) noexcept { protected_until_ = deadline; }
private:
    const InboundDatagramAssociationPolicy& policy_;
    Clock::time_point protected_until_{};
};

struct InboundDatagramAssociationPolicy {
    size_t capacity;
    std::chrono::steady_clock::duration retention;
    std::unique_ptr<InboundDatagramAssociation> (*create)();
};


struct InboundDatagramAssociationKey {
    InboundDatagramOwner owner;
    uint64_t session_id;
    const proxyman::inbound::ProtocolSettings* configuration;
    [[nodiscard]] bool operator==(const InboundDatagramAssociationKey& other) const noexcept {
        return session_id == other.session_id && configuration == other.configuration &&
            owner.Same(other.owner);
    }
};

struct InboundDatagramAssociationKeyHash {
    [[nodiscard]] size_t operator()(const InboundDatagramAssociationKey& key) const noexcept {
        uint64_t hash = common::Fnv1a64(std::span<const uint8_t>(key.owner.bytes.data(), key.owner.size));
        hash = common::Fnv1a64Step(hash, key.owner.size);
        hash = common::Mix64(hash ^ key.session_id);
        hash = common::Mix64(hash ^ reinterpret_cast<uintptr_t>(key.configuration));
        return static_cast<size_t>(hash);
    }
};

// One index per listener on its receiving Worker. Entries borrow the state
// owned by a live association row; detached/prepared rows carry null entries.
using InboundDatagramAssociationIndex = std::unordered_map<
    InboundDatagramAssociationKey, InboundDatagramAssociation*,
    InboundDatagramAssociationKeyHash>;

struct InboundDatagramRequest {
    std::string_view tag;
    std::span<const uint8_t> payload;
    const InboundDatagramAssociationIndex* associations = nullptr;
    const proxyman::inbound::ProtocolSettings* configuration = nullptr;
    uint32_t worker_id = 0;
    udp::endpoint client_endpoint;
};

struct InboundDatagramResult {
    common::TargetAddress target;
    buf::MultiBuffer payload;
    std::optional<common::ForwardedMetadata> forwarded;
    // Absent means that the normalized client endpoint identifies the session.
    std::optional<uint64_t> session_id;
    // Protocol session IDs are scoped by the authenticated credential.
    InboundDatagramOwner session_owner;
    // Present only with an authenticated, replay-protected protocol session.
    std::optional<uint64_t> packet_id;
    const InboundDatagramAssociationPolicy* association_policy = nullptr;
    // Borrowed only until the synchronous ProcessDatagram call returns.
    InboundDatagramAssociation* committed_association = nullptr;
    // Synchronous-only view into the Worker's current user snapshot;
    // ingress copies the profile before any asynchronous handoff.
    const common::UserProfile* user = nullptr;
};

// ============================================================================
// Inbound - 入站协议处理器接口（代理层）
//
// 职责：协议解析、认证和 dispatcher handoff，不涉及传输层（TLS/WS 由 proxyman inbound 负责）。
//
// 协议实现示例：
//   - VMessInbound: Process 解析 AEAD 头后提交 session::Context 给 dispatcher
//   - TrojanInbound: Process 解析 SHA224+目标后提交 session::Context 给 dispatcher
// ============================================================================
class Inbound {
public:
    virtual ~Inbound() noexcept = default;

    // -----------------------------------------------------------------------
    // 从已建立的传输流中解析协议头，并移交给 dispatcher。
    //
    // @param stream  已完成 TLS/WS 等传输层握手的字节流
    // @param ctx     会话上下文（用于填充用户信息、错误记录）
    // @param pressure_idle_timeout Worker 当前压力模式的空闲超时秒数；0 表示未启用
    // @return        dispatcher/relay 结果；协议解析失败在进入 dispatcher 前返回错误
    // -----------------------------------------------------------------------
    virtual net::awaitable<app::RelayResult> Process(
        std::unique_ptr<transport::AsyncStream> stream,
        routing::Dispatcher& dispatcher,
        const proxyman::inbound::ReceiverSettings& receiver,
        net::io_context& io_context,
        session::Context& ctx,
        const infra::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) = 0;

    // Native datagrams enter through the same protocol handler abstraction.
    // The owning UDP runtime performs the dispatcher handoff after protocol
    // parsing and authentication.
    [[nodiscard]] virtual tl::expected<InboundDatagramResult, common::ErrorCode>
    Process(const InboundDatagramRequest&) {
        return tl::unexpected(common::ErrorCode::NOT_SUPPORTED);
    }
    // Prepared only when the authenticated datagram starts an association.
    [[nodiscard]] virtual tl::expected<std::shared_ptr<InboundDatagramResponse>, common::ErrorCode>
    CreateDatagramResponse(const InboundDatagramResult&) {
        return tl::unexpected(common::ErrorCode::NOT_SUPPORTED);
    }
};

}  // namespace proxy

