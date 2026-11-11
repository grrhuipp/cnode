#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/error.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/target_address.hpp"
#include "common/unsafe.hpp"

#include <tl/expected.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

class ConnectionLimiter;
struct ConnectionFamily;
class AsyncStream;
struct TimeoutsConfig;

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
struct UDPPacketView {
    const TargetAddress& target;
    std::span<const uint8_t> data;
};


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
        ::SecureZeroMemory(bytes.data(), bytes.size());
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
            ::ConstantTimeEqual(bytes.data(), other.bytes.data(), size);
    }

    std::array<uint8_t, kMaxBytes> bytes{};
    uint8_t size = 0;
};

struct InboundDatagramAssociationPolicy;

enum class InboundDatagramCheck : uint8_t { Inspect, Commit };

// Protocol-owned continuity state. Control calls require an exclusive claim;
// the protocol's normal Process entry uses its concrete implementation locally.
class InboundDatagramAssociation {
public:
    using Clock = std::chrono::steady_clock;
    explicit InboundDatagramAssociation(const InboundDatagramAssociationPolicy& policy) noexcept
        : policy_(policy) {}
    virtual ~InboundDatagramAssociation() noexcept = default;
    [[nodiscard]] virtual bool Check(
        uint64_t packet_id, uint32_t worker, const udp::endpoint& endpoint,
        InboundDatagramCheck check, Clock::time_point now = Clock::now()) noexcept = 0;
    [[nodiscard]] const InboundDatagramAssociationPolicy& Policy() const noexcept {
        return policy_;
    }
    [[nodiscard]] Clock::time_point ProtectedUntil() const noexcept {
        return protected_until_;
    }
    // Guards against re-entrant local commits while handoff inspection/creation runs.
    bool claimed{true};

protected:
    void ProtectUntil(Clock::time_point deadline) noexcept {
        protected_until_ = deadline;
    }

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
        size_t hash = 2166136261u;
        for (size_t i = 0; i < key.owner.size; ++i)
            hash = (hash ^ key.owner.bytes[i]) * 16777619u;
        hash = (hash ^ key.owner.size) * 16777619u;
        hash ^= std::hash<uint64_t>{}(key.session_id) + (hash << 6) + (hash >> 2);
        return hash ^ std::hash<const proxyman::inbound::ProtocolSettings*>{}(key.configuration);
    }
};

// One index per listener on its receiving Worker. Entries borrow the state
// owned by a live association row; detached/prepared rows carry null entries.
using InboundDatagramAssociationIndex = memory::UnorderedMap<
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
    TargetAddress target;
    buf::MultiBuffer payload;
    std::optional<ForwardedMetadata> forwarded;
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
    const UserProfile* user = nullptr;
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
    virtual net::awaitable<RelayResult> Process(
        std::unique_ptr<AsyncStream> stream,
        routing::Dispatcher& dispatcher,
        const proxyman::inbound::ReceiverSettings& receiver,
        net::io_context& io_context,
        session::Context& ctx,
        const TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) = 0;

    // Native datagrams enter through the same protocol handler abstraction.
    // The owning UDP runtime performs the dispatcher handoff after protocol
    // parsing and authentication.
    [[nodiscard]] virtual tl::expected<InboundDatagramResult, ErrorCode>
    Process(const InboundDatagramRequest&) {
        return tl::unexpected(ErrorCode::NOT_SUPPORTED);
    }
    // Prepared only when the authenticated datagram starts an association.
    [[nodiscard]] virtual tl::expected<std::shared_ptr<InboundDatagramResponse>, ErrorCode>
    CreateDatagramResponse(const InboundDatagramResult&) {
        return tl::unexpected(ErrorCode::NOT_SUPPORTED);
    }
};

