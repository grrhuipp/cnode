#include "app/udp_flow_dispatcher.hpp"

#include "app/default_dispatcher.hpp"
#include "app/stats.hpp"
#include "common/awaitable_task_group.hpp"
#include "common/hash.hpp"
#include "common/session.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "sniff/sniffer.hpp"
#include "transport/async_stream.hpp"
#include "transport/async_write_gate.hpp"

#include <asio/post.hpp>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace app {
namespace {

constexpr size_t kMaxUdpRouteFlows = 64;
constexpr size_t kMaxUdpRouteTargets = 64;
constexpr size_t kMaxQuicAliases = 512;
constexpr size_t kMaxQuicAliasesPerFlow = 8;
constexpr size_t kMaxFlowQueuedDatagrams = 64;
constexpr size_t kMaxFlowQueuedBytes = 1024 * 1024;
constexpr size_t kMaxAssociationQueuedBytes = 4 * 1024 * 1024;

[[nodiscard]] uint64_t HashTarget(
    const common::TargetAddress& target) noexcept {
    uint64_t hash = common::kFnv1aOffset64;
    hash = common::Fnv1a64Step(hash, static_cast<uint8_t>(target.type));
    hash = common::Fnv1a64Step(hash, static_cast<uint8_t>(target.port >> 8));
    hash = common::Fnv1a64Step(hash, static_cast<uint8_t>(target.port));
    if (target.IsDomain()) {
        return common::Fnv1a64(target.host, hash);
    }
    if (!target.resolved_addr) return hash;
    const auto address = common::NormalizeAddress(*target.resolved_addr);
    if (address.is_v4()) {
        const auto bytes = address.to_v4().to_bytes();
        return common::Fnv1a64(bytes, hash);
    }
    if (address.is_v6()) {
        const auto value = address.to_v6();
        hash = common::Fnv1a64(value.to_bytes(), hash);
        const auto scope = value.scope_id();
        for (size_t shift = 0; shift < sizeof(scope) * 8; shift += 8) {
            hash = common::Fnv1a64Step(
                hash, static_cast<uint8_t>(scope >> shift));
        }
    }
    return hash;
}

struct TargetLookup {
    const common::TargetAddress* target = nullptr;
};

struct TargetHash {
    using is_transparent = void;

    [[nodiscard]] size_t operator()(
        const common::TargetAddress& target) const noexcept {
        return static_cast<size_t>(HashTarget(target));
    }
    [[nodiscard]] size_t operator()(TargetLookup lookup) const noexcept {
        return static_cast<size_t>(HashTarget(*lookup.target));
    }
};

struct TargetEqual {
    using is_transparent = void;

    [[nodiscard]] bool operator()(
        const common::TargetAddress& left,
        const common::TargetAddress& right) const noexcept {
        return left.SameEndpoint(right);
    }
    [[nodiscard]] bool operator()(
        const common::TargetAddress& left,
        TargetLookup right) const noexcept {
        return left.SameEndpoint(*right.target);
    }
    [[nodiscard]] bool operator()(
        TargetLookup left,
        const common::TargetAddress& right) const noexcept {
        return left.target->SameEndpoint(right);
    }
};

[[nodiscard]] uint64_t HashCid(
    const sniff::QuicConnectionId& cid,
    uint64_t hash = common::kFnv1aOffset64) noexcept {
    hash = common::Fnv1a64Step(hash, cid.size);
    return common::Fnv1a64(
        std::span<const uint8_t>(cid.bytes.data(), cid.size), hash);
}

struct UdpTargetState;
class UdpAssociationState;

struct UdpFlowKey {
    const UdpTargetState* target = nullptr;
    uint32_t quic_version = 0;
    sniff::QuicConnectionId initial_dcid;
    bool quic = false;

    [[nodiscard]] bool operator==(const UdpFlowKey& other) const noexcept {
        return target == other.target && quic == other.quic &&
            (!quic || (quic_version == other.quic_version &&
                       initial_dcid == other.initial_dcid));
    }
};

struct UdpFlowKeyHash {
    [[nodiscard]] size_t operator()(const UdpFlowKey& key) const noexcept {
        uint64_t hash = common::Mix64(
            reinterpret_cast<uintptr_t>(key.target));
        hash = common::Fnv1a64Step(hash, key.quic);
        if (key.quic) {
            for (unsigned shift = 0; shift < 32; shift += 8) {
                hash = common::Fnv1a64Step(
                    hash, static_cast<uint8_t>(key.quic_version >> shift));
            }
            hash = HashCid(key.initial_dcid, hash);
        }
        return static_cast<size_t>(common::Mix64(hash));
    }
};

struct QuicAliasKey {
    const UdpTargetState* target = nullptr;
    sniff::QuicConnectionId cid;

    [[nodiscard]] bool operator==(const QuicAliasKey& other) const noexcept {
        return target == other.target && cid == other.cid;
    }
};

struct QuicAliasKeyHash {
    [[nodiscard]] size_t operator()(const QuicAliasKey& key) const noexcept {
        return static_cast<size_t>(common::Mix64(HashCid(
            key.cid, common::Mix64(reinterpret_cast<uintptr_t>(key.target)))));
    }
};

class UdpRouteFlow final
    : public transport::MultiBufferReader,
      public transport::MultiBufferWriter,
      public std::enable_shared_from_this<UdpRouteFlow> {
public:
    UdpRouteFlow(
        UdpAssociationState& owner,
        const UdpFlowKey& key,
        const common::Context& parent,
        net::io_context& io_context);
    ~UdpRouteFlow() noexcept override;

    UdpRouteFlow(const UdpRouteFlow&) = delete;
    UdpRouteFlow& operator=(const UdpRouteFlow&) = delete;

    [[nodiscard]] bool Push(common::MultiBuffer payload);
    void FinishInput() noexcept;
    void Close(common::ErrorCode error) noexcept;

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override;
    transport::CancellationSource& Cancellation() noexcept override {
        return cancellation_;
    }
    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer payload) override;
    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override { co_return; }

    UdpAssociationState& owner;
    UdpFlowKey key;
    common::Context context;
    std::vector<sniff::QuicConnectionId> aliases;

private:
    struct QueuedDatagram {
        common::MultiBuffer payload;
        size_t bytes = 0;
    };

    void WakeReader() noexcept {
        (void)read_signal_.try_send(IoErrorCode{});
    }

    common::SignalChannel read_signal_;
    transport::CancellationSource cancellation_;
    common::RingDeque<QueuedDatagram> queue_;
    size_t queued_bytes_ = 0;
    common::ErrorCode terminal_error_ = common::ErrorCode::OK;
    bool closed_ = false;
};

struct UdpTargetState {
    const common::TargetAddress* target = nullptr;
    std::weak_ptr<UdpRouteFlow> plain_flow;
    bool saw_quic = false;
};

struct QuicAliasEntry {
    std::weak_ptr<UdpRouteFlow> owner;
    bool ambiguous = false;
};

class UdpAssociationState final
    : public std::enable_shared_from_this<UdpAssociationState> {
public:
    struct Resolution {
        std::shared_ptr<UdpRouteFlow> flow;
        common::ErrorCode error = common::ErrorCode::OK;
        bool created = false;
    };

    UdpAssociationState(
        transport::Link parent,
        common::Context& parent_context,
        app::StatsShard& stats,
        net::io_context& io_context,
        bool terminate_on_flow_error)
        : parent_(parent), parent_context_(parent_context), stats_(stats),
          io_context_(io_context),
          terminate_on_flow_error_(terminate_on_flow_error) {}

    [[nodiscard]] Resolution Resolve(
        const common::TargetAddress& target,
        std::span<const uint8_t> payload) {
        auto* target_state = FindOrCreateTarget(target);
        if (!target_state) {
            return {
                .flow = {},
                .error = common::ErrorCode::RESOURCE_EXHAUSTED,
            };
        }

        const auto long_header = sniff::InspectQuicLongHeader(payload);
        if (long_header) {
            if (auto alias = FindAlias(*target_state, long_header->destination);
                alias.error != common::ErrorCode::OK || alias.flow) {
                return alias;
            }
            if (long_header->type == sniff::QuicLongPacketType::Initial) {
                UdpFlowKey key{
                    .target = target_state,
                    .quic_version = long_header->version,
                    .initial_dcid = long_header->destination,
                    .quic = true,
                };
                auto resolved = FindOrCreateFlow(key);
                if (resolved.flow &&
                    !AddAlias(resolved.flow, long_header->destination)) {
                    FinishFlow(resolved.flow);
                    return {
                        .flow = {},
                        .error = common::ErrorCode::RESOURCE_EXHAUSTED,
                    };
                }
                return resolved;
            }
            return {
                .flow = {},
                .error = common::ErrorCode::PROTOCOL_DECODE_FAILED,
            };
        } else if (LooksLikeQuicShortHeader(payload) &&
                   target_state->saw_quic) {
            return ResolveShortHeader(*target_state, payload);
        }

        UdpFlowKey key{
            .target = target_state,
            .initial_dcid = {},
        };
        return FindOrCreateFlow(key);
    }

    void LearnReplyCid(
        const std::shared_ptr<UdpRouteFlow>& flow,
        const common::MultiBuffer& payload) {
        if (!flow->key.quic) return;
        const auto header = sniff::InspectQuicLongHeader(payload.FrontSpan());
        if (!header || header->source.size == 0) return;
        if (!AddAlias(flow, header->source)) {
            Fail(common::ErrorCode::RESOURCE_EXHAUSTED);
            throw transport::LinkError(common::ErrorCode::RESOURCE_EXHAUSTED);
        }
    }

    net::awaitable<void> WriteReply(
        const std::shared_ptr<UdpRouteFlow>& flow,
        common::MultiBuffer payload) {
        LearnReplyCid(flow, payload);
        if (!common::SetUdpTarget(payload, *flow->key.target->target)) {
            throw std::bad_alloc();
        }
        auto lease = write_gate_.TryAcquire();
        if (!lease) lease = co_await write_gate_.Acquire();
        if (!lease || failed_ != common::ErrorCode::OK) {
            payload.clear();
            throw transport::LinkError(
                failed_ == common::ErrorCode::OK
                    ? common::ErrorCode::CANCELLED : failed_);
        }
        try {
            co_await parent_.writer->WriteMultiBuffer(std::move(payload));
        } catch (...) {
            Fail(transport::ClassifyFailure(
                std::current_exception(), common::ErrorCode::SOCKET_WRITE_FAILED));
            throw;
        }
    }

    void FinishFlow(const std::shared_ptr<UdpRouteFlow>& flow) noexcept {
        for (const auto& cid : flow->aliases) {
            const QuicAliasKey key{flow->key.target, cid};
            auto found = aliases_.find(key);
            if (found == aliases_.end() || found->second.ambiguous) continue;
            if (found->second.owner.lock().get() == flow.get()) {
                aliases_.erase(found);
            }
        }
        auto* target = const_cast<UdpTargetState*>(flow->key.target);
        if (!flow->key.quic &&
            target->plain_flow.lock().get() == flow.get()) {
            target->plain_flow.reset();
        }
        if (auto found = flows_.find(flow->key);
            found != flows_.end() && found->second.get() == flow.get()) {
            flows_.erase(found);
        }
    }

    void FinishInputs() noexcept {
        for (auto& [key, flow] : flows_) {
            (void)key;
            flow->FinishInput();
        }
    }

    void CloseAll(common::ErrorCode error) noexcept {
        for (auto& [key, flow] : flows_) {
            (void)key;
            flow->Close(error);
        }
    }

    void Fail(common::ErrorCode error) noexcept {
        if (failed_ != common::ErrorCode::OK) return;
        failed_ = error == common::ErrorCode::OK
            ? common::ErrorCode::INTERNAL : error;
        write_gate_.Cancel();
        if (parent_.reader) {
            parent_.reader->Cancellation().CancelPending(failed_);
        }
    }

    void Deactivate() noexcept { active_ = false; }
    [[nodiscard]] common::ErrorCode Failure() const noexcept { return failed_; }

    void RecordResult(const RelayResult& child) noexcept {
        aggregate_.bytes_up = child.bytes_up >
            std::numeric_limits<uint64_t>::max() - aggregate_.bytes_up
            ? std::numeric_limits<uint64_t>::max()
            : aggregate_.bytes_up + child.bytes_up;
        aggregate_.bytes_down = child.bytes_down >
            std::numeric_limits<uint64_t>::max() - aggregate_.bytes_down
            ? std::numeric_limits<uint64_t>::max()
            : aggregate_.bytes_down + child.bytes_down;
    }

    void CompleteFlow(
        const std::shared_ptr<UdpRouteFlow>& flow,
        const RelayResult& child) noexcept {
        const bool terminate_stream_association =
            terminate_on_flow_error_ &&
            flows_.size() == 1 &&
            child.error != common::ErrorCode::OK &&
            child.error != common::ErrorCode::CANCELLED &&
            child.error != common::ErrorCode::SOCKET_EOF;
        RecordResult(child);
        FinishFlow(flow);
        if (terminate_stream_association) {
            const auto self = shared_from_this();
            try {
                net::post(io_context_, [self, error = child.error]() {
                    if (self->active_) self->Fail(error);
                });
            } catch (...) {
                failed_ = common::ErrorCode::RESOURCE_EXHAUSTED;
                write_gate_.Cancel();
            }
        }
    }

    [[nodiscard]] const RelayResult& Aggregate() const noexcept {
        return aggregate_;
    }

    void AddQueuedBytes(size_t bytes) noexcept { total_queued_bytes_ += bytes; }
    void RemoveQueuedBytes(size_t bytes) noexcept {
        total_queued_bytes_ -= std::min(total_queued_bytes_, bytes);
    }
    [[nodiscard]] bool CanQueue(size_t bytes) const noexcept {
        return bytes <= kMaxAssociationQueuedBytes -
            std::min(total_queued_bytes_, kMaxAssociationQueuedBytes);
    }

    void Reject(
        const common::TargetAddress& target,
        std::string_view reason,
        bool quic) {
        common::Context rejected;
        rejected.InitSubstreamFrom(parent_context_);
        rejected.content.network = common::Network::UDP;
        if (quic) rejected.content.protocol.assign(common::kQuic);
        rejected.outbound.target = target;
        LOG_ACCESS(common::FormatAccessLog(
            rejected, common::AccessStatus::Rejected, reason));
        stats_.OnError();
    }

private:
    [[nodiscard]] static bool LooksLikeQuicShortHeader(
        std::span<const uint8_t> payload) noexcept {
        return !payload.empty() && (payload[0] & 0xc0) == 0x40;
    }

    [[nodiscard]] UdpTargetState* FindOrCreateTarget(
        const common::TargetAddress& target) {
        auto found = targets_.find(TargetLookup{&target});
        if (found != targets_.end()) return found->second.get();
        if (targets_.size() >= kMaxUdpRouteTargets) return nullptr;
        auto state = std::make_unique<UdpTargetState>();
        auto [inserted, accepted] = targets_.emplace(target, std::move(state));
        if (!accepted) return inserted->second.get();
        inserted->second->target = &inserted->first;
        return inserted->second.get();
    }

    [[nodiscard]] Resolution FindOrCreateFlow(const UdpFlowKey& key) {
        if (auto found = flows_.find(key); found != flows_.end()) {
            return {.flow = found->second};
        }
        if (flows_.size() >= kMaxUdpRouteFlows) {
            return {
                .flow = {},
                .error = common::ErrorCode::RESOURCE_EXHAUSTED,
            };
        }
        auto flow = std::make_shared<UdpRouteFlow>(
            *this, key, parent_context_, io_context_);
        auto [inserted, accepted] = flows_.emplace(key, flow);
        if (!accepted) return {.flow = inserted->second};
        if (key.quic) {
            const_cast<UdpTargetState*>(key.target)->saw_quic = true;
        } else {
            const_cast<UdpTargetState*>(key.target)->plain_flow = flow;
        }
        return {.flow = std::move(flow), .created = true};
    }

    [[nodiscard]] Resolution FindAlias(
        UdpTargetState& target,
        const sniff::QuicConnectionId& cid) {
        if (cid.size == 0) return {};
        const auto found = aliases_.find(QuicAliasKey{&target, cid});
        if (found == aliases_.end()) return {};
        if (found->second.ambiguous) {
            return {
                .flow = {},
                .error = common::ErrorCode::PROTOCOL_DECODE_FAILED,
            };
        }
        auto flow = found->second.owner.lock();
        if (!flow) {
            aliases_.erase(found);
            return {};
        }
        return {.flow = std::move(flow)};
    }

    [[nodiscard]] Resolution ResolveShortHeader(
        UdpTargetState& target,
        std::span<const uint8_t> payload) {
        std::shared_ptr<UdpRouteFlow> selected;
        for (uint8_t size = 1; size <= 20; ++size) {
            if ((cid_lengths_ & (uint32_t{1} << size)) == 0 ||
                payload.size() < static_cast<size_t>(size) + 1) {
                continue;
            }
            sniff::QuicConnectionId cid;
            cid.size = size;
            std::copy_n(payload.begin() + 1, size, cid.bytes.begin());
            auto resolved = FindAlias(target, cid);
            if (resolved.error != common::ErrorCode::OK) return resolved;
            if (!resolved.flow) continue;
            if (selected && selected.get() != resolved.flow.get()) {
                return {
                    .flow = {},
                    .error = common::ErrorCode::PROTOCOL_DECODE_FAILED,
                };
            }
            selected = std::move(resolved.flow);
        }
        if (!selected) {
            return {
                .flow = {},
                .error = common::ErrorCode::PROTOCOL_DECODE_FAILED,
            };
        }
        return {.flow = std::move(selected)};
    }

    [[nodiscard]] bool AddAlias(
        const std::shared_ptr<UdpRouteFlow>& flow,
        const sniff::QuicConnectionId& cid) {
        if (cid.size == 0) return true;
        if (std::find(flow->aliases.begin(), flow->aliases.end(), cid) ==
            flow->aliases.end()) {
            if (flow->aliases.size() >= kMaxQuicAliasesPerFlow) return false;
            flow->aliases.push_back(cid);
        }
        cid_lengths_ |= uint32_t{1} << cid.size;
        const QuicAliasKey key{flow->key.target, cid};
        if (auto found = aliases_.find(key); found != aliases_.end()) {
            if (found->second.ambiguous) return true;
            auto current = found->second.owner.lock();
            if (!current) {
                found->second.owner = flow;
                return true;
            }
            if (current.get() != flow.get()) {
                found->second.owner.reset();
                found->second.ambiguous = true;
            }
            return true;
        }
        if (aliases_.size() >= kMaxQuicAliases) return false;
        aliases_.emplace(key, QuicAliasEntry{flow, false});
        return true;
    }

    transport::Link parent_;
    common::Context& parent_context_;
    app::StatsShard& stats_;
    net::io_context& io_context_;
    bool terminate_on_flow_error_ = false;
    transport::AsyncWriteGate write_gate_;
    std::unordered_map<
        common::TargetAddress,
        std::unique_ptr<UdpTargetState>,
        TargetHash,
        TargetEqual> targets_;
    std::unordered_map<UdpFlowKey, std::shared_ptr<UdpRouteFlow>, UdpFlowKeyHash>
        flows_;
    std::unordered_map<QuicAliasKey, QuicAliasEntry, QuicAliasKeyHash> aliases_;
    RelayResult aggregate_;
    size_t total_queued_bytes_ = 0;
    uint32_t cid_lengths_ = 0;
    bool active_ = true;
    common::ErrorCode failed_ = common::ErrorCode::OK;
};

UdpRouteFlow::UdpRouteFlow(
    UdpAssociationState& owner_value,
    const UdpFlowKey& key_value,
    const common::Context& parent,
    net::io_context& io_context)
    : owner(owner_value), key(key_value),
      read_signal_(io_context.get_executor(), 1) {
    context.InitSubstreamFrom(parent);
    context.content.network = common::Network::UDP;
    context.outbound.target = *key.target->target;
}

UdpRouteFlow::~UdpRouteFlow() noexcept {
    if (!queue_.empty()) owner.RemoveQueuedBytes(queued_bytes_);
}

bool UdpRouteFlow::Push(common::MultiBuffer payload) {
    const size_t bytes = payload.byte_size();
    if (closed_ || queue_.size() >= kMaxFlowQueuedDatagrams ||
        bytes > kMaxFlowQueuedBytes - std::min(queued_bytes_, kMaxFlowQueuedBytes) ||
        !owner.CanQueue(bytes)) {
        payload.clear();
        if (!closed_) Close(common::ErrorCode::RESOURCE_EXHAUSTED);
        return false;
    }
    queue_.push_back(QueuedDatagram{std::move(payload), bytes});
    queued_bytes_ += bytes;
    owner.AddQueuedBytes(bytes);
    WakeReader();
    return true;
}

void UdpRouteFlow::FinishInput() noexcept {
    if (closed_) return;
    closed_ = true;
    terminal_error_ = common::ErrorCode::OK;
    WakeReader();
}

void UdpRouteFlow::Close(common::ErrorCode error) noexcept {
    if (closed_) return;
    closed_ = true;
    terminal_error_ = error;
    owner.RemoveQueuedBytes(queued_bytes_);
    queue_.clear();
    queued_bytes_ = 0;
    cancellation_.Stop(error);
    WakeReader();
}

net::awaitable<common::MultiBuffer> UdpRouteFlow::ReadMultiBuffer() {
    for (;;) {
        if (!queue_.empty()) {
            auto item = std::move(queue_.front());
            queue_.pop_front();
            queued_bytes_ -= item.bytes;
            owner.RemoveQueuedBytes(item.bytes);
            co_return std::move(item.payload);
        }
        if (closed_) {
            if (terminal_error_ != common::ErrorCode::OK) {
                throw transport::LinkError(terminal_error_);
            }
            co_return common::MultiBuffer{};
        }
        auto [error] = co_await read_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (error) {
            throw IoSystemError(
                io_error::operation_aborted, "UDP route flow read cancelled");
        }
    }
}

net::awaitable<void> UdpRouteFlow::WriteMultiBuffer(
    common::MultiBuffer payload) {
    co_await owner.WriteReply(shared_from_this(), std::move(payload));
}

net::awaitable<void> UdpRouteFlow::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    co_await WriteBuffersAsMultiBuffer(buffers);
}


}  // namespace

net::awaitable<void> UdpFlowDispatcher::Run(
    DefaultDispatcher& dispatcher,
    net::io_context& io_context,
    const routing::DispatchPolicy& policy,
    std::unique_ptr<transport::AsyncStream> inbound,
    transport::Link inbound_link,
    common::InitialPayload first_packet,
    common::Context& parent_context,
    StatsShard& stats,
    const infra::TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout,
    RelayResult& result,
    common::ErrorCode& cancellation_reason) {
    const bool has_protocol_link = inbound_link.Valid();
    transport::AsyncStream* inbound_endpoint = inbound.get();
    transport::Link parent_link{
        has_protocol_link ? inbound_link.reader : inbound_endpoint,
        has_protocol_link ? inbound_link.writer : inbound_endpoint,
        inbound_link.control ? inbound_link.control : inbound_endpoint,
    };
    if (!parent_link.Valid()) {
        result.error = common::ErrorCode::PROTOCOL_DECODE_FAILED;
        co_return;
    }

    auto state = std::make_shared<UdpAssociationState>(
        parent_link, parent_context, stats, io_context, has_protocol_link);
    common::ResidentTaskGroup children(io_context.get_executor());
    std::exception_ptr failure;
    common::MultiBuffer initial = std::move(first_packet).MoveToMultiBuffer();

    static constexpr auto run_flow = [](
        DefaultDispatcher* dispatcher,
        net::io_context* io_context,
        const routing::DispatchPolicy* policy,
        StatsShard* stats,
        const infra::TimeoutsConfig* timeouts,
        uint32_t pressure_idle_timeout,
        std::shared_ptr<UdpAssociationState> state,
        std::shared_ptr<UdpRouteFlow> flow) -> net::awaitable<void> {
        RelayResult child_result;
        common::ErrorCode child_cancellation = common::ErrorCode::OK;
        common::InitialPayload no_initial_payload;
        try {
            co_await dispatcher->DispatchPreparedLink(
                *io_context, *policy, nullptr,
                transport::Link{flow.get(), flow.get()},
                no_initial_payload, flow->context, *stats, *timeouts,
                pressure_idle_timeout, false,
                child_result, child_cancellation);
        } catch (...) {
            const auto error = transport::ClassifyFailure(
                std::current_exception(), common::ErrorCode::INTERNAL);
            if (error != common::ErrorCode::CANCELLED &&
                error != common::ErrorCode::SOCKET_EOF) {
                stats->OnError();
                LOG_CONN_DEBUG(
                    flow->context,
                    "UDP route flow failed > {}",
                    common::ErrorCodeToString(error));
            }
            child_result.error = error;
        }
        state->CompleteFlow(flow, child_result);
        co_return;
    };

    auto spawn_flow = [&](const std::shared_ptr<UdpRouteFlow>& flow) {
        children.Spawn(
            run_flow(
                &dispatcher, &io_context, &policy, &stats, &timeouts,
                pressure_idle_timeout, state, flow),
            &flow->Cancellation());
    };

    auto process = [&](common::MultiBuffer packet) {
        auto datagram = common::InspectUdpDatagram(packet);
        if (datagram.status == common::UdpDatagramStatus::MissingTarget &&
            parent_context.outbound.target.IsValid() &&
            common::SetUdpTarget(packet, parent_context.outbound.target)) {
            datagram = common::InspectUdpDatagram(packet);
        }
        if (!datagram.Valid() || !datagram.target || !datagram.target->IsValid()) {
            packet.clear();
            throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        const bool quic = sniff::InspectQuicLongHeader(packet.FrontSpan()).has_value() ||
            (!packet.FrontSpan().empty() &&
             (packet.FrontSpan()[0] & 0xc0) == 0x40);
        auto resolved = state->Resolve(*datagram.target, packet.FrontSpan());
        if (!resolved.flow) {
            state->Reject(
                *datagram.target,
                resolved.error == common::ErrorCode::RESOURCE_EXHAUSTED
                    ? "UDP route flow capacity" : "ambiguous UDP route flow",
                quic);
            packet.clear();
            return;
        }
        if (!resolved.flow->Push(std::move(packet))) {
            state->Reject(
                *datagram.target, "UDP route flow queue full", quic);
            return;
        }
        if (resolved.created) spawn_flow(resolved.flow);
    };

    try {
        if (!initial.empty() || initial.HasUDP()) process(std::move(initial));
        for (;;) {
            auto packet = co_await parent_link.reader->ReadMultiBuffer();
            if (packet.empty() && !packet.HasUDP()) break;
            process(std::move(packet));
            if (state->Failure() != common::ErrorCode::OK) {
                throw transport::LinkError(state->Failure());
            }
        }
    } catch (...) {
        failure = std::current_exception();
    }

    try {
        if (failure) {
            state->CloseAll(transport::ClassifyFailure(
                failure, common::ErrorCode::SOCKET_READ_FAILED));
            co_await children.AsyncJoin();
        } else {
            state->FinishInputs();
            co_await children.AsyncDrain();
        }
    } catch (...) {
        if (!failure) failure = std::current_exception();
    }
    state->Deactivate();

    if (failure) std::rethrow_exception(failure);
    result = state->Aggregate();
    result.error = cancellation_reason;
    co_return;
}

}  // namespace app
