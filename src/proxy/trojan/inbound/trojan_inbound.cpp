#include "trojan_inbound.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "../trojan_codec.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/initial_payload.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/byte_reader.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/app/udp_types.hpp"
#include <span>
#include <cstring>
#include <algorithm>
#include <format>

#include <expected>
#include <optional>
#include <utility>

namespace acpp {

namespace {

constexpr size_t kUdpFrameQueueShrinkItems = 64;

class TrojanOnlineSession {
public:
    TrojanOnlineSession(::acpp::trojan::Validator& manager,
                        std::string_view tag,
                        uint64_t user_id,
                        std::string_view client_ip)
        : manager_(&manager)
        , tag_(tag)
        , user_id_(user_id)
        , client_ip_(client_ip) {}

    ~TrojanOnlineSession() noexcept {
        if (!manager_ || user_id_ == 0) {
            return;
        }
        try {
            manager_->OnUserDisconnected(tag_, user_id_, client_ip_);
        } catch (...) {
        }
    }

    TrojanOnlineSession(const TrojanOnlineSession&) = delete;
    TrojanOnlineSession& operator=(const TrojanOnlineSession&) = delete;
    TrojanOnlineSession(TrojanOnlineSession&&) = delete;
    TrojanOnlineSession& operator=(TrojanOnlineSession&&) = delete;

private:
    ::acpp::trojan::Validator* manager_;
    memory::ThreadLocalString tag_;
    uint64_t user_id_;
    memory::ThreadLocalString client_ip_;
};


class TrojanUdpFramer {
public:
    void Feed(const uint8_t* data, size_t len) {
        while (len > 0) {
            if (!pending_) {
                pending_ = buf::BufferGuard{buf::Buffer::New()};
                if (!pending_) {
                    return;
                }
            }

            if (pending_->Available() == 0 && pending_->start > 0) {
                Compact();
            }
            if (pending_->Available() == 0) {
                ClearBuffer();
                return;
            }

            const size_t n = std::min<size_t>(len, pending_->Available());
            std::memcpy(pending_->Tail().data(), data, n);
            pending_->Produce(static_cast<uint32_t>(n));
            data += n;
            len -= n;

            Parse();
        }
    }

    struct FramedUdpPacket {
        TargetAddress target;
        buf::BufferGuard payload;
    };

    bool Next(FramedUdpPacket& out) {
        if (queue_.empty()) {
            return false;
        }
        out = std::move(queue_.front());
        queue_.pop_front();
        if (queue_.empty() && shrink_queue_on_drain_) {
            TryShrinkSequence(queue_);
            shrink_queue_on_drain_ = false;
        }
        return true;
    }

private:
    buf::BufferGuard pending_;
    memory::ThreadLocalDeque<FramedUdpPacket> queue_;
    bool shrink_queue_on_drain_ = false;

    void Compact() {
        if (!pending_ || pending_->start == 0) {
            return;
        }
        const uint32_t remaining = pending_->Len();
        if (remaining == 0) {
            ClearBuffer();
            return;
        }

        std::memmove(pending_->data, pending_->Bytes().data(), remaining);
        pending_->start = 0;
        pending_->end = remaining;
    }

    const uint8_t* Data() const {
        return pending_ ? pending_->Bytes().data() : nullptr;
    }

    size_t Size() const {
        return pending_ ? pending_->Len() : 0;
    }

    void ClearBuffer() {
        pending_ = buf::BufferGuard{};
    }

    static trojan::TrojanCodec::UdpParseOutput DecodePacket(
        const uint8_t* data, size_t len) {
        return trojan::TrojanCodec::ParseUdpPacket(data, len);
    }

    [[nodiscard]] bool TryTakePacket(const TargetAddress& target,
                                     std::span<const uint8_t> payload) {
        buf::BufferGuard taken;
        if (!buf::TakeBufferSuffix(pending_, payload, taken)) {
            return false;
        }

        FramedUdpPacket pkt;
        pkt.target = target;
        pkt.payload = std::move(taken);
        queue_.push_back(std::move(pkt));
        if (queue_.size() >= kUdpFrameQueueShrinkItems) {
            shrink_queue_on_drain_ = true;
        }
        return true;
    }

    void Parse() {
        while (Size() > 0) {
            auto result = DecodePacket(Data(), Size());
            if (result.result == trojan::TrojanCodec::UdpParseResult::SUCCESS) {
                if (result.packet &&
                    TryTakePacket(result.packet->target, result.packet->payload)) {
                    continue;
                }
                FramedUdpPacket pkt;
                pkt.target = result.packet->target;
                pkt.payload = buf::BufferGuard{buf::Buffer::New()};
                if (pkt.payload) {
                    const auto payload = result.packet->payload;
                    const size_t n = std::min<size_t>(
                        payload.size(),
                        static_cast<size_t>(pkt.payload->Available()));
                    std::memcpy(pkt.payload->Tail().data(), payload.data(), n);
                    pkt.payload->Produce(static_cast<uint32_t>(n));
                    queue_.push_back(std::move(pkt));
                    if (queue_.size() >= kUdpFrameQueueShrinkItems) {
                        shrink_queue_on_drain_ = true;
                    }
                }
                pending_->Advance(static_cast<uint32_t>(result.consumed));
            } else if (result.result == trojan::TrojanCodec::UdpParseResult::INCOMPLETE) {
                break;
            } else {
                pending_->Advance(1);
                if (Size() < 8) {
                    ClearBuffer();
                    break;
                }
            }
        }

        if (pending_ && pending_->IsEmpty()) {
            ClearBuffer();
        }
    }
};


// ============================================================================
// Trojan UDP reader/writer helper
//
// 把 TCP 隧道上的 Trojan UDP 帧解析/封装为携带逐包目标的 MultiBuffer，
// 供 dispatcher.Dispatch -> outbound.Process -> DoUDPRelayLink 以协议无关方式中继。
// 对齐 xray-core 把 UDP 封帧放在入站 reader/writer，而非 relay 内部。
// ============================================================================
class TrojanUdpReader final : public transport::MultiBufferReader {
public:
    TrojanUdpReader(AsyncStream& src, std::span<const uint8_t> first_packet)
        : src_(src) {
        if (!first_packet.empty()) {
            framer_.Feed(first_packet.data(), first_packet.size());
        }
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (true) {
            buf::MultiBuffer out;
            TrojanUdpFramer::FramedUdpPacket pkt;
            while (framer_.Next(pkt)) {
                if (!pkt.payload || pkt.payload->IsEmpty()) {
                    continue;
                }
                pkt.payload->SetUDP(std::move(pkt.target));
                out.push_back(pkt.payload.release());
            }
            if (buf::HasData(out)) {
                co_return out;
            }
            buf::MultiBuffer raw = co_await src_.ReadMultiBuffer();
            if (!buf::HasData(raw)) {
                co_return buf::MultiBuffer{};
            }
            for (buf::Buffer* rb : raw) {
                if (rb && !rb->IsEmpty()) {
                    framer_.Feed(rb->Bytes().data(), rb->Len());
                }
            }
            raw.clear();
        }
    }

private:
    AsyncStream& src_;
    TrojanUdpFramer framer_;
};

class TrojanUdpWriter final : public transport::MultiBufferWriter {
public:
    explicit TrojanUdpWriter(AsyncStream& dst) : dst_(dst) {}

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        buf::MultiBuffer out;
        for (buf::Buffer*& b : mb) {
            if (!b || b->IsEmpty() || !b->HasUDP()) {
                mb.FreeSlot(b);
                continue;
            }
            buf::BufferGuard header{buf::Buffer::New()};
            if (!header) {
                throw std::bad_alloc();
            }
            const size_t n = trojan::TrojanCodec::EncodeUdpPacketHeaderTo(
                b->UDP(), b->Len(),
                header->Tail().data(), header->Available());
            if (n == 0) {
                mb.FreeSlot(b);
                continue;
            }
            header->Produce(static_cast<uint32_t>(n));
            out.push_back(header.release());
            b->ClearUDP();
            out.push_back(mb.ReleaseSlot(b));
        }
        mb.clear();
        if (buf::HasData(out)) {
            co_await dst_.WriteMultiBuffer(std::move(out));
        }
        co_return;
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer>) override {
        co_return;
    }

private:
    AsyncStream& dst_;
};

}  // namespace

// ============================================================================
// proxy/trojan/inbound.Handler 实现（代理层，无传输层知识）
// ============================================================================

proxy::trojan::inbound::Handler::Handler(
    ::acpp::trojan::Validator& validator,
    StatsShard& stats,
    ConnectionLimiterPtr limiter)
    : validator_(validator)
    , stats_(&stats)
    , limiter_(std::move(limiter))
{}

net::awaitable<RelayResult>
proxy::trojan::inbound::Handler::Process(
    std::unique_ptr<AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    net::io_context& io_context,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout)
{
    const std::string_view tag   = ctx.inbound.tag;
    const std::string_view client_ip = ctx.inbound.source_ip;
    auto fail = [&](ErrorCode error) {
        stats_->OnError();
        RelayResult result;
        result.error = error;
        return result;
    };
    auto fail_abortive = [&](ErrorCode error) {
        if (stream) {
            stream->CloseAbortive();
        }
        return fail(error);
    };

    LOG_CONN_DEBUG(ctx, "[Trojan][{}] Process start from {}", tag, client_ip);

    if (limiter_ && limiter_->GetLimiter().IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_ACCESS_FMT("{} from {}:{} rejected ip_banned [{}]",
            FormatTimestamp(ctx.accept_time_us),
            ctx.inbound.source_ip, ctx.inbound.source_port, ctx.inbound.tag);
        co_return fail_abortive(ErrorCode::BLOCKED);
    }
    std::optional<TrojanOnlineSession> user_session;

    buf::BufferGuard handshake_guard{buf::Buffer::New()};
    if (!handshake_guard) {
        co_return fail_abortive(ErrorCode::RESOURCE_EXHAUSTED);
    }
    uint8_t* handshake_buf = handshake_guard->Tail().data();
    const size_t handshake_capacity = handshake_guard->Available();
    auto read_handshake = [&]() -> net::awaitable<std::expected<size_t, ErrorCode>> {
        size_t n = 0;
        try {
            n = co_await stream->AsyncRead(net::buffer(handshake_buf, handshake_capacity));
        } catch (const IoSystemError&) {
            if (stream->ConsumePhaseDeadline()) {
                LOG_CONN_FAIL_CTX(ctx, "[Trojan][{}] handshake phase deadline from {}",
                                  ctx.inbound.tag, ctx.inbound.source_ip);
                co_return std::unexpected(ErrorCode::TIMEOUT);
            }
            LOG_CONN_FAIL_CTX(ctx, "[Trojan][{}] handshake read failed from {}",
                              ctx.inbound.tag, ctx.inbound.source_ip);
            co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
        }
        if (n == 0 && stream->ConsumePhaseDeadline()) {
            LOG_CONN_FAIL_CTX(ctx, "[Trojan][{}] handshake phase deadline from {}",
                              ctx.inbound.tag, ctx.inbound.source_ip);
            co_return std::unexpected(ErrorCode::TIMEOUT);
        }
        if (n == 0 && stream->ConsumeIdleTimeout()) {
            LOG_CONN_FAIL_CTX(ctx, "[Trojan][{}] handshake idle timeout from {}",
                              ctx.inbound.tag, ctx.inbound.source_ip);
            co_return std::unexpected(ErrorCode::TIMEOUT);
        }
        if (n == 0) co_return std::unexpected(ErrorCode::SOCKET_EOF);
        co_return n;
    };
    auto read_result = co_await read_handshake();
    if (!read_result) co_return fail_abortive(read_result.error());
    const size_t total_read = *read_result;

    size_t consumed = 0;
    auto request = ::acpp::trojan::TrojanCodec::ParseRequest(
        handshake_buf, total_read, consumed);

    if (!request) {
        LOG_CONN_FAIL("[{}] Trojan parse failed from {}", tag, client_ip);
        co_return fail_abortive(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    auto user_info = validator_.FindUser(tag, request->password_hash);
    if (!user_info) {
        LOG_CONN_FAIL("[{}] Trojan auth failed from {} hash={}...{} store_size={} tag_size={}",
                      tag, client_ip,
                      request->password_hash.substr(0, 8),
                      request->password_hash.substr(request->password_hash.size() > 8 ? request->password_hash.size() - 4 : 0),
                      validator_.Size(),
                      validator_.SizeForTag(tag));
        if (limiter_) {
            limiter_->OnAuthFailTracked(tag, client_ip);
        }
        co_return fail_abortive(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    uint64_t tracked_uid = 0;
    if (user_info->profile) {
        const auto& profile = *user_info->profile;
        ctx.inbound.user_id = profile.user_id;
        ctx.inbound.user_email = profile.email;
        ctx.content.speed_limit = profile.speed_limit;
        tracked_uid = static_cast<uint64_t>(profile.user_id);
        if (!validator_.CanAcceptDevice(
                tag, tracked_uid, ctx.inbound.source_ip, profile.device_limit)) {
            LOG_ACCESS_FMT("{} from {}:{} rejected device_limit [{}] user={} limit={} online_devices={}",
                FormatTimestamp(ctx.accept_time_us),
                ctx.inbound.source_ip, ctx.inbound.source_port, tag, ctx.inbound.user_email,
                profile.device_limit,
                validator_.OnlineDeviceCount(tag, tracked_uid));
            co_return fail_abortive(ErrorCode::RESOURCE_EXHAUSTED);
        }
    }

    // 在线追踪：认证成功后由当前协议 Process 的本地 guard 解注册。
    validator_.OnUserConnected(tag, tracked_uid, ctx.inbound.source_ip);
    user_session.emplace(validator_, tag, tracked_uid, ctx.inbound.source_ip);

    LOG_CONN_DEBUG(ctx, "[Trojan][{}] auth ok: {} -> {} user={}",
                   tag, client_ip, request->target, ctx.inbound.user_email);

    Network net = (request->command == ::acpp::trojan::TrojanCommand::UDP_ASSOCIATE)
                  ? Network::UDP : Network::TCP;

    ctx.outbound.original_target = request->target;
    ctx.outbound.target = std::move(request->target);
    ctx.content.network = net;

    std::span<const uint8_t> leftover;
    if (consumed < total_read) {
        leftover = std::span<const uint8_t>(handshake_buf + consumed,
                                            total_read - consumed);
    }

    if (net == Network::UDP) {
        // UDP：封帧下沉到入站 reader/writer helper，dispatcher 拿到的是携带逐包
        // 目标的 Link；relay 协议无关。reader/writer 是本协程局部对象，
        // 在 co_await Dispatch 期间有效；stream 被 Dispatch 接管但堆对象稳定，
        // 引用持续有效。首帧 leftover 在构造时喂入 reader 的 framer。
        TrojanUdpReader udp_reader(*stream, leftover);
        TrojanUdpWriter udp_writer(*stream);
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver,
            std::move(stream),
            transport::Link{&udp_reader, &udp_writer},
            InitialPayload{},
            ctx,
            *stats_,
            timeouts,
            pressure_idle_timeout);
    }

    InitialPayload first_packet;
    if (!leftover.empty()) {
        first_packet.assign(leftover.begin(), leftover.end());
    }

    auto* tcp_stream = stream.get();
    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver,
        std::move(stream),
        transport::Link{tcp_stream, tcp_stream},
        std::move(first_packet),
        ctx,
        *stats_,
        timeouts,
        pressure_idle_timeout);
}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
const bool kTrojanInboundRegistered = [] {
    acpp::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = acpp::proxyman::inbound::UserProtocol::Trojan;

    reg.create_runtime = []() -> std::unique_ptr<
        acpp::proxyman::inbound::ProtocolRuntime> {
        return std::make_unique<acpp::proxyman::inbound::ValidatorProtocolRuntime<
            acpp::trojan::Validator>>();
    };

    reg.create_tcp_handler =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::proxyman::inbound::BuildRequest& req) -> std::unique_ptr<acpp::Inbound> {
            auto* validator = deps.ValidatorAs<acpp::trojan::Validator>();
            if (!validator || !deps.stats) {
                return nullptr;
            }
            return std::make_unique<acpp::proxy::trojan::inbound::Handler>(
                *validator,
                *deps.stats,
                limiter);
        };

    reg.build_static_users =
        [](std::string_view tag, const acpp::StaticUserConfig& config)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::proxyman::inbound::PreparedTrojanUser> users;

            for (const auto& client : config.clients) {
                if (client.password.empty()) {
                    LOG_WARN("Trojan inbound '{}': static user password is empty", tag);
                    return std::nullopt;
                }
                acpp::proxyman::inbound::PreparedTrojanUser info;
                info.password_hash = acpp::trojan::HashPassword(client.password);
                info.profile.email = client.email;
                users.push_back(std::move(info));
            }

            return acpp::proxyman::inbound::UserSet{std::move(users)};
        };

    reg.build_users =
        [](const acpp::proxyman::inbound::BuildRequest& /*req*/,
           std::span<const acpp::proxyman::inbound::RuntimeUser> runtime_users)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::proxyman::inbound::PreparedTrojanUser> users;
            users.reserve(runtime_users.size());

            for (const auto& runtime_user : runtime_users) {
                if (runtime_user.password.empty()) {
                    continue;
                }
                acpp::proxyman::inbound::PreparedTrojanUser info;
                info.password_hash = acpp::trojan::HashPassword(runtime_user.password);
                info.profile.email = runtime_user.email;
                info.profile.user_id = runtime_user.user_id;
                info.profile.speed_limit = runtime_user.speed_limit;
                info.profile.device_limit = runtime_user.device_limit;
                users.push_back(std::move(info));
            }

            return acpp::proxyman::inbound::UserSet{std::move(users)};
        };

    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kTrojan, std::move(reg));
    return true;
}();
}  // namespace
