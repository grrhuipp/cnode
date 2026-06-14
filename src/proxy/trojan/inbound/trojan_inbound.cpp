#include "acppnode/proxy/trojan/inbound/trojan_inbound.hpp"
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
        if (queue_.empty()) {
            TryShrinkSequence(queue_);
        }
        return true;
    }

private:
    buf::BufferGuard pending_;
    memory::ThreadLocalDeque<FramedUdpPacket> queue_;

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
        trojan::TrojanCodec::UdpParseOutput output;
        output.result = trojan::TrojanCodec::UdpParseResult::INCOMPLETE;
        output.consumed = 0;

        if (len < 8) {
            output.error_reason = "buffer too short (< 8 bytes)";
            return output;
        }

        ByteReader reader(data, len);
        trojan::TrojanCodec::UdpPacket pkt;

        auto read_socks_address = [&](uint8_t atype) -> std::optional<TargetAddress> {
            if (atype == 0x01) {
                auto ipv4_bytes = reader.ReadBytes(4);
                uint16_t port = reader.ReadU16BE();
                if (!reader.Ok()) return std::nullopt;

                net::ip::address_v4::bytes_type bytes{};
                std::memcpy(bytes.data(), ipv4_bytes.data(), bytes.size());
                return TargetAddress(net::ip::make_address_v4(bytes), port);
            }

            if (atype == 0x03) {
                uint8_t domain_len = reader.ReadU8();
                if (!reader.Ok()) return std::nullopt;
                if (domain_len == 0 || domain_len > 253) {
                    return std::nullopt;
                }

                std::string_view domain = reader.ReadStringView(domain_len);
                uint16_t port = reader.ReadU16BE();
                if (!reader.Ok()) return std::nullopt;
                return TargetAddress(domain, port);
            }

            if (atype == 0x04) {
                auto ipv6_bytes = reader.ReadBytes(16);
                uint16_t port = reader.ReadU16BE();
                if (!reader.Ok()) return std::nullopt;

                net::ip::address_v6::bytes_type bytes{};
                std::memcpy(bytes.data(), ipv6_bytes.data(), bytes.size());
                return TargetAddress(net::ip::make_address_v6(bytes), port);
            }

            return std::nullopt;
        };

        uint8_t atype = reader.ReadU8();
        if (atype == 0x03) {
            uint8_t domain_len = reader.ReadU8();
            if (!reader.Ok()) {
                output.error_reason = "incomplete domain length";
                return output;
            }

            if (domain_len == 0 || domain_len > 253) {
                output.result = trojan::TrojanCodec::UdpParseResult::INVALID;
                output.error_reason = "invalid domain length";
                return output;
            }

            std::string_view domain = reader.ReadStringView(domain_len);
            uint16_t port = reader.ReadU16BE();
            if (!reader.Ok()) {
                output.error_reason = std::format("incomplete domain: need {} bytes", domain_len);
                return output;
            }

            pkt.target = TargetAddress(domain, port);
        } else if (atype == 0x01 || atype == 0x04) {
            auto target = read_socks_address(atype);
            if (!target) {
                output.error_reason = atype == 0x01
                    ? "incomplete IPv4 address"
                    : "incomplete IPv6 address";
                return output;
            }
            pkt.target = std::move(*target);
        } else {
            output.result = trojan::TrojanCodec::UdpParseResult::INVALID;
            output.error_reason = std::format("invalid atype: 0x{:02x}", atype);
            return output;
        }

        uint16_t payload_len = reader.ReadU16BE();
        if (!reader.Ok()) {
            output.error_reason = "incomplete payload length";
            return output;
        }

        uint8_t cr = reader.ReadU8();
        uint8_t lf = reader.ReadU8();
        if (!reader.Ok()) {
            output.error_reason = "incomplete CRLF";
            return output;
        }

        if (cr != 0x0D || lf != 0x0A) {
            output.result = trojan::TrojanCodec::UdpParseResult::INVALID;
            output.error_reason = std::format(
                "CRLF mismatch: expected 0x0D 0x0A, got 0x{:02x} 0x{:02x}",
                cr, lf);
            return output;
        }

        auto payload_span = reader.ReadBytes(payload_len);
        if (!reader.Ok()) {
            output.error_reason = std::format(
                "incomplete payload: need {} bytes, have {}",
                payload_len, reader.Remaining());
            return output;
        }

        pkt.payload = payload_span;
        output.result = trojan::TrojanCodec::UdpParseResult::SUCCESS;
        output.packet = std::move(pkt);
        output.consumed = reader.Position();
        return output;
    }

    void Parse() {
        while (Size() > 0) {
            auto result = DecodePacket(Data(), Size());
            if (result.result == trojan::TrojanCodec::UdpParseResult::SUCCESS) {
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
// 把 TCP 隧道上的 Trojan UDP 帧解析/封装为携带逐包目标(buffer.udp)的 MultiBuffer，
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
            if (!out.empty()) {
                co_return out;
            }
            buf::MultiBuffer raw = co_await src_.ReadMultiBuffer();
            if (raw.empty()) {
                co_return buf::MultiBuffer{};
            }
            for (buf::Buffer* rb : raw) {
                if (rb && !rb->IsEmpty()) {
                    framer_.Feed(rb->Bytes().data(), rb->Len());
                }
            }
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
        for (buf::Buffer* b : mb) {
            if (!b || b->IsEmpty() || !b->HasUDP()) {
                continue;
            }
            buf::Buffer* enc = buf::Buffer::New();
            if (!enc) {
                break;
            }
            const size_t n = trojan::TrojanCodec::EncodeUdpPacketTo(
                b->udp, b->Bytes().data(), b->Len(),
                enc->Tail().data(), enc->Available());
            if (n == 0) {
                buf::Buffer::Free(enc);
                continue;
            }
            enc->Produce(static_cast<uint32_t>(n));
            out.push_back(enc);
        }
        if (!out.empty()) {
            co_await dst_.WriteMultiBuffer(std::move(out));
        }
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
    ::acpp::trojan::Validator& user_manager,
    StatsShard& stats,
    ConnectionLimiterPtr limiter)
    : user_manager_(user_manager)
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

    LOG_CONN_DEBUG(ctx, "[Trojan][{}] Process start from {}", tag, client_ip);

    if (limiter_ && limiter_->GetLimiter().IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_ACCESS_FMT("{} from {}:{} rejected ip_banned [{}]",
            FormatTimestamp(ctx.accept_time_us),
            ctx.inbound.source_ip, ctx.inbound.source_port, ctx.inbound.tag);
        co_return fail(ErrorCode::BLOCKED);
    }
    std::optional<TrojanOnlineSession> user_session;

    buf::BufferGuard handshake_guard{buf::Buffer::New()};
    if (!handshake_guard) {
        co_return fail(ErrorCode::RESOURCE_EXHAUSTED);
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
    if (!read_result) co_return fail(read_result.error());
    const size_t total_read = *read_result;

    size_t consumed = 0;
    auto request = ::acpp::trojan::TrojanCodec::ParseRequest(
        handshake_buf, total_read, consumed);

    if (!request) {
        LOG_CONN_FAIL("[{}] Trojan parse failed from {}", tag, client_ip);
        co_return fail(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (!user_manager_.Validate(tag, request->password_hash)) {
        LOG_CONN_FAIL("[{}] Trojan auth failed from {} hash={}...{} store_size={} tag_size={}",
                      tag, client_ip,
                      request->password_hash.substr(0, 8),
                      request->password_hash.substr(request->password_hash.size() > 8 ? request->password_hash.size() - 4 : 0),
                      user_manager_.Size(),
                      user_manager_.SizeForTag(tag));
        if (limiter_ && ban_tracking_enabled_) {
            limiter_->OnAuthFailTracked(tag, client_ip);
        }
        stats_->OnError();
        co_return fail(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    auto user_info = user_manager_.FindUser(tag, request->password_hash);
    uint64_t tracked_uid = 0;
    if (user_info) {
        ctx.inbound.user_id = user_info->user_id;
        ctx.inbound.user_email = user_info->email;
        ctx.content.speed_limit = user_info->speed_limit;
        tracked_uid = static_cast<uint64_t>(user_info->user_id);
        if (!user_manager_.CanAcceptDevice(
                tag, tracked_uid, ctx.inbound.source_ip, user_info->device_limit)) {
            LOG_ACCESS_FMT("{} from {}:{} rejected device_limit [{}] user={} limit={} online_devices={}",
                FormatTimestamp(ctx.accept_time_us),
                ctx.inbound.source_ip, ctx.inbound.source_port, tag, ctx.inbound.user_email,
                user_info->device_limit,
                user_manager_.OnlineDeviceCount(tag, tracked_uid));
            co_return fail(ErrorCode::RESOURCE_EXHAUSTED);
        }
    }

    // 在线追踪：认证成功后由当前协议 Process 的本地 guard 解注册。
    user_manager_.OnUserConnected(tag, tracked_uid, ctx.inbound.source_ip);
    user_session.emplace(user_manager_, tag, tracked_uid, ctx.inbound.source_ip);

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
        // 目标(buffer.udp)的 Link；relay 协议无关。reader/writer 是本协程局部对象，
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

    reg.create_tcp_handler =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::proxyman::inbound::BuildRequest& req) -> std::unique_ptr<acpp::Inbound> {
            if (!deps.validator || !deps.stats) {
                return nullptr;
            }
            return std::make_unique<acpp::proxy::trojan::inbound::Handler>(
                *deps.validator,
                *deps.stats,
                limiter);
        };

    reg.build_static_users =
        [](std::string_view /*tag*/, const acpp::StaticUserConfig& config)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::trojan::TrojanUserInfo> users;

            for (const auto& client : config.clients) {
                if (client.password.empty()) {
                    continue;
                }
                acpp::trojan::TrojanUserInfo info;
                info.password_hash = acpp::trojan::HashPassword(client.password);
                info.email = client.email;
                users.push_back(std::move(info));
            }

            acpp::proxyman::inbound::UserSet result;
            result.trojan_users = std::move(users);
            return result;
        };

    reg.apply_worker_users =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           std::string_view tag,
           const acpp::proxyman::inbound::UserSet& users) {
            if (!deps.validator) return;
            deps.validator->UpdateUsersForTag(
                std::string(tag), users.trojan_users);
        };

    reg.add_worker_users =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           std::string_view tag,
           const acpp::proxyman::inbound::UserSet& users) {
            if (!deps.validator) return;
            deps.validator->AddUsersForTag(
                std::string(tag), users.trojan_users);
        };

    reg.remove_worker_users =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           std::string_view tag,
           const acpp::proxyman::inbound::UserSet& users) {
            if (!deps.validator) return;
            deps.validator->RemoveUsersForTag(
                std::string(tag), users.trojan_users);
        };

    reg.clear_worker_users = [](const acpp::proxyman::inbound::ProtocolDeps& deps, std::string_view tag) {
        if (deps.validator) {
            deps.validator->UpdateUsersForTag(std::string(tag), {});
        }
    };

    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kTrojan, std::move(reg));
    return true;
}();
}  // namespace
