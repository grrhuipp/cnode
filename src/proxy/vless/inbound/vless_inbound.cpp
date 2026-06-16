#include "acppnode/proxy/vless/inbound/vless_inbound.hpp"

#include "../vless_codec.hpp"
#include "../vless_encryption.hpp"
#include "../vless_vision.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/udp_types.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/initial_payload.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <utility>

namespace acpp {

namespace {

constexpr std::string_view kPacketAddrMagicAddress =
    "sp.packet-addr.v2fly.arpa";

bool IsPacketAddrMagic(const TargetAddress& target) {
    return target.IsDomain() && target.host == kPacketAddrMagicAddress;
}

size_t EncodePacketAddrHeaderTo(const TargetAddress& target,
                                uint8_t* out,
                                size_t cap) {
    if (!target.resolved_addr) {
        return 0;
    }
    if (target.resolved_addr->is_v4()) {
        if (cap < 7) return 0;
        out[0] = 0x01;
        const auto bytes = target.resolved_addr->to_v4().to_bytes();
        std::memcpy(out + 1, bytes.data(), bytes.size());
        out[5] = static_cast<uint8_t>((target.port >> 8) & 0xff);
        out[6] = static_cast<uint8_t>(target.port & 0xff);
        return 7;
    }
    if (target.resolved_addr->is_v6()) {
        if (cap < 19) return 0;
        out[0] = 0x02;
        const auto bytes = target.resolved_addr->to_v6().to_bytes();
        std::memcpy(out + 1, bytes.data(), bytes.size());
        out[17] = static_cast<uint8_t>((target.port >> 8) & 0xff);
        out[18] = static_cast<uint8_t>(target.port & 0xff);
        return 19;
    }
    return 0;
}

struct PacketAddrHeader {
    TargetAddress target;
    size_t consumed = 0;
};

std::optional<PacketAddrHeader> DecodePacketAddrHeader(std::span<const uint8_t> data) {
    if (data.empty()) {
        return std::nullopt;
    }
    if (data[0] == 0x01) {
        if (data.size() < 7) return std::nullopt;
        net::ip::address_v4::bytes_type bytes{};
        std::memcpy(bytes.data(), data.data() + 1, bytes.size());
        const uint16_t port =
            (static_cast<uint16_t>(data[5]) << 8) |
            static_cast<uint16_t>(data[6]);
        return PacketAddrHeader{
            TargetAddress(net::ip::make_address_v4(bytes), port),
            7,
        };
    }
    if (data[0] == 0x02) {
        if (data.size() < 19) return std::nullopt;
        net::ip::address_v6::bytes_type bytes{};
        std::memcpy(bytes.data(), data.data() + 1, bytes.size());
        const uint16_t port =
            (static_cast<uint16_t>(data[17]) << 8) |
            static_cast<uint16_t>(data[18]);
        return PacketAddrHeader{
            TargetAddress(net::ip::make_address_v6(bytes), port),
            19,
        };
    }
    return std::nullopt;
}

bool EncodePacketAddrUdpPacketTo(const TargetAddress& target,
                                 std::span<const uint8_t> payload,
                                 buf::Buffer& out) {
    std::array<uint8_t, 19> addr{};
    const size_t addr_len = EncodePacketAddrHeaderTo(target, addr.data(), addr.size());
    if (addr_len == 0) {
        return false;
    }
    const size_t packet_len = addr_len + payload.size();
    if (packet_len == 0 || packet_len > 0xffff || out.Available() < packet_len + 2) {
        return false;
    }
    auto tail = out.Tail();
    tail[0] = static_cast<uint8_t>((packet_len >> 8) & 0xff);
    tail[1] = static_cast<uint8_t>(packet_len & 0xff);
    std::memcpy(tail.data() + 2, addr.data(), addr_len);
    std::memcpy(tail.data() + 2 + addr_len, payload.data(), payload.size());
    out.Produce(static_cast<uint32_t>(packet_len + 2));
    return true;
}

class VlessOnlineSession {
public:
    VlessOnlineSession(::acpp::vless::Validator& manager,
                       std::string_view tag,
                       uint64_t user_id,
                       std::string_view client_ip)
        : manager_(&manager)
        , tag_(tag)
        , user_id_(user_id)
        , client_ip_(client_ip) {}

    ~VlessOnlineSession() noexcept {
        if (!manager_ || user_id_ == 0) {
            return;
        }
        try {
            manager_->OnUserDisconnected(tag_, user_id_, client_ip_);
        } catch (...) {
        }
    }

    VlessOnlineSession(const VlessOnlineSession&) = delete;
    VlessOnlineSession& operator=(const VlessOnlineSession&) = delete;
    VlessOnlineSession(VlessOnlineSession&&) = delete;
    VlessOnlineSession& operator=(VlessOnlineSession&&) = delete;

private:
    ::acpp::vless::Validator* manager_;
    memory::ThreadLocalString tag_;
    uint64_t user_id_ = 0;
    memory::ThreadLocalString client_ip_;
};

net::awaitable<bool> WriteFull(AsyncStream& stream,
                               const uint8_t* data,
                               size_t len) {
    size_t offset = 0;
    while (offset < len) {
        size_t written = 0;
        try {
            written = co_await stream.AsyncWrite(net::buffer(data + offset, len - offset));
        } catch (...) {
            co_return false;
        }
        if (written == 0) {
            co_return false;
        }
        offset += written;
    }
    co_return true;
}

class VlessPendingReader final : public transport::MultiBufferReader {
public:
    VlessPendingReader(AsyncStream& src, std::span<const uint8_t> first_packet)
        : src_(src) {
        (void)buf::AppendSpanToMultiBuffer(first_packet, pending_);
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (pending_.empty()) {
            co_return co_await src_.ReadMultiBuffer();
        }

        co_return std::move(pending_);
    }

private:
    AsyncStream& src_;
    buf::MultiBuffer pending_;
};

class VlessUdpFramer {
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

    bool Next(buf::BufferGuard& out) {
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
    memory::ThreadLocalDeque<buf::BufferGuard> queue_;

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

    void Parse() {
        while (Size() > 0) {
            auto parsed = vless::Codec::ParseUdpPacket(Data(), Size());
            if (parsed.result == vless::Codec::UdpParseResult::SUCCESS) {
                buf::BufferGuard payload{buf::Buffer::New()};
                if (payload && parsed.packet) {
                    const auto bytes = parsed.packet->payload;
                    const size_t n = std::min<size_t>(
                        bytes.size(),
                        static_cast<size_t>(payload->Available()));
                    std::memcpy(payload->Tail().data(), bytes.data(), n);
                    payload->Produce(static_cast<uint32_t>(n));
                    queue_.push_back(std::move(payload));
                }
                pending_->Advance(static_cast<uint32_t>(parsed.consumed));
                continue;
            }
            if (parsed.result == vless::Codec::UdpParseResult::INCOMPLETE) {
                break;
            }
            pending_->Advance(1);
            if (Size() < 2) {
                ClearBuffer();
                break;
            }
        }

        if (pending_ && pending_->IsEmpty()) {
            ClearBuffer();
        }
    }
};

class VlessUdpReader final : public transport::MultiBufferReader {
public:
    VlessUdpReader(AsyncStream& src,
                   TargetAddress target,
                   std::span<const uint8_t> first_packet,
                   bool packet_addr = false)
        : src_(src)
        , target_(std::move(target))
        , packet_addr_(packet_addr) {
        if (!first_packet.empty()) {
            framer_.Feed(first_packet.data(), first_packet.size());
        }
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (true) {
            buf::MultiBuffer out;
            buf::BufferGuard pkt;
            while (framer_.Next(pkt)) {
                if (!pkt || pkt->IsEmpty()) {
                    continue;
                }
                if (packet_addr_) {
                    auto header = DecodePacketAddrHeader(pkt->Bytes());
                    if (!header || header->consumed >= pkt->Len()) {
                        continue;
                    }
                    pkt->Advance(static_cast<uint32_t>(header->consumed));
                    pkt->SetUDP(std::move(header->target));
                } else {
                    pkt->SetUDP(target_);
                }
                out.push_back(pkt.release());
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
            raw.clear();
        }
    }

private:
    AsyncStream& src_;
    TargetAddress target_;
    bool packet_addr_ = false;
    VlessUdpFramer framer_;
};

class VlessUdpWriter final : public transport::MultiBufferWriter {
public:
    explicit VlessUdpWriter(AsyncStream& dst, bool packet_addr = false)
        : dst_(dst)
        , packet_addr_(packet_addr) {}

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        buf::MultiBuffer out;
        for (buf::Buffer* buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            buf::BufferGuard framed{buf::Buffer::New()};
            if (!framed) {
                break;
            }
            bool ok = false;
            if (packet_addr_) {
                if (!buffer->HasUDP()) {
                    continue;
                }
                ok = EncodePacketAddrUdpPacketTo(buffer->UDP(), buffer->Bytes(), *framed);
            } else {
                const size_t written = vless::Codec::EncodeUdpPacketTo(
                    buffer->Bytes().data(),
                    buffer->Len(),
                    framed->Tail().data(),
                    framed->Available());
                if (written > 0) {
                    framed->Produce(static_cast<uint32_t>(written));
                    ok = true;
                }
            }
            if (!ok) {
                continue;
            }
            out.push_back(framed.release());
        }
        mb.clear();
        if (!out.empty()) {
            co_await dst_.WriteMultiBuffer(std::move(out));
        }
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        co_await dst_.AsyncShutdownWrite();
        co_return;
    }

private:
    AsyncStream& dst_;
    bool packet_addr_ = false;
};

}  // namespace

proxy::vless::inbound::Handler::Handler(
    ::acpp::vless::Validator& validator,
    StatsShard& stats,
    ConnectionLimiterPtr limiter)
    : validator_(validator)
    , stats_(&stats)
    , limiter_(std::move(limiter)) {}

net::awaitable<RelayResult>
proxy::vless::inbound::Handler::Process(
    std::unique_ptr<AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    net::io_context& io_context,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout) {
    const std::string_view tag = ctx.inbound.tag;
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

    if (limiter_ && limiter_->GetLimiter().IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_ACCESS_FMT("{} from {}:{} rejected ip_banned [{}]",
            FormatTimestamp(ctx.accept_time_us),
            ctx.inbound.source_ip, ctx.inbound.source_port, ctx.inbound.tag);
        co_return fail_abortive(ErrorCode::BLOCKED);
    }

    std::optional<VlessOnlineSession> user_session;
    std::array<uint8_t, 1024> handshake{};
    size_t total_read = 0;
    size_t consumed = 0;
    std::optional<::acpp::vless::RequestHeader> request;

    while (!request && total_read < handshake.size()) {
        size_t n = 0;
        try {
            n = co_await stream->AsyncRead(
                net::buffer(handshake.data() + total_read,
                            handshake.size() - total_read));
        } catch (const IoSystemError&) {
            if (stream->ConsumePhaseDeadline()) {
                LOG_CONN_FAIL_CTX(ctx, "[VLESS][{}] handshake phase deadline from {}",
                                  tag, client_ip);
                co_return fail_abortive(ErrorCode::TIMEOUT);
            }
            co_return fail_abortive(ErrorCode::SOCKET_READ_FAILED);
        }
        if (n == 0 && stream->ConsumePhaseDeadline()) {
            co_return fail_abortive(ErrorCode::TIMEOUT);
        }
        if (n == 0 && stream->ConsumeIdleTimeout()) {
            co_return fail_abortive(ErrorCode::TIMEOUT);
        }
        if (n == 0) {
            co_return fail_abortive(ErrorCode::SOCKET_EOF);
        }
        total_read += n;
        request = ::acpp::vless::Codec::ParseRequestHeader(
            handshake.data(),
            total_read,
            consumed);
        if (total_read >= 1 && handshake[0] != ::acpp::vless::kVersion) {
            co_return fail_abortive(ErrorCode::PROTOCOL_INVALID_VERSION);
        }
    }

    if (!request) {
        LOG_CONN_FAIL("[VLESS][{}] parse failed from {}", tag, client_ip);
        co_return fail_abortive(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    auto user_info = validator_.FindUser(tag, request->uuid);
    if (!user_info) {
        LOG_CONN_FAIL("[VLESS][{}] auth failed from {} store_size={} tag_size={}",
                      tag, client_ip, validator_.Size(), validator_.SizeForTag(tag));
        if (limiter_ && ban_tracking_enabled_) {
            limiter_->OnAuthFailTracked(tag, client_ip);
        }
        co_return fail_abortive(ErrorCode::PROTOCOL_AUTH_FAILED);
    }
    if (request->addons_len != 0 && request->flow.empty()) {
        LOG_CONN_FAIL("[VLESS][{}] unsupported request addons from {}", tag, client_ip);
        co_return fail_abortive(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    const bool use_vision = ::acpp::vless::IsVisionFlow(request->flow);
    if (!request->flow.empty()) {
        if (request->flow != user_info->flow) {
            LOG_CONN_FAIL("[VLESS][{}] request flow '{}' not allowed for user",
                          tag, request->flow);
            co_return fail_abortive(ErrorCode::PROTOCOL_UNSUPPORTED);
        }
        if (!use_vision) {
            LOG_CONN_FAIL("[VLESS][{}] unknown request flow '{}'", tag, request->flow);
            co_return fail_abortive(ErrorCode::PROTOCOL_UNSUPPORTED);
        }
    }
    if (!user_info->flow.empty() && !::acpp::vless::IsVisionFlow(user_info->flow)) {
        LOG_CONN_FAIL("[VLESS][{}] unsupported flow '{}'", tag, user_info->flow);
        co_return fail_abortive(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    if (request->flow.empty() && ::acpp::vless::IsVisionFlow(user_info->flow)) {
        LOG_CONN_FAIL("[VLESS][{}] missing required flow '{}'", tag, user_info->flow);
        co_return fail_abortive(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    if (use_vision && request->command != ::acpp::vless::Command::TCP) {
        LOG_CONN_FAIL("[VLESS][{}] flow '{}' only supports TCP", tag, request->flow);
        co_return fail_abortive(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    if (use_vision && !receiver.stream_settings.IsTls()) {
        LOG_CONN_FAIL("[VLESS][{}] flow '{}' requires TLS transport", tag, request->flow);
        co_return fail_abortive(ErrorCode::PROTOCOL_UNSUPPORTED);
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

    validator_.OnUserConnected(tag, tracked_uid, ctx.inbound.source_ip);
    user_session.emplace(validator_, tag, tracked_uid, ctx.inbound.source_ip);

    Network net = Network::TCP;
    if (request->command == ::acpp::vless::Command::UDP) {
        net = Network::UDP;
    } else if (request->command == ::acpp::vless::Command::MUX) {
        net = Network::MUX;
    }
    const bool packet_addr_udp =
        request->command == ::acpp::vless::Command::UDP &&
        IsPacketAddrMagic(request->target);
    ctx.outbound.original_target = request->target;
    ctx.outbound.target = std::move(request->target);
    ctx.content.network = net;

    uint8_t response_header[2]{};
    const size_t response_len =
        ::acpp::vless::Codec::EncodeResponseHeaderTo(response_header, sizeof(response_header));
    if (response_len == 0 ||
        !co_await WriteFull(*stream, response_header, response_len)) {
        co_return fail_abortive(ErrorCode::SOCKET_WRITE_FAILED);
    }

    std::span<const uint8_t> leftover;
    if (consumed < total_read) {
        leftover = std::span<const uint8_t>(
            handshake.data() + consumed,
            total_read - consumed);
    }

    if (net == Network::MUX) {
        auto* tcp_stream = stream.get();
        VlessPendingReader mux_reader(*tcp_stream, leftover);
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver,
            std::move(stream),
            transport::Link{&mux_reader, tcp_stream},
            InitialPayload{},
            ctx,
            *stats_,
            timeouts,
            pressure_idle_timeout);
    }

    if (net == Network::UDP) {
        VlessUdpReader udp_reader(
            *stream, ctx.outbound.target, leftover, packet_addr_udp);
        VlessUdpWriter udp_writer(*stream, packet_addr_udp);
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
    if (use_vision) {
        ::acpp::vless::VisionReader vision_reader(*tcp_stream, request->uuid, leftover);
        ::acpp::vless::VisionWriter vision_writer(*tcp_stream, request->uuid);
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver,
            std::move(stream),
            transport::Link{&vision_reader, &vision_writer},
            InitialPayload{},
            ctx,
            *stats_,
            timeouts,
            pressure_idle_timeout);
    }

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

namespace {
const bool kVlessInboundRegistered = [] {
    acpp::proxyman::inbound::ProxyRegistration reg;

    reg.create_tcp_handler =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::proxyman::inbound::BuildRequest& /*req*/)
            -> std::unique_ptr<acpp::Inbound> {
            auto* validator = deps.ValidatorAs<acpp::vless::Validator>();
            if (!validator || !deps.stats) {
                return nullptr;
            }
            return std::make_unique<acpp::proxy::vless::inbound::Handler>(
                *validator,
                *deps.stats,
                limiter);
        };

    reg.build_static_users =
        [](std::string_view tag, const acpp::StaticUserConfig& config)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            if (!acpp::vless::IsNoVlessEncryption(config.vless_decryption)) {
                auto parsed = acpp::vless::ParseVlessServerDecryption(
                    config.vless_decryption);
                if (!parsed) {
                    LOG_WARN("VLESS inbound '{}': invalid decryption '{}': {}",
                             tag,
                             config.vless_decryption,
                             acpp::vless::VlessEncryptionParseErrorMessage(
                                 parsed.error));
                    return std::nullopt;
                }
                LOG_WARN("VLESS inbound '{}': decryption '{}' is valid VLESS Encryption syntax but runtime support is not implemented yet",
                         tag,
                         config.vless_decryption);
                return std::nullopt;
            }
            std::vector<acpp::proxyman::inbound::PreparedVlessUser> users;
            users.reserve(config.clients.size());
            for (const auto& client : config.clients) {
                std::string uuid = client.id.empty() ? client.password : client.id;
                auto uuid_bytes = acpp::vless::ParseUuidBytes(uuid);
                if (!uuid_bytes) {
                    continue;
                }
                acpp::proxyman::inbound::PreparedVlessUser info;
                info.uuid = std::move(uuid);
                info.uuid_bytes = *uuid_bytes;
                info.flow = acpp::vless::NormalizeFlow(client.flow);
                info.profile.email = client.email;
                users.push_back(std::move(info));
            }
            acpp::proxyman::inbound::UserSet result;
            result.vless_users = std::move(users);
            return result;
        };

    reg.build_users =
        [](const acpp::proxyman::inbound::BuildRequest& /*req*/,
           std::span<const acpp::proxyman::inbound::RuntimeUser> runtime_users)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::proxyman::inbound::PreparedVlessUser> users;
            users.reserve(runtime_users.size());
            for (const auto& runtime_user : runtime_users) {
                const std::string& uuid =
                    runtime_user.uuid.empty() ? runtime_user.password : runtime_user.uuid;
                auto uuid_bytes = acpp::vless::ParseUuidBytes(uuid);
                if (!uuid_bytes) {
                    continue;
                }
                acpp::proxyman::inbound::PreparedVlessUser info;
                info.uuid = uuid;
                info.uuid_bytes = *uuid_bytes;
                info.flow = acpp::vless::NormalizeFlow(runtime_user.flow);
                info.profile.email = runtime_user.email;
                info.profile.user_id = runtime_user.user_id;
                info.profile.speed_limit = runtime_user.speed_limit;
                info.profile.device_limit = runtime_user.device_limit;
                users.push_back(std::move(info));
            }
            acpp::proxyman::inbound::UserSet result;
            result.vless_users = std::move(users);
            return result;
        };

    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kVless, std::move(reg));
    return true;
}();
}  // namespace
