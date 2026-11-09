#include "common/domain_name.hpp"
#include "common/ip_address.hpp"
#include "common/unsafe.hpp"
#include "proxy/outbound.hpp"
#include "../vless_codec.hpp"
#include "../vless_encryption.hpp"
#include "../../inbound_admission.hpp"
#include "../../outbound_stream_endpoint.hpp"
#include "app/dns/dns.hpp"
#include "app/proxyman/outbound/factory.hpp"
#include "infra/json.hpp"
#include "app/relay.hpp"
#include "common/allocator.hpp"
#include "common/buffer_util.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"
#include "common/error.hpp"
#include "common/mux/mux_codec.hpp"
#include "common/session.hpp"
#include "core/constants.hpp"
#include "core/naming.hpp"
#include "infra/log.hpp"
#include "infra/config_types.hpp"
#include "transport/async_stream.hpp"
#include "transport/internet/outbound_target_builder.hpp"
#include "transport/link.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <array>
#include <cctype>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <chrono>
#include <cstdint>

struct VlessOutboundConfig {
    OutboundServer server;
    std::array<uint8_t, 16> uuid_bytes{};
    std::shared_ptr<const vless::VlessEncryptionConfig> encryption;
    std::string flow;
    bool packet_xudp = true;
    bool packet_addr = false;

    VlessOutboundConfig() = default;
    VlessOutboundConfig(const VlessOutboundConfig&) = default;
    VlessOutboundConfig& operator=(const VlessOutboundConfig&) = default;
    VlessOutboundConfig(VlessOutboundConfig&&) noexcept = default;
    VlessOutboundConfig& operator=(VlessOutboundConfig&&) noexcept = default;
    ~VlessOutboundConfig() noexcept {
        ::SecureZeroMemory(uuid_bytes.data(), uuid_bytes.size());
    }
};

namespace proxy::vless::outbound {

class Handler final : public ::Outbound {
public:
    explicit Handler(std::shared_ptr<const ::VlessOutboundConfig> config);

    ~Handler() override;

    ::net::awaitable<::OutboundProcessResult> Process(
        ::session::Context& ctx,
        ::transport::Link inbound,
        ::OutboundDialer& dialer,
        const ::TimeoutsConfig& timeouts,
        ::StatsShard& stats,
        const ::RelayConfig& relay_config,
        ::buf::MultiBufferBatch first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;

private:
    std::shared_ptr<const ::VlessOutboundConfig> config_;
    std::shared_ptr<::vless::VlessEncryptionClientTicketCache> encryption_tickets_;
};

}  // namespace proxy::vless::outbound

namespace {

using ::vless::VlessBufferedReader;
using ::vless::WriteVlessBytes;

// Version, addons length, then addons this client ignores. Progress lives in
// the endpoint so a cancelled read resumes at the same stream offset.
struct VlessResponseHeaderState {
    std::array<uint8_t, 2> fixed{};
    size_t fixed_read = 0;
    size_t addons_read = 0;
    bool complete = false;
};

net::awaitable<void> ReadVlessResponseHeader(VlessBufferedReader& reader,
                                             VlessResponseHeaderState& state,
                                             const char* failure) {
    if (state.complete) {
        co_return;
    }
    if (!co_await reader.ReadExact(
            state.fixed.data(), state.fixed.size(), false, &state.fixed_read) ||
        state.fixed[0] != vless::kVersion) {
        throw IoSystemError(io_error::connection_reset, failure);
    }
    if (state.fixed[1] != 0 &&
        !co_await reader.DiscardExact(state.fixed[1], &state.addons_read)) {
        throw IoSystemError(io_error::connection_reset, failure);
    }
    state.complete = true;
}

class VlessOutboundEndpoint final : public proxy::OutboundStreamEndpointBase {
public:
    struct VisionIoState {
        ::vless::VisionTrafficState traffic;
        ::vless::VisionReader reader;
        ::vless::VisionWriter writer;

        VisionIoState(VlessBufferedReader& src,
                      transport::MultiBufferWriter& dst,
                      std::array<uint8_t, 16> user_uuid)
            : reader(src, user_uuid, traffic)
            , writer(dst, user_uuid, traffic) {}
    };

    VlessOutboundEndpoint(AsyncStream& control,
                          VlessBufferedReader& reader,
                          transport::MultiBufferWriter& writer,
                          bool is_udp,
                          const TargetAddress& udp_target,
                          bool packet_addr,
                          bool vision,
                          std::array<uint8_t, 16> user_uuid)
        : OutboundStreamEndpointBase(control)
        , reader_(reader)
        , writer_(writer)
        , is_udp_(is_udp)
        , udp_target_(udp_target)
        , packet_addr_(packet_addr) {
        if (is_udp_) {
            io_state_.emplace<::vless::UdpFramer>(packet_addr);
        } else if (vision) {
            io_state_.emplace<VisionIoState>(reader_, writer_, user_uuid);
        }
        OPENSSL_cleanse(user_uuid.data(), user_uuid.size());
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!response_header_.complete) {
            return ReadInitialMultiBuffer();
        }
        if (auto* udp_framer = std::get_if<::vless::UdpFramer>(&io_state_)) {
            return udp_framer->ReadDatagram(reader_, udp_target_);
        }
        if (auto* vision_io = std::get_if<VisionIoState>(&io_state_)) {
            return vision_io->reader.ReadMultiBuffer();
        }
        return reader_.ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!is_udp_) {
            if (auto* vision_io = std::get_if<VisionIoState>(&io_state_)) {
                return vision_io->writer.WriteMultiBuffer(std::move(mb));
            }
            return writer_.WriteMultiBuffer(std::move(mb));
        }

        return ::vless::WriteUdpDatagram(
            writer_, std::move(mb), packet_addr_,
            packet_addr_ ? nullptr : &udp_target_);
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (!is_udp_) {
            if (auto* vision_io = std::get_if<VisionIoState>(&io_state_)) {
                return vision_io->writer.WriteBuffers(buffers);
            }
            return writer_.WriteBuffers(buffers);
        }

        return ::vless::WriteUdpDatagram(
            writer_, udp_target_, packet_addr_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return writer_.AsyncShutdownWrite();
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return is_udp_ ? transport::EofAction::WaitForPeer : reader_.ReadEofAction();
    }

private:
    net::awaitable<buf::MultiBuffer> ReadInitialMultiBuffer() {
        co_await ReadVlessResponseHeader(
            reader_, response_header_, "VLESS response header read failed");
        if (auto* udp_framer = std::get_if<::vless::UdpFramer>(&io_state_)) {
            co_return co_await udp_framer->ReadDatagram(reader_, udp_target_);
        }
        if (auto* vision_io = std::get_if<VisionIoState>(&io_state_)) {
            co_return co_await vision_io->reader.ReadMultiBuffer();
        }
        co_return co_await reader_.ReadMultiBuffer();
    }

    VlessBufferedReader& reader_;
    transport::MultiBufferWriter& writer_;
    VlessResponseHeaderState response_header_;
    bool is_udp_ = false;
    const TargetAddress& udp_target_;
    bool packet_addr_ = false;
    std::variant<std::monostate, VisionIoState, ::vless::UdpFramer> io_state_;
};


class VlessMuxUdpEndpoint final : public proxy::OutboundStreamEndpointBase {
public:
    VlessMuxUdpEndpoint(AsyncStream& control,
                        VlessBufferedReader& reader,
                        transport::MultiBufferWriter& writer,
                        const TargetAddress& udp_target,
                        ForwardedMetadataView forwarded) noexcept
        : OutboundStreamEndpointBase(control)
        , reader_(reader)
        , writer_(writer)
        , udp_target_(udp_target)
        , forwarded_(forwarded) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (peer_ended_) {
            co_return buf::MultiBuffer{};
        }
        co_await ReadVlessResponseHeader(
            reader_, response_header_, "VLESS mux response header read failed");

        while (true) {
            auto header = mux::DecodeFrame(pending_);
            if (header) {
                if (header->frame_size == 0) {
                    throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                if (header->status == mux::SessionStatus::KEEPALIVE) {
                    (void)pending_.DropPrefixBytes(header->frame_size);
                    pending_.ReleaseIfIdle();
                    continue;
                }
                if (header->status == mux::SessionStatus::NEW) {
                    throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                if (header->session_id != session_id_) {
                    throw IoSystemError(
                        io_error::connection_reset,
                        "VLESS mux response session id mismatch");
                }
                if ((header->option & mux::kOptionError) != 0) {
                    throw IoSystemError(
                        io_error::connection_reset,
                        "VLESS mux response error frame");
                }
                if (header->has_target && header->network != mux::NetworkType::UDP) {
                    throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                buf::MultiBuffer payload;
                if (header->data_len == 0) {
                    (void)pending_.DropPrefixBytes(header->frame_size);
                } else {
                    (void)pending_.DropPrefixBytes(header->frame_size - header->data_len);
                    if (!pending_.MovePrefixTo(payload, header->data_len)) {
                        throw std::bad_alloc();
                    }
                }
                pending_.ReleaseIfIdle();
                if (header->status == mux::SessionStatus::END) {
                    peer_ended_ = true;
                    pending_.clear();
                    if (!header->has_data) {
                        co_return buf::MultiBuffer{};
                    }
                }
                if (!header->has_data) continue;
                const TargetAddress& src = header->has_target
                    ? header->target
                    : udp_target_;
                if (!buf::SetUdpTarget(payload, src)) {
                    throw std::bad_alloc();
                }
                co_return payload;
            }

            buf::MultiBuffer raw = co_await ReadMultiBufferOrThrowOnCancel(reader_);
            if (raw.byte_size() == 0) {
                if (pending_.byte_size() != 0) {
                    throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                co_return buf::MultiBuffer{};
            }
            buf::AppendPacketStreamInput(pending_, std::move(raw));
        }
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        const auto datagram = buf::InspectUdpDatagram(mb);
        if (datagram.status == buf::UdpDatagramStatus::Empty) {
            co_return;
        }
        if (!datagram.Valid() || !datagram.target->IsValid()) {
            throw IoSystemError(
                io_error::invalid_argument,
                "VLESS mux datagram contains missing or mixed targets");
        }
        ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity> payload;
        payload.AppendMultiBuffer(mb);
        co_await WriteDatagram(*datagram.target, payload.Span());
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        co_await WriteDatagram(udp_target_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (session_started_ && !end_sent_) {
            std::array<uint8_t, 6> write_frame{};
            const size_t header_len = mux::EncodeEndTo(write_frame, session_id_);
            co_await WriteVlessBytes(
                writer_, std::span<const uint8_t>(write_frame.data(), header_len));
            end_sent_ = true;
        }
        co_await writer_.AsyncShutdownWrite();
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return transport::EofAction::WaitForPeer;
    }

private:
    net::awaitable<void> WriteDatagram(
        const TargetAddress& target,
        std::span<const net::const_buffer> payload) {
        const auto payload_size = buf::TrySumBufferSizes(
            payload, std::numeric_limits<uint16_t>::max());
        if (!payload_size) {
            throw IoSystemError(
                io_error::message_size,
                "VLESS mux datagram exceeds wire length");
        }

        std::array<uint8_t, mux::kMaxFrameHeaderBytes> write_frame{};
        const size_t header_len = !session_started_
            ? mux::EncodeNewHeaderTo(
                  write_frame, session_id_, mux::NetworkType::UDP,
                  target, *payload_size, true, forwarded_)
            : mux::EncodeKeepUDPHeaderTo(
                  write_frame, session_id_, target, *payload_size);
        if (header_len == 0) {
            throw IoSystemError(
                io_error::connection_reset,
                "VLESS mux request encode failed");
        }

        ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity + 1> frame;
        frame.Append(net::const_buffer(write_frame.data(), header_len));
        frame.AppendBuffers(payload);
        co_await writer_.WriteBuffers(frame.Span());
        session_started_ = true;
        forwarded_ = {};
    }

    VlessBufferedReader& reader_;
    transport::MultiBufferWriter& writer_;
    const TargetAddress& udp_target_;
    ForwardedMetadataView forwarded_;
    VlessResponseHeaderState response_header_;
    bool session_started_ = false;
    bool end_sent_ = false;
    bool peer_ended_ = false;
    uint16_t session_id_ = 1;
    buf::MultiBuffer pending_;
};

// 稳态只保留拒绝信号和身份；完整 PFS 快照仅属于握手子协程。
// 此对象先于 encrypted_io 构造，且禁止移动，保证延迟读端的借用有效。
struct VlessClientTicketLease {
    explicit VlessClientTicketLease(
        std::shared_ptr<::vless::VlessEncryptionClientTicketCache> cache)
        : cache(std::move(cache)) {}

    VlessClientTicketLease(const VlessClientTicketLease&) = delete;
    VlessClientTicketLease& operator=(const VlessClientTicketLease&) = delete;
    VlessClientTicketLease(VlessClientTicketLease&&) = delete;
    VlessClientTicketLease& operator=(VlessClientTicketLease&&) = delete;

    void Acquire(::vless::VlessEncryptionClientTicketCache& local) {
        if (!cache) return;
        local = *cache;
        identity = local.ticket;
    }

    void Publish(
        const ::vless::VlessEncryptionClientTicketCache& local,
        std::chrono::steady_clock::time_point original_expiry) {
        if (!cache ||
            (CRYPTO_memcmp(local.ticket.data(), identity.data(), identity.size()) == 0 &&
             local.expires_at == original_expiry)) return;
        if (CRYPTO_memcmp(cache->ticket.data(), identity.data(), identity.size()) == 0) {
            *cache = local;
        }
        identity = local.ticket;
    }

    ~VlessClientTicketLease() {
        if (!cache || !rejection.rejected) return;
        if (CRYPTO_memcmp(cache->ticket.data(), identity.data(), identity.size()) == 0) {
            cache->Clear();
        }
    }

    std::shared_ptr<::vless::VlessEncryptionClientTicketCache> cache;
    std::array<uint8_t, ::vless::kVlessEncryptionTicketSize> identity{};
    ::vless::VlessEncryptionTicketRejection rejection;
};

net::awaitable<tl::expected<void, ErrorCode>>
SendVlessHandshake(
    AsyncStream& stream,
    const VlessOutboundConfig& config,
    VlessClientTicketLease& tickets,
    const TargetAddress& target,
    bool is_udp,
    bool use_vision,
    bool use_xudp,
    bool use_packet_addr,
    std::chrono::seconds handshake_timeout,
    VlessBufferedReader& protocol_reader,
    transport::MultiBufferWriter& protocol_writer,
    std::optional<::vless::VlessEncryptedIo>& encrypted_io,
    VlessBufferedReader*& active_reader,
    transport::MultiBufferWriter*& active_writer,
    const OutboundDialer& dialer,
    const session::Context& ctx) {
    ::vless::VlessEncryptionClientTicketCache local_tickets;
    tickets.Acquire(local_tickets);
    const auto original_expiry = local_tickets.expires_at;
    stream.SetIdleTimeout(handshake_timeout);
    PhaseDeadlineHandle outbound_protocol_deadline =
        stream.StartPhaseDeadline(handshake_timeout);

    if (config.encryption) {
        try {
            auto runtime =
                co_await ::vless::RunVlessEncryptionClientHandshake(
                    protocol_reader,
                    protocol_writer,
                    *config.encryption,
                    tickets.cache ? &local_tickets : nullptr,
                    tickets.rejection);
            tickets.rejection.rejected =
                local_tickets.expires_at == std::chrono::steady_clock::time_point{};
            if (!runtime) {
                if (proxy::ConsumeOutboundHandshakeTimeout(
                        stream, outbound_protocol_deadline)) {
                    co_return tl::unexpected(ErrorCode::TIMEOUT);
                }
                if (runtime.error() == ::vless::VlessEncryptionHandshakeFailure::Truncated) {
                    co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
                }
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            encrypted_io.emplace(
                protocol_reader, protocol_writer, std::move(*runtime));
            active_reader = &encrypted_io->plain_reader;
            active_writer = &encrypted_io->writer;
        } catch (...) {
            tickets.rejection.rejected =
                local_tickets.expires_at == std::chrono::steady_clock::time_point{};
            co_return tl::unexpected(
                proxy::ClassifyOutboundHandshakeException(
                    stream,
                    outbound_protocol_deadline,
                    ErrorCode::PROTOCOL_DECODE_FAILED));
        }
    }

    std::array<uint8_t, ::vless::kMaxRequestHeaderSize> header_buf{};
    const TargetAddress packet_magic_target = use_packet_addr
        ? TargetAddress(::vless::kPacketAddrMagicAddress, 0)
        : TargetAddress{};
    const TargetAddress& request_target = use_packet_addr ? packet_magic_target : target;
    const size_t header_len = ::vless::EncodeRequestHeaderTo(
        config.uuid_bytes,
        use_xudp
            ? ::vless::Command::MUX
            : (is_udp ? ::vless::Command::UDP : ::vless::Command::TCP),
        request_target,
        header_buf.data(),
        header_buf.size(),
        use_vision ? std::string_view(config.flow) : std::string_view{},
        dialer.ForwardedMetadata(ctx));
    if (header_len == 0) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    try {
        co_await WriteVlessBytes(
            *active_writer, std::span<const uint8_t>(header_buf.data(), header_len));
    } catch (...) {
        OPENSSL_cleanse(header_buf.data(), header_len);
        const ErrorCode classified = proxy::ClassifyOutboundHandshakeException(
            stream, outbound_protocol_deadline);
        if (encrypted_io && classified != ErrorCode::CANCELLED) {
            encrypted_io->reader.RejectDeferredTicket();
        }
        co_return tl::unexpected(classified);
    }
    OPENSSL_cleanse(header_buf.data(), header_len);
    tickets.Publish(local_tickets, original_expiry);
    co_return tl::expected<void, ErrorCode>{};
}

}  // namespace

proxy::vless::outbound::Handler::Handler(
    std::shared_ptr<const VlessOutboundConfig> config)
    : config_(std::move(config))
    , encryption_tickets_(config_->encryption
          ? std::make_shared<::vless::VlessEncryptionClientTicketCache>()
          : nullptr) {}

proxy::vless::outbound::Handler::~Handler() = default;

net::awaitable<OutboundProcessResult>
proxy::vless::outbound::Handler::Process(
    session::Context& ctx,
    transport::Link inbound,
    OutboundDialer& dialer,
    const TimeoutsConfig& timeouts,
    StatsShard& stats,
    const RelayConfig& relay_config,
    buf::MultiBufferBatch first_payload,
    std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout) {
    if (!inbound.Valid()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (!config_->flow.empty() && ctx.content.network != Network::TCP) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    const auto& target = ctx.outbound.target;
    auto dialed = co_await dialer.Dial(ctx, config_->server);
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }
    auto stream = std::move(*dialed);

    auto fail_abortive = [&](ErrorCode error) {
        if (stream) {
            stream->CloseAbortive();
        }
        return tl::unexpected(error);
    };

    const bool is_udp = ctx.content.network == Network::UDP;
    const bool use_vision = !config_->flow.empty();
    const bool use_xudp = is_udp && config_->packet_xudp;
    const bool use_packet_addr = is_udp && config_->packet_addr;
    VlessClientTicketLease tickets(encryption_tickets_);
    VlessBufferedReader protocol_reader(*stream);
    transport::MultiBufferWriter& protocol_writer = *stream;
    VlessBufferedReader* active_reader = &protocol_reader;
    transport::MultiBufferWriter* active_writer = &protocol_writer;
    std::optional<::vless::VlessEncryptedIo> encrypted_io;

    if (auto ok = co_await SendVlessHandshake(
            *stream, *config_, tickets, target,
            is_udp, use_vision, use_xudp, use_packet_addr,
            timeouts.HandshakeTimeout(), protocol_reader, protocol_writer,
            encrypted_io, active_reader, active_writer, dialer, ctx); !ok) {
        co_return fail_abortive(ok.error());
    }
    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    stream->ClearPhaseDeadline();

    if (use_xudp) {
        VlessMuxUdpEndpoint target_endpoint(
            *stream,
            *active_reader,
            *active_writer,
            target,
            dialer.ForwardedMetadata(ctx));
        auto res = co_await DoRelayLink(
            dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
            target_endpoint, ctx, stats, relay_config, std::move(first_payload));
        if (encrypted_io && !res) {
            encrypted_io->reader.RejectDeferredTicket();
        }
        co_return res;
    }

    VlessOutboundEndpoint target_endpoint(
        *stream,
        *active_reader,
        *active_writer,
        is_udp,
        target,
        use_packet_addr,
        use_vision,
        config_->uuid_bytes);
    auto res = co_await DoRelayLink(
        dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
        target_endpoint, ctx, stats, relay_config, std::move(first_payload));
    if (encrypted_io && !res) {
        encrypted_io->reader.RejectDeferredTicket();
    }
    co_return res;
}


namespace {
const bool kVlessRegistered = (::proxyman::outbound::RegisterProxy(
    ::constants::protocol::kVless,
    [](const ::infra::OutboundSourceConfig& cfg)
        -> std::optional<::proxyman::outbound::PreparedOutboundProxy> {
        // A present field of the wrong type is a configuration error, never
        // an implicit default.
        bool invalid_field = false;
        auto json_string = [&](const ::json::object& obj,
                               std::string_view key) -> std::string {
            auto parsed = ::ParseJsonString(obj, key);
            if (!parsed) {
                LOG_ERROR("VLESS outbound '{}': {}", cfg.tag, parsed.error());
                invalid_field = true;
                return {};
            }
            return std::move(*parsed).value_or(std::string{});
        };

        ::VlessOutboundConfig vless_config;
        std::string address;
        uint16_t port = 443;
        std::string uuid;
        std::string encryption;

        const auto& s = cfg.settings;
        std::string packet_encoding;
        const auto vnext_server = ::proxy::ParseOptionalSingleObjectArray(
            s, "vnext", "VLESS", cfg.tag);
        if (!vnext_server) {
            return std::nullopt;
        }
        const ::json::object& server_obj = *vnext_server ? **vnext_server : s;
        const ::json::object* user_obj = &s;
        if (*vnext_server) {
            user_obj = ::proxy::ParseRequiredSingleObjectArray(
                server_obj, "users", "VLESS", cfg.tag);
            if (!user_obj) {
                return std::nullopt;
            }
        } else if (s.if_contains("users")) {
            LOG_ERROR("VLESS outbound '{}': users requires vnext", cfg.tag);
            return std::nullopt;
        }
        address = json_string(server_obj, "address");
        const auto source_port = ::ReadJsonPort(server_obj, "port");
        if (source_port.Invalid()) {
            return std::nullopt;
        }
        if (source_port.Valid()) {
            port = source_port.value;
        }
        uuid = json_string(*user_obj, "id");
        if (*vnext_server && uuid.empty()) {
            uuid = json_string(*user_obj, "uuid");
        }
        encryption = json_string(*user_obj, "encryption");
        vless_config.flow = json_string(*user_obj, "flow");
        packet_encoding = json_string(*user_obj, "packetEncoding");
        if (*vnext_server) {
            if (packet_encoding.empty()) {
                packet_encoding = json_string(s, "packetEncoding");
            }
            if (encryption.empty()) {
                encryption = json_string(s, "encryption");
            }
        }
        if (invalid_field) {
            return std::nullopt;
        }

        if (!::vless::IsNoVlessEncryption(encryption)) {
            auto parsed = ::vless::ParseVlessClientEncryption(
                encryption);
            if (!parsed) {
                LOG_WARN("VLESS outbound '{}': invalid encryption: {}",
                         cfg.tag,
                         ::vless::VlessEncryptionParseErrorMessage(
                             parsed.error));
                return std::nullopt;
            }
            vless_config.encryption = std::make_shared<const ::vless::VlessEncryptionConfig>(
                std::move(*parsed.config));
        }

        packet_encoding = ::naming::LowerAscii(std::move(packet_encoding));
        if (packet_encoding.empty() || packet_encoding == "xudp") {
            vless_config.packet_xudp = true;
            vless_config.packet_addr = false;
        } else if (packet_encoding == "none" || packet_encoding == "raw") {
            vless_config.packet_xudp = false;
            vless_config.packet_addr = false;
        } else if (packet_encoding == "packetaddr" ||
                   packet_encoding == "packet-addr" ||
                   packet_encoding == "packet") {
            vless_config.packet_xudp = false;
            vless_config.packet_addr = true;
        } else {
            LOG_WARN("VLESS outbound '{}': packet encoding '{}' is not supported",
                     cfg.tag, packet_encoding);
            return std::nullopt;
        }

        vless_config.flow = ::vless::NormalizeFlow(vless_config.flow);
        if (!vless_config.flow.empty() &&
            !::vless::IsVisionFlow(vless_config.flow)) {
            LOG_WARN("VLESS outbound '{}': flow '{}' is not supported",
                     cfg.tag, vless_config.flow);
            return std::nullopt;
        }

        const auto uuid_bytes = ::vless::ParseUuidBytes(uuid);
        if (!uuid_bytes) {
            LOG_ERROR("VLESS outbound '{}': invalid UUID", cfg.tag);
            return std::nullopt;
        }
        vless_config.uuid_bytes = *uuid_bytes;
        auto next_hop = ::proxy::PrepareNextHop(
            cfg, std::move(address), port, ::OutboundStreamDefaults{});
        if (!next_hop) {
            return std::nullopt;
        }
        const auto& stream_settings = next_hop->sender.stream_settings;
        if (!vless_config.flow.empty() &&
            (!(stream_settings.IsTlsLike() || vless_config.encryption != nullptr) ||
             stream_settings.network_mode != ::NetworkMode::Tcp)) {
            LOG_ERROR("VLESS outbound '{}': Vision requires TCP with TLS, Reality, or VLESS Encryption", cfg.tag);
            return std::nullopt;
        }
        vless_config.server = std::move(next_hop->server);
        return ::proxyman::outbound::PreparedOutboundProxy{
            .create = ::proxyman::outbound::MakePreparedOutboundCreator<
                ::VlessOutboundConfig,
                +[](std::string_view,
                    std::shared_ptr<const ::VlessOutboundConfig> cfg_state,
                    ::net::io_context& /*io_context*/,
                    ::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<::Outbound> {
                    return std::make_unique<::proxy::vless::outbound::Handler>(
                        std::move(cfg_state));
                }>(std::move(vless_config)),
            .sender = std::move(next_hop->sender),
        };
    }), true);
}  // namespace
