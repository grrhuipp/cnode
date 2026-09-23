#include "vless_outbound.hpp"
#include "acppnode/common/domain_name.hpp"
#include "acppnode/common/ip_address.hpp"

#include "../vless_codec.hpp"
#include "../vless_encryption.hpp"
#include "../vless_encryption_io.hpp"
#include "../vless_encryption_runtime.hpp"
#include "../vless_io_util.hpp"
#include "../udp_framing.hpp"
#include "../vless_vision.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/registration.hpp"
#include "acppnode/infra/json_port.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/mux/mux_codec.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/infra/config_types.hpp"
#include "../credentials.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/transport/link.hpp"

#include <array>
#include <cctype>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace acpp {

namespace {

using ::acpp::vless::VlessBufferedReader;
using ::acpp::vless::WriteVlessBytes;

constexpr size_t kUdpFrameQueueShrinkItems = 64;

class VlessOutboundEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    VlessOutboundEndpoint(AsyncStream& control,
                          VlessBufferedReader& reader,
                          transport::MultiBufferWriter& writer,
                          bool is_udp,
                          TargetAddress udp_target,
                          bool packet_addr = false,
                          bool vision = false,
                          std::array<uint8_t, 16> user_uuid = {})
        : control_(control)
        , reader_(reader)
        , writer_(writer)
        , is_udp_(is_udp)
        , udp_target_(std::move(udp_target))
        , packet_addr_(packet_addr)
        , framer_(packet_addr) {
        if (vision) {
            vision_reader_.emplace(reader_, user_uuid);
            vision_writer_.emplace(writer_, user_uuid);
        }
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!response_header_read_) {
            if (!co_await ReadResponseHeader()) {
                throw IoSystemError(
                    io_error::connection_reset,
                    "VLESS response header read failed");
            }
            response_header_read_ = true;
        }

        if (!is_udp_) {
            if (vision_reader_) {
                co_return co_await vision_reader_->ReadMultiBuffer();
            }
            co_return co_await reader_.ReadMultiBuffer();
        }

        while (true) {
            ::acpp::vless::FramedUdpPacket packet;
            if (framer_.Next(packet)) {
                const TargetAddress& target = packet.target
                    ? *packet.target
                    : udp_target_;
                for (buf::Buffer* buffer : packet.payload) {
                    if (buffer && !buffer->IsEmpty()) {
                        buffer->SetUDP(target);
                    }
                }
                co_return std::move(packet.payload);
            }

            buf::MultiBuffer raw = co_await reader_.ReadMultiBuffer();
            if (!buf::HasData(raw)) {
                co_return buf::MultiBuffer{};
            }
            for (buf::Buffer* buffer : raw) {
                if (buffer && !buffer->IsEmpty()) {
                    framer_.Feed(buffer->Bytes().data(), buffer->Len());
                }
            }
            raw.clear();
        }
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!is_udp_) {
            if (vision_writer_) {
                co_await vision_writer_->WriteMultiBuffer(std::move(mb));
                co_return;
            }
            co_await writer_.WriteMultiBuffer(std::move(mb));
            co_return;
        }

        co_await ::acpp::vless::WriteUdpDatagram(
            writer_, std::move(mb), packet_addr_,
            packet_addr_ ? nullptr : &udp_target_);
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (!is_udp_) {
            if (vision_writer_) {
                co_await vision_writer_->WriteBuffers(buffers);
                co_return;
            }
            co_await writer_.WriteBuffers(buffers);
            co_return;
        }

        co_await ::acpp::vless::WriteUdpDatagram(
            writer_, udp_target_, packet_addr_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        co_await writer_.AsyncShutdownWrite();
    }

    void SetIdleTimeout(std::chrono::seconds timeout) {
        control_.SetIdleTimeout(timeout);
    }

    void SetReadTimeout(std::chrono::seconds timeout) {
        control_.SetReadTimeout(timeout);
    }

    void SetWriteTimeout(std::chrono::seconds timeout) {
        control_.SetWriteTimeout(timeout);
    }

    bool ConsumeIdleTimeout() noexcept {
        return control_.ConsumeIdleTimeout();
    }

    bool ConsumeReadTimeout() noexcept {
        return control_.ConsumeReadTimeout();
    }

    bool ConsumeWriteTimeout() noexcept {
        return control_.ConsumeWriteTimeout();
    }

    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
        return control_.StartPhaseDeadline(timeout);
    }

    void ClearPhaseDeadline() {
        control_.ClearPhaseDeadline();
    }

    bool ConsumePhaseDeadline() noexcept {
        return control_.ConsumePhaseDeadline();
    }

    void Cancel() noexcept {
        control_.Cancel();
    }

    transport::CancellationSource& Cancellation() noexcept override { return control_.Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override {
        return is_udp_ ? transport::EofAction::WaitForPeer : reader_.ReadEofAction();
    }

    void SetAbortiveClose(bool enable = true) noexcept {
        control_.SetAbortiveClose(enable);
    }

private:
    net::awaitable<bool> ReadResponseHeader() {
        uint8_t fixed[2]{};
        if (!co_await reader_.ReadExact(fixed, sizeof(fixed))) {
            co_return false;
        }
        if (fixed[0] != vless::kVersion) {
            co_return false;
        }
        const size_t addons_len = fixed[1];
        if (addons_len > 0) {
            std::array<uint8_t, 255> addons{};
            if (!co_await reader_.ReadExact(addons.data(), addons_len)) {
                co_return false;
            }
        }
        co_return true;
    }

    AsyncStream& control_;
    VlessBufferedReader& reader_;
    transport::MultiBufferWriter& writer_;
    bool response_header_read_ = false;
    bool is_udp_ = false;
    TargetAddress udp_target_;
    bool packet_addr_ = false;
    std::optional<::acpp::vless::VisionReader> vision_reader_;
    std::optional<::acpp::vless::VisionWriter> vision_writer_;
    ::acpp::vless::UdpFramer framer_;
};

struct MuxFramePayload {
    mux::FrameHeader header;
    buf::MultiBuffer payload;
};

class MuxFrameFramer {
public:
    [[nodiscard]] bool Feed(const uint8_t* data, size_t len) {
        if (failed_) {
            return false;
        }
        if (!data || len == 0) {
            return true;
        }
        CompactConsumed();
        EnsureAppendCapacity(pending_, len, buf::Buffer::kSize);
        pending_.insert(pending_.end(), data, data + len);
        return Parse();
    }

    bool Next(MuxFramePayload& out) {
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
    memory::ByteVector pending_;
    memory::ThreadLocalDeque<MuxFramePayload> queue_;
    size_t pending_offset_ = 0;
    bool shrink_queue_on_drain_ = false;
    bool failed_ = false;

    [[nodiscard]] bool Parse() {
        while (pending_offset_ < pending_.size()) {
            const uint8_t* frame_base = pending_.data() + pending_offset_;
            const size_t available = pending_.size() - pending_offset_;
            auto parsed = mux::DecodeFrame(frame_base, available);
            if (!parsed) {
                break;
            }
            if (parsed->frame_size == 0) {
                Fail();
                return false;
            }

            MuxFramePayload packet;
            packet.header = *parsed;
            if (parsed->has_data && parsed->data_len > 0) {
                const size_t payload_offset =
                    pending_offset_ + parsed->frame_size - parsed->data_len;
                if (!buf::AppendSpanToMultiBuffer(
                        std::span<const uint8_t>(
                            pending_.data() + payload_offset,
                            parsed->data_len),
                        packet.payload)) {
                    Fail();
                    return false;
                }
            }
            queue_.push_back(std::move(packet));
            if (queue_.size() >= kUdpFrameQueueShrinkItems) {
                shrink_queue_on_drain_ = true;
            }
            pending_offset_ += parsed->frame_size;
        }
        CompactConsumed();
        return true;
    }

    void Fail() noexcept {
        failed_ = true;
        pending_.clear();
        pending_offset_ = 0;
        queue_.clear();
        shrink_queue_on_drain_ = false;
    }

    void CompactConsumed() {
        if (pending_offset_ == 0) {
            return;
        }
        if (pending_offset_ >= pending_.size()) {
            pending_.clear();
            pending_offset_ = 0;
            ReleaseIdleBuffer(pending_);
            return;
        }
        const size_t remaining = pending_.size() - pending_offset_;
        if (pending_offset_ >= buf::Buffer::kSize && pending_offset_ >= remaining) {
            pending_.erase(
                pending_.begin(),
                pending_.begin() + static_cast<std::ptrdiff_t>(pending_offset_));
            pending_offset_ = 0;
        }
    }
};

class VlessMuxUdpEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    VlessMuxUdpEndpoint(AsyncStream& control,
                        VlessBufferedReader& reader,
                        transport::MultiBufferWriter& writer,
                        TargetAddress udp_target)
        : control_(control)
        , reader_(reader)
        , writer_(writer)
        , udp_target_(std::move(udp_target)) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!response_header_read_) {
            if (!co_await ReadResponseHeader()) {
                throw IoSystemError(
                    io_error::connection_reset,
                    "VLESS mux response header read failed");
            }
            response_header_read_ = true;
        }

        while (true) {
            MuxFramePayload frame;
            while (framer_.Next(frame)) {
                if (frame.header.status == mux::SessionStatus::KEEPALIVE) {
                    continue;
                }
                if (frame.header.session_id != session_id_) {
                    throw IoSystemError(
                        io_error::connection_reset,
                        "VLESS mux response session id mismatch");
                }
                if (frame.header.status == mux::SessionStatus::END) {
                    co_return buf::MultiBuffer{};
                }
                if (!frame.header.has_data || !buf::HasData(frame.payload)) {
                    continue;
                }
                const TargetAddress& src = frame.header.has_target
                    ? frame.header.target
                    : udp_target_;
                for (buf::Buffer* buffer : frame.payload) {
                    if (buffer && !buffer->IsEmpty()) {
                        buffer->SetUDP(src);
                    }
                }
                co_return std::move(frame.payload);
            }

            buf::MultiBuffer raw = co_await reader_.ReadMultiBuffer();
            if (!buf::HasData(raw)) {
                co_return buf::MultiBuffer{};
            }
            for (buf::Buffer* buffer : raw) {
                if (buffer && !buffer->IsEmpty()) {
                    if (!framer_.Feed(
                            buffer->Bytes().data(), buffer->Len())) {
                        throw IoSystemError(
                            io_error::connection_reset,
                            "invalid VLESS mux response frame");
                    }
                }
            }
            raw.clear();
        }
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        const TargetAddress* target = nullptr;
        ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity> payload;
        for (const buf::Buffer* buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const TargetAddress& buffer_target = buffer->HasUDP()
                ? buffer->UDP()
                : udp_target_;
            if (!target) {
                target = std::addressof(buffer_target);
            } else if (!target->SameEndpoint(buffer_target)) {
                throw IoSystemError(
                    io_error::invalid_argument,
                    "VLESS mux datagram contains mixed targets");
            }
            const auto bytes = buffer->Bytes();
            payload.Append(net::const_buffer(bytes.data(), bytes.size()));
        }
        if (!target || payload.empty()) {
            mb.clear();
            co_return;
        }

        co_await WriteDatagram(*target, payload.Span());
        mb.clear();
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        co_await WriteDatagram(udp_target_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (session_started_ && !end_sent_) {
            mux::EncodeEndTo(write_frame_, session_id_);
            co_await WriteVlessBytes(writer_, write_frame_);
            end_sent_ = true;
        }
        co_await writer_.AsyncShutdownWrite();
    }

    void SetIdleTimeout(std::chrono::seconds timeout) {
        control_.SetIdleTimeout(timeout);
    }

    void SetReadTimeout(std::chrono::seconds timeout) {
        control_.SetReadTimeout(timeout);
    }

    void SetWriteTimeout(std::chrono::seconds timeout) {
        control_.SetWriteTimeout(timeout);
    }

    bool ConsumeIdleTimeout() noexcept {
        return control_.ConsumeIdleTimeout();
    }

    bool ConsumeReadTimeout() noexcept {
        return control_.ConsumeReadTimeout();
    }

    bool ConsumeWriteTimeout() noexcept {
        return control_.ConsumeWriteTimeout();
    }

    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
        return control_.StartPhaseDeadline(timeout);
    }

    void ClearPhaseDeadline() {
        control_.ClearPhaseDeadline();
    }

    bool ConsumePhaseDeadline() noexcept {
        return control_.ConsumePhaseDeadline();
    }

    void Cancel() noexcept {
        control_.Cancel();
    }

    transport::CancellationSource& Cancellation() noexcept override { return control_.Cancellation(); }

    void SetAbortiveClose(bool enable = true) noexcept {
        control_.SetAbortiveClose(enable);
    }

private:
    net::awaitable<void> WriteDatagram(
        const TargetAddress& target,
        std::span<const net::const_buffer> payload) {
        size_t payload_size = 0;
        for (const auto& buffer : payload) {
            if (buffer.size() >
                std::numeric_limits<uint16_t>::max() - payload_size) {
                throw IoSystemError(
                    io_error::message_size,
                    "VLESS mux datagram exceeds wire length");
            }
            payload_size += buffer.size();
        }
        if (payload_size == 0) {
            co_return;
        }

        const bool encoded = !session_started_
            ? mux::EncodeNewHeaderTo(
                  write_frame_, session_id_, mux::NetworkType::UDP,
                  target, payload_size)
            : mux::EncodeKeepUDPHeaderTo(
                  write_frame_, session_id_, target, payload_size);
        if (!encoded || write_frame_.empty()) {
            throw IoSystemError(
                io_error::connection_reset,
                "VLESS mux request encode failed");
        }

        ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity + 1> frame;
        frame.Append(net::const_buffer(write_frame_.data(), write_frame_.size()));
        frame.AppendBuffers(payload);
        co_await writer_.WriteBuffers(frame.Span());
        session_started_ = true;
    }

    net::awaitable<bool> ReadResponseHeader() {
        uint8_t fixed[2]{};
        if (!co_await reader_.ReadExact(fixed, sizeof(fixed))) {
            co_return false;
        }
        if (fixed[0] != vless::kVersion) {
            co_return false;
        }
        const size_t addons_len = fixed[1];
        if (addons_len > 0) {
            std::array<uint8_t, 255> addons{};
            if (!co_await reader_.ReadExact(addons.data(), addons_len)) {
                co_return false;
            }
        }
        co_return true;
    }

    AsyncStream& control_;
    VlessBufferedReader& reader_;
    transport::MultiBufferWriter& writer_;
    TargetAddress udp_target_;
    bool response_header_read_ = false;
    bool session_started_ = false;
    bool end_sent_ = false;
    uint16_t session_id_ = 1;
    MuxFrameFramer framer_;
    memory::ByteVector write_frame_;
};

}  // namespace

proxy::vless::outbound::Handler::Handler(std::string tag,
                                          const VlessOutboundConfig& config,
                                          ::acpp::app::dns::DNS& dns_service)
    : tag_(std::move(tag))
    , config_(config)
    , dns_service_(dns_service)
    , encryption_tickets_(config_.encryption
          ? std::make_unique<::acpp::vless::VlessEncryptionClientTicketCache>()
          : nullptr) {}

proxy::vless::outbound::Handler::~Handler() = default;

net::awaitable<OutboundProcessResult>
proxy::vless::outbound::Handler::Process(
    net::io_context& io_context,
    const tcp::endpoint* inbound_local_addr,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    transport::Link inbound,
    StatsShard& stats,
    const RelayConfig& relay_config,
    buf::MultiBuffer first_payload,
    std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout) {
    if (!inbound.Valid()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (!config_.flow.empty() && ctx.content.network != Network::TCP) {
        co_return std::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    const auto& target = ctx.outbound.target;
    auto transport_target = co_await BuildOutboundTransportTarget(OutboundTargetOptions{
        .dns_service = &dns_service_,
        .address = config_.address,
        .literal_address = config_.literal_address,
        .port = config_.port,
        .stream_settings = &config_.stream_settings,
        .timeout = config_.timeout,
        .send_through = &config_.send_through,
        .inbound_local_addr = inbound_local_addr,
        .inbound_source_ip = ctx.inbound.source_ip,
        .inbound_source_port = ctx.inbound.source_port,
        .tls_server_name = ResolveOutboundTlsServerName(
            config_.stream_settings, config_.address),
        .ws_host = config_.address,
    });
    if (!transport_target) {
        if (transport_target.error() == ErrorCode::DNS_RESOLVE_FAILED) {
            LOG_CONN_WARN(ctx, "[VLESS] DNS resolve failed for {}", config_.address);
        }
        co_return std::unexpected(transport_target.error());
    }

    auto dial_result = co_await DialOutboundTransport(io_context, ctx, *transport_target);
    if (!dial_result.Ok()) {
        LOG_CONN_WARN(ctx, "[VLESS] dial failed {} -> {} via {}: {}",
                          ctx.inbound.source_ip, ctx.outbound.target,
                          ctx.outbound.tag, dial_result.error_msg);
        co_return std::unexpected(dial_result.error);
    }

    auto stream = std::move(dial_result.stream);
    stream->SetStreamLabel("out");
    if (auto local_ep = stream->LocalEndpoint();
        local_ep && !local_ep->address().is_unspecified()) {
        ctx.outbound.connected_local_addr = local_ep->address();
        ctx.outbound.connected_local_port = local_ep->port();
    }
    LOG_ACCESS(FormatXrayAccessLog(ctx));

    auto fail_abortive = [&](ErrorCode error) {
        if (stream) {
            stream->CloseAbortive();
        }
        return std::unexpected(error);
    };

    stream->SetIdleTimeout(timeouts.HandshakeTimeout());
    PhaseDeadlineHandle outbound_protocol_deadline =
        stream->StartPhaseDeadline(timeouts.HandshakeTimeout());

    const bool is_udp = ctx.content.network == Network::UDP;
    const bool use_vision = !config_.flow.empty();
    const bool use_xudp = is_udp && config_.packet_xudp;
    const bool use_packet_addr = is_udp && config_.packet_addr;
    TargetAddress request_target = use_packet_addr
        ? TargetAddress(::acpp::vless::kPacketAddrMagicAddress, 0)
        : target;
    std::array<uint8_t, 512> header{};
    const size_t header_len = ::acpp::vless::Codec::EncodeRequestHeaderTo(
        config_.uuid_bytes,
        use_xudp
            ? ::acpp::vless::Command::MUX
            : (is_udp ? ::acpp::vless::Command::UDP : ::acpp::vless::Command::TCP),
        request_target,
        header.data(),
        header.size(),
        use_vision ? std::string_view(config_.flow) : std::string_view{});
    if (header_len == 0) {
        co_return fail_abortive(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    VlessBufferedReader protocol_reader(*stream);
    transport::MultiBufferWriter* protocol_writer = stream.get();
    VlessBufferedReader* active_reader = &protocol_reader;
    transport::MultiBufferWriter* active_writer = protocol_writer;
    std::optional<::acpp::vless::VlessEncryptionReader> encrypted_reader;
    std::optional<::acpp::vless::VlessEncryptionWriter> encrypted_writer;
    std::optional<VlessBufferedReader> encrypted_plain_reader;

    if (config_.encryption) {
        try {
            auto runtime =
                co_await ::acpp::vless::RunVlessEncryptionClientHandshake(
                    protocol_reader,
                    *protocol_writer,
                    *config_.encryption,
                    encryption_tickets_.get());
            if (!runtime) {
                co_return fail_abortive(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            if (runtime->read_aead_ready) {
                encrypted_reader.emplace(
                    protocol_reader,
                    std::move(runtime->read_aead),
                    runtime->united_key,
                    std::move(runtime->read_xor));
            } else {
                encrypted_reader.emplace(
                    ::acpp::vless::VlessEncryptionReader::CreateLazyReadContext(
                        protocol_reader,
                        runtime->lazy_read_context_size,
                        runtime->united_key,
                        runtime->cipher,
                        runtime->lazy_read_xor_from_context));
            }
            encrypted_writer.emplace(
                *protocol_writer,
                std::move(runtime->write_aead),
                std::move(runtime->united_key),
                std::move(runtime->write_xor));
            encrypted_plain_reader.emplace(*encrypted_reader);
            active_reader = std::addressof(*encrypted_plain_reader);
            active_writer = std::addressof(*encrypted_writer);
        } catch (const IoSystemError&) {
            co_return fail_abortive(outbound_protocol_deadline.Expired()
                ? ErrorCode::TIMEOUT
                : ErrorCode::SOCKET_READ_FAILED);
        } catch (...) {
            co_return fail_abortive(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
    }

    try {
        co_await WriteVlessBytes(*active_writer,
            std::span<const uint8_t>(header.data(), header_len));
    } catch (...) {
        co_return fail_abortive(outbound_protocol_deadline.Expired()
            ? ErrorCode::TIMEOUT : ErrorCode::SOCKET_WRITE_FAILED);
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
            target);
        if (inbound.control) {
            co_return co_await DoRelayLink(
                io_context, *inbound.reader, *inbound.writer, *inbound.control,
                target_endpoint, ctx, stats, relay_config, std::move(first_payload));
        }
        co_return co_await DoRelayLink(
            io_context, *inbound.reader, *inbound.writer,
            target_endpoint, ctx, stats, relay_config, std::move(first_payload));
    }

    VlessOutboundEndpoint target_endpoint(
        *stream,
        *active_reader,
        *active_writer,
        is_udp,
        target,
        use_packet_addr,
        use_vision,
        config_.uuid_bytes);
    if (inbound.control) {
        co_return co_await DoRelayLink(
            io_context, *inbound.reader, *inbound.writer, *inbound.control,
            target_endpoint, ctx, stats, relay_config, std::move(first_payload));
    }
    co_return co_await DoRelayLink(
        io_context, *inbound.reader, *inbound.writer,
        target_endpoint, ctx, stats, relay_config, std::move(first_payload));
}

}  // namespace acpp

namespace {
const bool kVlessRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kVless,
    [](const acpp::infra::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundCreator> {
        auto json_string = [](const acpp::json::object& obj,
                              std::string_view key) -> std::string {
            if (const auto* v = obj.if_contains(key); v && v->is_string()) {
                return std::string(v->as_string());
            }
            return {};
        };
        auto lower_ascii = [](std::string text) {
            std::transform(
                text.begin(),
                text.end(),
                text.begin(),
                [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
            return text;
        };
        auto json_packet_encoding = [&](const acpp::json::object& obj) -> std::string {
            std::string value = json_string(obj, "packet_encoding");
            if (value.empty()) {
                value = json_string(obj, "packetEncoding");
            }
            if (value.empty()) {
                value = json_string(obj, "packet-encoding");
            }
            return value;
        };

        acpp::VlessOutboundConfig vless_config;
        std::string uuid;
        std::string encryption;

        const auto& s = cfg.settings;
        std::string packet_encoding;
        if (const auto* vnext_p = s.if_contains("vnext");
                vnext_p && vnext_p->is_array() && !vnext_p->as_array().empty() &&
                vnext_p->as_array()[0].is_object()) {
            const auto& server = vnext_p->as_array()[0].as_object();
            vless_config.address = json_string(server, "address");
            const auto port = acpp::ReadJsonPort(server, {"port"});
            if (port.Invalid()) {
                return std::nullopt;
            }
            if (port.Valid()) {
                vless_config.port = port.value;
            }

            if (const auto* users_p = server.if_contains("users");
                    users_p && users_p->is_array() && !users_p->as_array().empty() &&
                    users_p->as_array()[0].is_object()) {
                const auto& user = users_p->as_array()[0].as_object();
                uuid = json_string(user, "id");
                if (uuid.empty()) {
                    uuid = json_string(user, "uuid");
                }
                encryption = json_string(user, "encryption");
                vless_config.flow = json_string(user, "flow");
                const std::string user_packet_encoding = json_packet_encoding(user);
                if (!user_packet_encoding.empty()) {
                    packet_encoding = user_packet_encoding;
                }
            }
            if (encryption.empty()) {
                encryption = json_string(s, "encryption");
            }
        } else {
            vless_config.address = json_string(s, "address");
            const auto port = acpp::ReadJsonPort(s, {"port"});
            if (port.Invalid()) {
                return std::nullopt;
            }
            if (port.Valid()) {
                vless_config.port = port.value;
            }
            uuid = json_string(s, "id");
            if (uuid.empty()) {
                uuid = json_string(s, "id");
            }
            encryption = json_string(s, "encryption");
            vless_config.flow = json_string(s, "flow");
            packet_encoding = json_packet_encoding(s);
        }
        if (packet_encoding.empty()) {
            packet_encoding = json_packet_encoding(s);
        }

        if (!acpp::vless::IsNoVlessEncryption(encryption)) {
            auto parsed = acpp::vless::ParseVlessClientEncryption(
                encryption);
            if (!parsed) {
                LOG_WARN("VLESS outbound '{}': invalid encryption '{}': {}",
                         cfg.tag,
                         encryption,
                         acpp::vless::VlessEncryptionParseErrorMessage(
                             parsed.error));
                return std::nullopt;
            }
            vless_config.encryption = acpp::memory::AllocateShared<const acpp::vless::VlessEncryptionConfig>(
                std::move(*parsed.config));
        }

        packet_encoding = lower_ascii(std::move(packet_encoding));
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

        vless_config.flow = acpp::vless::NormalizeFlow(vless_config.flow);
        if (!vless_config.flow.empty() &&
            !acpp::vless::IsVisionFlow(vless_config.flow)) {
            LOG_WARN("VLESS outbound '{}': flow '{}' is not supported",
                     cfg.tag, vless_config.flow);
            return std::nullopt;
        }

        vless_config.send_through = cfg.send_through.value_or(acpp::OutboundBind{});
        vless_config.stream_settings = acpp::NormalizeOutboundStreamSettings(
            cfg.stream_settings,
            acpp::OutboundStreamDefaults{
                .require_tls = false,
                .fallback_server_name = vless_config.address,
                .allow_insecure = false,
                .alpn = {},
            });

        const auto uuid_bytes = acpp::vless::ParseUuidBytes(uuid);
        if (vless_config.address.empty() || vless_config.port == 0 || !uuid_bytes) {
            return std::nullopt;
        }
        vless_config.uuid_bytes = *uuid_bytes;
        vless_config.literal_address = acpp::iputil::ParseLiteral(vless_config.address);
        if (!vless_config.literal_address && !acpp::domain::IsValidDnsHostname(
                vless_config.address, acpp::domain::TrailingDotPolicy::Allow)) {
            LOG_ERROR("vless outbound '{}': address must be an IP literal or DNS hostname", cfg.tag);
            return std::nullopt;
        }
        if (!vless_config.flow.empty() &&
            (!vless_config.stream_settings.IsTlsLike() ||
             vless_config.stream_settings.network_mode != acpp::NetworkMode::Tcp)) {
            LOG_ERROR("VLESS outbound '{}': Vision requires TCP with TLS or Reality", cfg.tag);
            return std::nullopt;
        }

        return acpp::proxyman::outbound::PreparedOutboundCreator{
            [vless_config = std::move(vless_config)](
                std::string_view tag,
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& dns,
                acpp::UDPSessionManager* /*udp_mgr*/,
                std::chrono::seconds timeout) -> std::unique_ptr<acpp::Outbound> {
                auto runtime_config = vless_config;
                runtime_config.timeout = timeout;
                return std::make_unique<acpp::proxy::vless::outbound::Handler>(
                    std::string(tag), runtime_config, dns);
            }};
    }), true);
}  // namespace
