#include "vless_inbound.hpp"
#include "../credentials.hpp"
#include "../../mux/inbound/mux_inbound.hpp"

#include "../vless_codec.hpp"
#include "../vless_encryption.hpp"
#include "../vless_encryption_io.hpp"
#include "../vless_encryption_runtime.hpp"
#include "../vless_io_util.hpp"
#include "../udp_framing.hpp"
#include "../vless_vision.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/address_codec.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/udp_types.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/initial_payload.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link.hpp"

#include <array>
#include <tl/expected.hpp>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>

namespace acpp {

namespace {

using ::acpp::vless::VlessBufferedReader;


class VlessUdpReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return src_.Cancellation(); }

    VlessUdpReader(transport::MultiBufferReader& src,
                   TargetAddress target,
                   bool packet_addr = false)
        : src_(src)
        , target_(std::move(target))
        , framer_(packet_addr) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (true) {
            ::acpp::vless::FramedUdpPacket packet;
            if (framer_.Next(packet)) {
                const TargetAddress& target = packet.target
                    ? *packet.target
                    : target_;
                for (buf::Buffer* buffer : packet.payload) {
                    if (buffer && !buffer->IsEmpty()) {
                        buffer->SetUDP(target);
                    }
                }
                co_return std::move(packet.payload);
            }

            buf::MultiBuffer raw = co_await src_.ReadMultiBuffer();
            if (!buf::HasData(raw)) {
                framer_.Finish();
                co_return buf::MultiBuffer{};
            }
            framer_.Feed(std::move(raw));
        }
    }

private:
    transport::MultiBufferReader& src_;
    TargetAddress target_;
    ::acpp::vless::UdpFramer framer_;
};

class VlessUdpWriter final : public transport::MultiBufferWriter {
public:
    explicit VlessUdpWriter(transport::MultiBufferWriter& dst,
                            bool packet_addr = false)
        : dst_(dst)
        , packet_addr_(packet_addr) {}

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        return ::acpp::vless::WriteUdpDatagram(
            dst_, std::move(mb), packet_addr_);
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (packet_addr_) {
            throw IoSystemError(
                io_error::invalid_argument,
                "packet-address VLESS UDP write requires a target");
        }
        return ::acpp::vless::WriteUdpDatagram(
            dst_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return dst_.AsyncShutdownWrite();
    }

private:
    transport::MultiBufferWriter& dst_;
    bool packet_addr_ = false;
};

class VlessResponseHeaderWriter final : public transport::MultiBufferWriter {
public:
    VlessResponseHeaderWriter(transport::MultiBufferWriter& dst,
                              std::span<const uint8_t> header)
        : dst_(&dst) {
        SetHeader(header);
    }

    VlessResponseHeaderWriter(AsyncStream& dst,
                              std::span<const uint8_t> header)
        : dst_(&dst) {
        SetHeader(header);
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (header_len_ > 0) {
            const size_t header_len = header_len_;
            std::array<net::const_buffer, 1 + buf::MultiBuffer::kInlineCapacity> stack_out{};
            memory::ThreadLocalVector<net::const_buffer> spill_out;
            const bool use_spill = mb.size() > buf::MultiBuffer::kInlineCapacity;
            size_t stack_count = 0;
            header_len_ = 0;

            auto append = [&](net::const_buffer buffer) {
                if (buffer.size() == 0) {
                    return;
                }
                if (use_spill) {
                    spill_out.push_back(buffer);
                    return;
                }
                stack_out[stack_count++] = buffer;
            };

            if (use_spill) {
                spill_out.reserve(mb.size() + 1);
            }
            append(net::const_buffer(header_.data(), header_len));
            for (const buf::Buffer* buffer : mb) {
                if (!buffer || buffer->IsEmpty()) {
                    continue;
                }
                const auto bytes = buffer->Bytes();
                append(net::const_buffer(bytes.data(), bytes.size()));
            }
            const auto out = use_spill
                ? std::span<const net::const_buffer>(spill_out.data(), spill_out.size())
                : std::span<const net::const_buffer>(stack_out.data(), stack_count);
            co_await dst_->WriteBuffers(out);
            mb.clear();
            co_return;
        }
        co_await dst_->WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (header_len_ > 0) {
            std::array<net::const_buffer, 1 + buf::MultiBuffer::kInlineCapacity> stack_out{};
            memory::ThreadLocalVector<net::const_buffer> spill_out;
            const bool use_spill = buffers.size() > buf::MultiBuffer::kInlineCapacity;
            size_t stack_count = 0;
            if (use_spill) {
                spill_out.reserve(buffers.size() + 1);
                spill_out.emplace_back(header_.data(), header_len_);
                for (const auto& buffer : buffers) {
                    if (buffer.size() > 0) {
                        spill_out.push_back(buffer);
                    }
                }
            } else {
                stack_out[stack_count++] = net::const_buffer(header_.data(), header_len_);
                for (const auto& buffer : buffers) {
                    if (buffer.size() > 0) {
                        stack_out[stack_count++] = buffer;
                    }
                }
            }
            header_len_ = 0;
            const auto out = use_spill
                ? std::span<const net::const_buffer>(spill_out.data(), spill_out.size())
                : std::span<const net::const_buffer>(stack_out.data(), stack_count);
            co_await dst_->WriteBuffers(out);
            co_return;
        }
        co_await dst_->WriteBuffers(buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (header_len_ > 0) {
            std::array<net::const_buffer, 1> out{
                net::const_buffer(header_.data(), header_len_)};
            header_len_ = 0;
            co_await dst_->WriteBuffers(out);
        }
        co_await dst_->AsyncShutdownWrite();
    }

private:
    void SetHeader(std::span<const uint8_t> header) {
        if (header.size() > header_.size()) {
            throw std::bad_alloc();
        }
        std::copy(header.begin(), header.end(), header_.begin());
        header_len_ = header.size();
    }

    transport::MultiBufferWriter* dst_ = nullptr;
    std::array<uint8_t, 16> header_{};
    size_t header_len_ = 0;
};


net::awaitable<tl::expected<::acpp::vless::RequestHeader, ErrorCode>>
ReadVlessRequestHeader(VlessBufferedReader& active_reader,
                       AsyncStream& stream,
                       session::Context& ctx,
                       std::string_view tag,
                       std::string_view client_ip) {
    std::array<uint8_t, 536> handshake{};
    size_t total_read = 0;

    auto read_exact = [&](size_t count) -> net::awaitable<tl::expected<void, ErrorCode>> {
        bool read_ok = false;
        try {
            read_ok = co_await active_reader.ReadExact(
                handshake.data() + total_read,
                count);
        } catch (const IoSystemError&) {
            if (stream.ConsumePhaseDeadline()) {
                LOG_CONN_WARN(ctx, "[VLESS][{}] handshake phase deadline from {}",
                              tag, client_ip);
                co_return tl::unexpected(ErrorCode::TIMEOUT);
            }
            co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
        }
        if (!read_ok && stream.ConsumePhaseDeadline()) {
            co_return tl::unexpected(ErrorCode::TIMEOUT);
        }
        if (!read_ok && stream.ConsumeIdleTimeout()) {
            co_return tl::unexpected(ErrorCode::TIMEOUT);
        }
        if (!read_ok) {
            co_return tl::unexpected(ErrorCode::SOCKET_EOF);
        }
        total_read += count;
        co_return tl::expected<void, ErrorCode>{};
    };

    if (auto ok = co_await read_exact(1); !ok) {
        co_return tl::unexpected(ok.error());
    }
    if (handshake[0] != ::acpp::vless::kVersion) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_VERSION);
    }

    if (auto ok = co_await read_exact(17); !ok) {
        co_return tl::unexpected(ok.error());
    }
    const uint8_t addons_len = handshake[17];
    if (auto ok = co_await read_exact(static_cast<size_t>(addons_len) + 1); !ok) {
        co_return tl::unexpected(ok.error());
    }

    const uint8_t cmd = handshake[18 + addons_len];
    if (cmd == static_cast<uint8_t>(::acpp::vless::Command::TCP) ||
        cmd == static_cast<uint8_t>(::acpp::vless::Command::UDP)) {
        const size_t address_offset = total_read;
        while (true) {
            auto address = DecodeAddress(
                std::span(handshake.data() + address_offset, total_read - address_offset),
                AddressWireFormat::PortFirst, {253, true});
            if (address.status == AddressDecodeStatus::Complete) break;
            if (address.status == AddressDecodeStatus::Invalid) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
            }
            if (auto ok = co_await read_exact(address.required - (total_read - address_offset)); !ok) {
                co_return tl::unexpected(ok.error());
            }
        }
    } else if (cmd != static_cast<uint8_t>(::acpp::vless::Command::MUX)) {
        LOG_NET_WARN("[VLESS][{}] parse failed from {}", tag, client_ip);
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    size_t consumed = 0;
    auto request = ::acpp::vless::Codec::ParseRequestHeader(
        handshake.data(),
        total_read,
        consumed);
    if (!request || consumed != total_read) {
        LOG_NET_WARN("[VLESS][{}] parse failed from {}", tag, client_ip);
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    co_return std::move(*request);
}
}  // namespace

proxy::vless::inbound::Handler::Handler(
    ::acpp::UserOnlineTracker& validator,
    StatsShard& stats,
    ConnectionLimiterPtr limiter,
    std::shared_ptr<const ::acpp::vless::VlessEncryptionConfig> decryption)
    : validator_(validator)
    , stats_(&stats)
    , limiter_(std::move(limiter))
    , decryption_(std::move(decryption)) {
    if (decryption_) {
        decryption_tickets_ = std::make_unique<
            ::acpp::vless::VlessEncryptionServerTicketStore>();
    }
}

proxy::vless::inbound::Handler::~Handler() = default;

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

    if (limiter_ && ctx.inbound.HasProxyProtocolClientIP() &&
        limiter_->IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_NET_DEBUG("{} from {}:{} rejected ip_banned [{}]",
            FormatTimestamp(ctx.accept_time_us),
            ctx.inbound.source_ip, ctx.inbound.source_port, ctx.inbound.tag);
        co_return fail_abortive(ErrorCode::BLOCKED);
    }

    std::optional<UserOnlineSessionGuard> user_session;
    std::optional<::acpp::vless::RequestHeader> request;
    VlessBufferedReader protocol_reader(*stream);
    transport::MultiBufferWriter* protocol_writer = stream.get();
    VlessBufferedReader* active_reader = &protocol_reader;
    transport::MultiBufferWriter* active_writer = protocol_writer;
    struct EncryptedIoState : memory::ThreadAllocated {
        std::optional<::acpp::vless::VlessEncryptionReader> reader;
        std::optional<::acpp::vless::VlessEncryptionWriter> writer;
        std::optional<VlessBufferedReader> plain_reader;
    };
    std::unique_ptr<EncryptedIoState> encrypted_io;

    if (decryption_) {
        try {
            auto runtime =
                co_await ::acpp::vless::RunVlessEncryptionServerHandshake(
                    protocol_reader,
                    *protocol_writer,
                    *decryption_,
                    decryption_tickets_.get());
            if (!runtime) {
                LOG_NET_WARN("[VLESS][{}] encryption handshake failed from {}",
                              tag, client_ip);
                co_return fail_abortive(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            encrypted_io = std::make_unique<EncryptedIoState>();
            if (runtime->read_aead_ready) {
                encrypted_io->reader.emplace(
                    protocol_reader,
                    std::move(runtime->read_aead),
                    runtime->united_key,
                    std::move(runtime->read_xor));
            } else {
                encrypted_io->reader.emplace(
                    ::acpp::vless::VlessEncryptionReader::CreateLazyReadContext(
                        protocol_reader,
                        runtime->lazy_read_context_size,
                        runtime->united_key,
                        runtime->cipher,
                        runtime->lazy_read_xor_from_context));
            }
            encrypted_io->writer.emplace(
                *protocol_writer,
                std::move(runtime->write_aead),
                std::move(runtime->united_key),
                std::move(runtime->write_xor));
            encrypted_io->plain_reader.emplace(*encrypted_io->reader);
            active_reader = std::addressof(*encrypted_io->plain_reader);
            active_writer = std::addressof(*encrypted_io->writer);
        } catch (const IoSystemError&) {
            co_return fail_abortive(stream->ConsumePhaseDeadline()
                ? ErrorCode::TIMEOUT
                : ErrorCode::SOCKET_READ_FAILED);
        } catch (...) {
            co_return fail_abortive(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
    }

    auto parsed_request = co_await ReadVlessRequestHeader(
        *active_reader, *stream, ctx, tag, client_ip);
    if (!parsed_request) {
        co_return fail_abortive(parsed_request.error());
    }
    request.emplace(std::move(*parsed_request));
    auto user_info = proxyman::inbound::UserStore::FindVlessUser(tag, request->uuid);
    if (!user_info) {
        LOG_NET_WARN("[VLESS][{}] auth failed from {}", tag, client_ip);
        if (limiter_ && ctx.inbound.HasProxyProtocolClientIP()) {
            limiter_->OnAuthFailTracked(tag, client_ip);
        }
        co_return fail_abortive(ErrorCode::PROTOCOL_AUTH_FAILED);
    }
    if (request->addons_len != 0 && request->flow.empty()) {
        LOG_NET_WARN("[VLESS][{}] unsupported request addons from {}", tag, client_ip);
        co_return fail_abortive(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    const bool use_vision = ::acpp::vless::IsVisionFlow(request->flow);
    if (!request->flow.empty()) {
        if (std::string_view(request->flow) != user_info->flow) {
            LOG_NET_WARN("[VLESS][{}] request flow '{}' not allowed for user",
                          tag, request->flow);
            co_return fail_abortive(ErrorCode::PROTOCOL_UNSUPPORTED);
        }
        if (!use_vision) {
            LOG_NET_WARN("[VLESS][{}] unknown request flow '{}'", tag, request->flow);
            co_return fail_abortive(ErrorCode::PROTOCOL_UNSUPPORTED);
        }
    }
    if (!user_info->flow.empty() && !::acpp::vless::IsVisionFlow(user_info->flow)) {
        LOG_NET_WARN("[VLESS][{}] unsupported flow '{}'", tag, user_info->flow);
        co_return fail_abortive(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    if (request->flow.empty() && ::acpp::vless::IsVisionFlow(user_info->flow)) {
        LOG_NET_WARN("[VLESS][{}] missing required flow '{}'", tag, user_info->flow);
        co_return fail_abortive(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    if (use_vision && request->command != ::acpp::vless::Command::TCP) {
        LOG_NET_WARN("[VLESS][{}] flow '{}' only supports TCP", tag, request->flow);
        co_return fail_abortive(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    if (use_vision &&
        (!receiver.stream_settings.IsTlsLike() ||
         receiver.stream_settings.network_mode != NetworkMode::Tcp)) {
        LOG_NET_WARN("[VLESS][{}] flow '{}' requires raw TCP TLS-like transport",
                      tag, request->flow);
        co_return fail_abortive(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    uint64_t tracked_uid = 0;
    {
        const auto& profile = user_info->profile;
        ctx.inbound.user_id = profile.user_id;
        ctx.inbound.user_email = profile.email;
        ctx.content.speed_limit = profile.speed_limit;
        tracked_uid = static_cast<uint64_t>(profile.user_id);
        if (!validator_.CanAcceptDevice(
                tag, tracked_uid, ctx.inbound.source_ip, profile.device_limit)) {
            LOG_NET_DEBUG("{} from {}:{} rejected device_limit [{}] user={} limit={} online_devices={}",
                FormatTimestamp(ctx.accept_time_us),
                ctx.inbound.source_ip, ctx.inbound.source_port, tag, ctx.inbound.user_email,
                profile.device_limit,
                validator_.OnlineDeviceCount(tag, tracked_uid));
            co_return fail_abortive(ErrorCode::PERMISSION_DENIED);
        }
    }

    // Flow validation and metadata copy are complete; no credential is needed
    // by the request body or Vision's per-session UUID state.
    user_info.reset();
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
        ::acpp::vless::IsPacketAddrMagic(request->target);
    const std::array<uint8_t, 16> request_uuid = request->uuid;
    ctx.outbound.original_target = request->target;
    ctx.outbound.target = std::move(request->target);
    ctx.content.network = net;
    request.reset();
    uint8_t response_header[2]{};
    const size_t response_len =
        ::acpp::vless::Codec::EncodeResponseHeaderTo(response_header, sizeof(response_header));
    if (response_len == 0) {
        co_return fail_abortive(ErrorCode::SOCKET_WRITE_FAILED);
    }
    std::optional<VlessResponseHeaderWriter> response_writer;
    if (active_writer == protocol_writer) {
        response_writer.emplace(
            *stream,
            std::span<const uint8_t>(response_header, response_len));
    } else {
        response_writer.emplace(
            *active_writer,
            std::span<const uint8_t>(response_header, response_len));
    }
    active_writer = &*response_writer;

    if (net == Network::MUX) {
        co_return co_await mux::ProcessInbound(
            io_context,
            transport::Link{active_reader, active_writer},
            *stream,
            dispatcher,
            receiver.dispatch_policy,
            ctx,
            *stats_,
            timeouts,
            pressure_idle_timeout);
    }

    if (net == Network::UDP) {
        VlessUdpReader udp_reader(
            *active_reader, ctx.outbound.target, packet_addr_udp);
        VlessUdpWriter udp_writer(*active_writer, packet_addr_udp);
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver.dispatch_policy,
            std::move(stream),
            transport::Link{&udp_reader, &udp_writer},
            InitialPayload{},
            ctx,
            *stats_,
            timeouts);
    }

    if (use_vision) {
        ::acpp::vless::VisionReader vision_reader(
            *active_reader,
            request_uuid,
            {});
        ::acpp::vless::VisionWriter vision_writer(*active_writer, request_uuid);
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver.dispatch_policy,
            std::move(stream),
            transport::Link{&vision_reader, &vision_writer},
            InitialPayload{},
            ctx,
            *stats_,
            timeouts);
    }

    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver.dispatch_policy,
        std::move(stream),
        transport::Link{active_reader, active_writer},
        InitialPayload{},
        ctx,
        *stats_,
        timeouts);
}

}  // namespace acpp

namespace {
class VlessRuntime final : public acpp::proxyman::inbound::ProtocolRuntime {
public:
    [[nodiscard]] std::vector<acpp::OnlineDevice>
    GetOnlineDevices(std::string_view tag) const override {
        return validator.GetOnlineDevices(tag);
    }

    acpp::UserOnlineTracker validator;
};

class VlessSettings final
    : public acpp::proxyman::inbound::ProtocolSettings {
public:
    std::shared_ptr<const acpp::vless::VlessEncryptionConfig> decryption;
};

[[nodiscard]] const VlessSettings* GetVlessSettings(
    const acpp::proxyman::inbound::BuildRequest& req) noexcept {
    return dynamic_cast<const VlessSettings*>(req.settings.get());
}

const bool kVlessInboundRegistered = [] {
    acpp::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = acpp::proxyman::inbound::UserProtocol::Vless;

    reg.create_runtime = []() -> std::unique_ptr<
        acpp::proxyman::inbound::ProtocolRuntime> {
        return std::make_unique<VlessRuntime>();
    };

    reg.create_tcp_handler =
        [](acpp::proxyman::inbound::ProtocolRuntime& runtime,
           acpp::StatsShard& stats,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::proxyman::inbound::BuildRequest& req)
            -> std::unique_ptr<acpp::Inbound> {
            auto* vless_runtime = dynamic_cast<VlessRuntime*>(&runtime);
            const auto* settings = GetVlessSettings(req);
            if (!vless_runtime || !settings) {
                return nullptr;
            }
            return std::make_unique<acpp::proxy::vless::inbound::Handler>(
                vless_runtime->validator,
                stats,
                limiter,
                settings->decryption);
        };

    reg.prepare_settings =
        [](std::string_view tag, const acpp::StaticUserConfig& config)
            -> std::optional<std::shared_ptr<
                const acpp::proxyman::inbound::ProtocolSettings>> {
            auto settings = std::make_shared<VlessSettings>();
            if (!acpp::vless::IsNoVlessEncryption(config.vless_decryption)) {
                auto parsed = acpp::vless::ParseVlessServerDecryption(
                    config.vless_decryption);
                if (!parsed) {
                    LOG_WARN("VLESS inbound '{}': invalid decryption: {}",
                             tag,
                             acpp::vless::VlessEncryptionParseErrorMessage(
                                 parsed.error));
                    return std::nullopt;
                }
                settings->decryption =
                    std::make_shared<acpp::vless::VlessEncryptionConfig>(
                        std::move(*parsed.config));
            }
            return settings;
        };

    reg.build_static_users =
        [](std::string_view tag, const acpp::StaticUserConfig& config)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            if (!acpp::vless::IsNoVlessEncryption(config.vless_decryption)) {
                auto parsed = acpp::vless::ParseVlessServerDecryption(
                    config.vless_decryption);
                if (!parsed) {
                    LOG_WARN("VLESS inbound '{}': invalid decryption: {}",
                             tag,
                             acpp::vless::VlessEncryptionParseErrorMessage(
                                 parsed.error));
                    return std::nullopt;
                }
            }
            std::vector<acpp::proxyman::inbound::PreparedVlessUser> users;
            users.reserve(config.clients.size());
            for (const auto& client : config.clients) {
                std::string uuid = client.id.empty() ? client.password : client.id;
                auto uuid_bytes = acpp::vless::ParseUuidBytes(uuid);
                if (!uuid_bytes) {
                    LOG_WARN("VLESS inbound '{}': invalid static user UUID", tag);
                    return std::nullopt;
                }
                acpp::proxyman::inbound::PreparedVlessUser info;
                info.uuid_bytes = *uuid_bytes;
                info.flow = acpp::vless::NormalizeFlow(client.flow);
                info.profile.email = client.email;
                users.push_back(std::move(info));
            }
            return acpp::proxyman::inbound::UserSet{std::move(users)};
        };

    reg.build_users =
        [](const acpp::proxyman::inbound::BuildRequest& /*req*/,
           std::span<const acpp::proxyman::inbound::RuntimeUser> runtime_users)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::proxyman::inbound::PreparedVlessUser> users;
            users.reserve(runtime_users.size());
            for (const auto& runtime_user : runtime_users) {
                const std::string& uuid = runtime_user.credential;
                auto uuid_bytes = acpp::vless::ParseUuidBytes(uuid);
                if (!uuid_bytes) {
                    return std::nullopt;
                }
                acpp::proxyman::inbound::PreparedVlessUser info;
                info.uuid_bytes = *uuid_bytes;
                info.flow = acpp::vless::NormalizeFlow(runtime_user.flow);
                info.profile.email = runtime_user.email;
                info.profile.user_id = runtime_user.user_id;
                info.profile.speed_limit = runtime_user.speed_limit;
                info.profile.device_limit = runtime_user.device_limit;
                users.push_back(std::move(info));
            }
            return acpp::proxyman::inbound::UserSet{std::move(users)};
        };

    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kVless, std::move(reg));
    return true;
}();
}  // namespace
