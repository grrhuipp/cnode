#include "vless_inbound.hpp"

#include "../vless_codec.hpp"
#include "../vless_encryption.hpp"
#include "../vless_encryption_io.hpp"
#include "../vless_encryption_runtime.hpp"
#include "../vless_io_util.hpp"
#include "../udp_framing.hpp"
#include "../vless_vision.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
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
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>

namespace acpp {

namespace {

using ::acpp::vless::VlessBufferedReader;

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

class VlessPendingReader final : public transport::MultiBufferReader {
public:
    VlessPendingReader(transport::MultiBufferReader& src,
                       std::span<const uint8_t> first_packet)
        : src_(src) {
        (void)buf::AppendSpanToMultiBuffer(first_packet, pending_);
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!buf::HasData(pending_)) {
            co_return co_await src_.ReadMultiBuffer();
        }

        co_return std::move(pending_);
    }

private:
    transport::MultiBufferReader& src_;
    buf::MultiBuffer pending_;
};

class VlessUdpReader final : public transport::MultiBufferReader {
public:
    VlessUdpReader(transport::MultiBufferReader& src,
                   TargetAddress target,
                   std::span<const uint8_t> first_packet,
                   bool packet_addr = false)
        : src_(src)
        , target_(std::move(target))
        , framer_(packet_addr) {
        if (!first_packet.empty()) {
            framer_.Feed(first_packet.data(), first_packet.size());
        }
    }

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
        co_await ::acpp::vless::WriteUdpDatagram(
            dst_, std::move(mb), packet_addr_);
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (packet_addr_) {
            throw IoSystemError(
                io_error::invalid_argument,
                "packet-address VLESS UDP write requires a target");
        }
        co_await ::acpp::vless::WriteUdpDatagram(
            dst_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        co_await dst_.AsyncShutdownWrite();
        co_return;
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

}  // namespace

proxy::vless::inbound::Handler::Handler(
    ::acpp::vless::Validator& validator,
    StatsShard& stats,
    ConnectionLimiterPtr limiter,
    std::string vless_decryption)
    : validator_(validator)
    , stats_(&stats)
    , limiter_(std::move(limiter)) {
    if (!::acpp::vless::IsNoVlessEncryption(vless_decryption)) {
        auto parsed =
            ::acpp::vless::ParseVlessServerDecryption(vless_decryption);
        if (parsed) {
            decryption_ =
                std::make_shared<::acpp::vless::VlessEncryptionConfig>(
                    std::move(*parsed.config));
            decryption_tickets_ = std::make_unique<
                ::acpp::vless::VlessEncryptionServerTicketStore>();
        } else {
            LOG_WARN("VLESS inbound decryption ignored '{}': {}",
                     vless_decryption,
                     ::acpp::vless::VlessEncryptionParseErrorMessage(
                         parsed.error));
        }
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
    const TimeoutsConfig& timeouts) {
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
        LOG_ACCESS_DEBUG("{} from {}:{} rejected ip_banned [{}]",
            FormatTimestamp(ctx.accept_time_us),
            ctx.inbound.source_ip, ctx.inbound.source_port, ctx.inbound.tag);
        co_return fail_abortive(ErrorCode::BLOCKED);
    }

    std::optional<VlessOnlineSession> user_session;
    std::array<uint8_t, 1024> handshake{};
    size_t total_read = 0;
    size_t consumed = 0;
    std::optional<::acpp::vless::RequestHeader> request;
    VlessBufferedReader protocol_reader(*stream);
    transport::MultiBufferWriter* protocol_writer = stream.get();
    VlessBufferedReader* active_reader = &protocol_reader;
    transport::MultiBufferWriter* active_writer = protocol_writer;
    std::optional<::acpp::vless::VlessEncryptionReader> encrypted_reader;
    std::optional<::acpp::vless::VlessEncryptionWriter> encrypted_writer;
    std::optional<VlessBufferedReader> encrypted_plain_reader;

    if (decryption_) {
        try {
            auto runtime =
                co_await ::acpp::vless::RunVlessEncryptionServerHandshake(
                    protocol_reader,
                    *protocol_writer,
                    *decryption_,
                    decryption_tickets_.get());
            if (!runtime) {
                LOG_CONN_FAIL("[VLESS][{}] encryption handshake failed from {}",
                              tag, client_ip);
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
            co_return fail_abortive(stream->ConsumePhaseDeadline()
                ? ErrorCode::TIMEOUT
                : ErrorCode::SOCKET_READ_FAILED);
        } catch (...) {
            co_return fail_abortive(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
    }

    while (!request && total_read < handshake.size()) {
        bool read_ok = false;
        try {
            read_ok = co_await active_reader->ReadExact(
                handshake.data() + total_read,
                1);
        } catch (const IoSystemError&) {
            if (stream->ConsumePhaseDeadline()) {
                LOG_CONN_FAIL_CTX(ctx, "[VLESS][{}] handshake phase deadline from {}",
                                  tag, client_ip);
                co_return fail_abortive(ErrorCode::TIMEOUT);
            }
            co_return fail_abortive(ErrorCode::SOCKET_READ_FAILED);
        }
        if (!read_ok && stream->ConsumePhaseDeadline()) {
            co_return fail_abortive(ErrorCode::TIMEOUT);
        }
        if (!read_ok && stream->ConsumeIdleTimeout()) {
            co_return fail_abortive(ErrorCode::TIMEOUT);
        }
        if (!read_ok) {
            co_return fail_abortive(ErrorCode::SOCKET_EOF);
        }
        ++total_read;
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
        if (limiter_) {
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
    if (use_vision &&
        (!receiver.stream_settings.IsTlsLike() ||
         receiver.stream_settings.network_mode != NetworkMode::Tcp)) {
        LOG_CONN_FAIL("[VLESS][{}] flow '{}' requires raw TCP TLS-like transport",
                      tag, request->flow);
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
            LOG_ACCESS_DEBUG("{} from {}:{} rejected device_limit [{}] user={} limit={} online_devices={}",
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
        ::acpp::vless::IsPacketAddrMagic(request->target);
    ctx.outbound.original_target = request->target;
    ctx.outbound.target = std::move(request->target);
    ctx.content.network = net;

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

    std::span<const uint8_t> leftover;
    if (consumed < total_read) {
        leftover = std::span<const uint8_t>(
            handshake.data() + consumed,
            total_read - consumed);
    }

    if (net == Network::MUX) {
        VlessPendingReader mux_reader(*active_reader, leftover);
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver,
            std::move(stream),
            transport::Link{&mux_reader, active_writer},
            InitialPayload{},
            ctx,
            *stats_,
            timeouts);
    }

    if (net == Network::UDP) {
        VlessUdpReader udp_reader(
            *active_reader, ctx.outbound.target, leftover, packet_addr_udp);
        VlessUdpWriter udp_writer(*active_writer, packet_addr_udp);
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver,
            std::move(stream),
            transport::Link{&udp_reader, &udp_writer},
            InitialPayload{},
            ctx,
            *stats_,
            timeouts);
    }

    InitialPayload first_packet;
    if (!leftover.empty()) {
        first_packet.assign(leftover.begin(), leftover.end());
    }

    if (use_vision) {
        ::acpp::vless::VisionReader vision_reader(
            *active_reader,
            request->uuid,
            leftover);
        ::acpp::vless::VisionWriter vision_writer(*active_writer, request->uuid);
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver,
            std::move(stream),
            transport::Link{&vision_reader, &vision_writer},
            InitialPayload{},
            ctx,
            *stats_,
            timeouts);
    }

    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver,
        std::move(stream),
        transport::Link{active_reader, active_writer},
        std::move(first_packet),
        ctx,
        *stats_,
        timeouts);
}

}  // namespace acpp

namespace {
const bool kVlessInboundRegistered = [] {
    acpp::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = acpp::proxyman::inbound::UserProtocol::Vless;

    reg.create_runtime = []() -> std::unique_ptr<
        acpp::proxyman::inbound::ProtocolRuntime> {
        return std::make_unique<acpp::proxyman::inbound::ValidatorProtocolRuntime<
            acpp::vless::Validator>>();
    };

    reg.create_tcp_handler =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::proxyman::inbound::BuildRequest& req)
            -> std::unique_ptr<acpp::Inbound> {
            auto* validator = deps.ValidatorAs<acpp::vless::Validator>();
            if (!validator || !deps.stats) {
                return nullptr;
            }
            return std::make_unique<acpp::proxy::vless::inbound::Handler>(
                *validator,
                *deps.stats,
                limiter,
                req.vless_decryption);
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
                info.uuid = std::move(uuid);
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
            return acpp::proxyman::inbound::UserSet{std::move(users)};
        };

    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kVless, std::move(reg));
    return true;
}();
}  // namespace
