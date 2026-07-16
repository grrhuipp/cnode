#include "acppnode/proxy/anytls/inbound/anytls_inbound.hpp"

#include "../anytls_codec.hpp"
#include "../../uot/uot.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/byte_reader.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/proxy/anytls/validator.hpp"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/channel.hpp>
#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace acpp::proxy::anytls::inbound {

// 协议核心 codec/validator 位于 acpp::anytls（对应 vmess core=acpp::vmess）。
// 迁移到 acpp::proxy::anytls::inbound 后，别名让既有的 anytls::* 限定引用、
// using-directive 让非限定 codec 符号（ParsePaddingScheme/Validator 等）
// 继续解析到核心命名空间，无需逐处改写。
namespace anytls = ::acpp::anytls;
using namespace ::acpp::anytls;

namespace {

constexpr size_t kMaxSubStreamQueuedPayloadBytes = anytls::kMaxFramePayload;
constexpr size_t kSubStreamQueueShrinkItems = 64;

class AnyTLSOnlineSession {
public:
    AnyTLSOnlineSession(Validator& validator,
                        std::string_view tag,
                        uint64_t user_id,
                        std::string_view client_ip)
        : validator_(&validator)
        , tag_(tag)
        , user_id_(user_id)
        , client_ip_(client_ip) {}

    ~AnyTLSOnlineSession() noexcept {
        if (!validator_ || user_id_ == 0) {
            return;
        }
        try {
            validator_->OnUserDisconnected(tag_, user_id_, client_ip_);
        } catch (...) {}
    }

    AnyTLSOnlineSession(const AnyTLSOnlineSession&) = delete;
    AnyTLSOnlineSession& operator=(const AnyTLSOnlineSession&) = delete;
    AnyTLSOnlineSession(AnyTLSOnlineSession&&) = delete;
    AnyTLSOnlineSession& operator=(AnyTLSOnlineSession&&) = delete;

private:
    Validator* validator_;
    std::string tag_;
    uint64_t user_id_;
    std::string client_ip_;
};

void CopySessionContext(const session::Context& source, session::Context& target) {
    target.conn_id = session::NewID(source.worker_id);
    target.inbound = source.inbound;
    target.outbound = source.outbound;
    target.outbounds = source.outbounds;
    target.content = source.content;
    target.traffic = {};
    target.sockopt = source.sockopt;
    target.accept_time_us = source.accept_time_us;
    target.worker_id = source.worker_id;
}

}  // namespace

Handler::Handler(Validator& validator,
                 StatsShard& stats,
                 ConnectionLimiterPtr limiter,
                 std::string padding_scheme)
    : validator_(validator)
    , stats_(&stats)
    , limiter_(limiter)
{
    if (!padding_scheme.empty()) {
        auto parsed = anytls::ParsePaddingScheme(padding_scheme);
        if (parsed) {
            padding_scheme_raw_ = std::move(parsed->raw);
            padding_scheme_md5_ = std::move(parsed->md5);
        }
    }
}

namespace {

std::string ParseSettingsPaddingMd5(std::string_view text) {
    while (!text.empty()) {
        const auto line_end = text.find('\n');
        auto line = line_end == std::string_view::npos ? text : text.substr(0, line_end);
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
        constexpr std::string_view kPrefix = "padding-md5=";
        if (line.starts_with(kPrefix)) {
            return std::string(line.substr(kPrefix.size()));
        }
        if (line_end == std::string_view::npos) {
            break;
        }
        text.remove_prefix(line_end + 1);
    }
    return {};
}

std::optional<TargetAddress> ParseSocksAddress(std::span<const uint8_t> data) {
    if (data.empty()) {
        return std::nullopt;
    }
    ByteReader reader(data.data(), data.size());
    const uint8_t atype = reader.ReadU8();
    if (atype == 0x01) {
        auto raw = reader.ReadBytes(4);
        const uint16_t port = reader.ReadU16BE();
        if (!reader.Ok()) {
            return std::nullopt;
        }
        net::ip::address_v4::bytes_type bytes{};
        std::copy(raw.begin(), raw.end(), bytes.begin());
        return TargetAddress(net::ip::make_address_v4(bytes), port);
    }
    if (atype == 0x04) {
        auto raw = reader.ReadBytes(16);
        const uint16_t port = reader.ReadU16BE();
        if (!reader.Ok()) {
            return std::nullopt;
        }
        net::ip::address_v6::bytes_type bytes{};
        std::copy(raw.begin(), raw.end(), bytes.begin());
        return TargetAddress(net::ip::make_address_v6(bytes), port);
    }
    if (atype == 0x03) {
        const uint8_t len = reader.ReadU8();
        auto host = reader.ReadStringView(len);
        const uint16_t port = reader.ReadU16BE();
        if (!reader.Ok() || len == 0) {
            return std::nullopt;
        }
        return TargetAddress(host, port);
    }
    return std::nullopt;
}

class MultiBufferByteReader {
public:
    MultiBufferByteReader(const buf::MultiBuffer& data, size_t size) noexcept
        : data_(data), size_(size) {}

    [[nodiscard]] bool Ok() const noexcept { return !error_; }

    [[nodiscard]] uint8_t ReadU8() noexcept {
        uint8_t out = 0;
        if (!ReadBytes(std::span<uint8_t>(&out, 1))) {
            return 0;
        }
        return out;
    }

    [[nodiscard]] uint16_t ReadU16BE() noexcept {
        std::array<uint8_t, 2> bytes{};
        if (!ReadBytes(bytes)) {
            return 0;
        }
        return static_cast<uint16_t>(
            (static_cast<uint16_t>(bytes[0]) << 8) |
            static_cast<uint16_t>(bytes[1]));
    }

    [[nodiscard]] std::string ReadString(size_t len) {
        std::string out(len, '\0');
        if (len == 0) {
            return out;
        }
        if (!ReadBytes(std::span<uint8_t>(
                reinterpret_cast<uint8_t*>(out.data()), out.size()))) {
            return {};
        }
        return out;
    }

    [[nodiscard]] bool ReadBytes(std::span<uint8_t> out) noexcept {
        if (error_ || pos_ + out.size() > size_) {
            error_ = true;
            return false;
        }
        size_t skip = pos_;
        size_t copied = 0;
        for (const auto* buffer : data_) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            if (skip >= bytes.size()) {
                skip -= bytes.size();
                continue;
            }
            const size_t n = std::min(bytes.size() - skip, out.size() - copied);
            std::memcpy(out.data() + copied, bytes.data() + skip, n);
            copied += n;
            if (copied == out.size()) {
                pos_ += out.size();
                return true;
            }
            skip = 0;
        }
        error_ = true;
        return false;
    }

private:
    const buf::MultiBuffer& data_;
    size_t size_ = 0;
    size_t pos_ = 0;
    bool error_ = false;
};

std::optional<TargetAddress> ParseSocksAddress(const buf::MultiBuffer& data, size_t size) {
    MultiBufferByteReader reader(data, size);
    const uint8_t atype = reader.ReadU8();
    if (atype == 0x01) {
        net::ip::address_v4::bytes_type bytes{};
        const uint16_t port = [&]() {
            (void)reader.ReadBytes(std::span<uint8_t>(bytes.data(), bytes.size()));
            return reader.ReadU16BE();
        }();
        if (!reader.Ok()) {
            return std::nullopt;
        }
        return TargetAddress(net::ip::make_address_v4(bytes), port);
    }
    if (atype == 0x04) {
        net::ip::address_v6::bytes_type bytes{};
        const uint16_t port = [&]() {
            (void)reader.ReadBytes(std::span<uint8_t>(bytes.data(), bytes.size()));
            return reader.ReadU16BE();
        }();
        if (!reader.Ok()) {
            return std::nullopt;
        }
        return TargetAddress(net::ip::make_address_v6(bytes), port);
    }
    if (atype == 0x03) {
        const uint8_t len = reader.ReadU8();
        std::string host = reader.ReadString(len);
        const uint16_t port = reader.ReadU16BE();
        if (!reader.Ok() || len == 0) {
            return std::nullopt;
        }
        return TargetAddress(std::string_view(host), port);
    }
    return std::nullopt;
}

class AnyTLSDemuxSession;

class AnyTLSSubStream final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter
    , public std::enable_shared_from_this<AnyTLSSubStream> {
public:
    AnyTLSSubStream(net::io_context& io_context,
                    std::shared_ptr<AnyTLSDemuxSession> session,
                    uint32_t sid)
        : io_context_(io_context)
        , input_signal_(io_context, 1)
        , input_space_signal_(io_context, 1)
        , session_(std::move(session))
        , sid_(sid) {}

    ~AnyTLSSubStream() noexcept override {
        Cancel();
    }

    AnyTLSSubStream(const AnyTLSSubStream&) = delete;
    AnyTLSSubStream& operator=(const AnyTLSSubStream&) = delete;

    [[nodiscard]] uint32_t Sid() const noexcept {
        return sid_;
    }

    net::awaitable<bool> PushInput(buf::MultiBuffer mb) {
        const size_t bytes = buf::TotalLen(mb);
        co_return co_await PushInput(std::move(mb), bytes);
    }

    net::awaitable<bool> PushInput(buf::MultiBuffer mb, size_t bytes) {
        if (cancelled_ || input_done_) {
            mb.clear();
            co_return false;
        }
        if (bytes == 0) {
            mb.clear();
            co_return true;
        }
        if (bytes > kMaxSubStreamQueuedPayloadBytes) {
            mb.clear();
            co_return false;
        }
        while (!cancelled_ &&
               !input_done_ &&
               queued_bytes_ + bytes > kMaxSubStreamQueuedPayloadBytes) {
            auto [ec] = co_await input_space_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                mb.clear();
                co_return false;
            }
        }
        if (cancelled_ || input_done_) {
            mb.clear();
            co_return false;
        }
        input_queue_.push_back(QueuedInput{std::move(mb), bytes});
        queued_bytes_ += bytes;
        if (input_queue_.size() >= kSubStreamQueueShrinkItems) {
            shrink_queue_on_drain_ = true;
        }
        WakeInputReader();
        co_return true;
    }

    void CloseInput() {
        if (input_done_) {
            return;
        }
        input_done_ = true;
        WakeInputReader();
    }

    void Cancel() noexcept {
        if (cancelled_) {
            return;
        }
        cancelled_ = true;
        input_done_ = true;
        input_queue_.clear();
        queued_bytes_ = 0;
        shrink_queue_on_drain_ = false;
        WakeInputReader();
        WakeInputWriter();
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (!cancelled_) {
            if (!input_queue_.empty()) {
                QueuedInput input = std::move(input_queue_.front());
                queued_bytes_ -= std::min(queued_bytes_, input.bytes);
                input_queue_.pop_front();
                ShrinkQueueIfDrained();
                WakeInputWriter();
                co_return std::move(input.payload);
            }
            if (input_done_) {
                co_return buf::MultiBuffer{};
            }
            auto [ec] = co_await input_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                co_return buf::MultiBuffer{};
            }
        }
        co_return buf::MultiBuffer{};
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;

private:
    void WakeInputReader() noexcept {
        if (io_context_.stopped()) {
            return;
        }
        (void)input_signal_.try_send(IoErrorCode{});
    }

    void WakeInputWriter() noexcept {
        if (io_context_.stopped()) {
            return;
        }
        (void)input_space_signal_.try_send(IoErrorCode{});
    }

    void ShrinkQueueIfDrained() noexcept {
        if (input_queue_.empty() && shrink_queue_on_drain_) {
            TryShrinkSequence(input_queue_);
            shrink_queue_on_drain_ = false;
        }
    }

    net::io_context& io_context_;
    net::experimental::channel<void(IoErrorCode)> input_signal_;
    net::experimental::channel<void(IoErrorCode)> input_space_signal_;
    std::shared_ptr<AnyTLSDemuxSession> session_;
    uint32_t sid_ = 0;
    struct QueuedInput {
        buf::MultiBuffer payload;
        size_t bytes = 0;
    };
    memory::ThreadLocalDeque<QueuedInput> input_queue_;
    size_t queued_bytes_ = 0;
    bool shrink_queue_on_drain_ = false;
    bool input_done_ = false;
    bool cancelled_ = false;
};

class AnyTLSDemuxSession final : public std::enable_shared_from_this<AnyTLSDemuxSession> {
public:
    AnyTLSDemuxSession(std::unique_ptr<AsyncStream> stream,
                       routing::Dispatcher& dispatcher,
                       const proxyman::inbound::ReceiverSettings& receiver,
                       net::io_context& io_context,
                       const session::Context& base_ctx,
                       StatsShard& stats,
                       const TimeoutsConfig& timeouts,
                       uint32_t pressure_idle_timeout,
                       std::string padding_scheme_raw,
                       std::string padding_scheme_md5)
        : stream_(std::move(stream))
        , dispatcher_(dispatcher)
        , receiver_(receiver)
        , io_context_(io_context)
        , stats_(stats)
        , timeouts_(timeouts)
        , pressure_idle_timeout_(pressure_idle_timeout)
        , padding_scheme_raw_(std::move(padding_scheme_raw))
        , padding_scheme_md5_(std::move(padding_scheme_md5))
        , write_signal_(io_context, 1) {
        CopySessionContext(base_ctx, base_ctx_);
    }

    ~AnyTLSDemuxSession() noexcept {
        CancelAll();
    }

    AnyTLSDemuxSession(const AnyTLSDemuxSession&) = delete;
    AnyTLSDemuxSession& operator=(const AnyTLSDemuxSession&) = delete;

    net::awaitable<RelayResult> Run();

    net::awaitable<std::expected<void, ErrorCode>>
    WriteFrameSerialized(uint8_t cmd, uint32_t sid, std::span<const uint8_t> payload) {
        while (write_busy_ && !cancelled_) {
            auto [ec] = co_await write_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                co_return std::unexpected(ErrorCode::CANCELLED);
            }
        }
        if (cancelled_ || !stream_) {
            co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
        }

        write_busy_ = true;
        auto guard = std::unique_ptr<void, void(*)(void*)>{
            this,
            [](void* p) {
                auto* self = static_cast<AnyTLSDemuxSession*>(p);
                self->write_busy_ = false;
                self->WakeWriter();
            }};
        (void)guard;

        co_return co_await anytls::WriteFrame(*stream_, cmd, sid, payload);
    }

    net::awaitable<std::expected<void, ErrorCode>>
    WriteMultiBufferSerialized(uint8_t cmd, uint32_t sid, buf::MultiBuffer mb) {
        while (write_busy_ && !cancelled_) {
            auto [ec] = co_await write_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                mb.clear();
                co_return std::unexpected(ErrorCode::CANCELLED);
            }
        }
        if (cancelled_ || !stream_) {
            mb.clear();
            co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
        }

        write_busy_ = true;
        auto guard = std::unique_ptr<void, void(*)(void*)>{
            this,
            [](void* p) {
                auto* self = static_cast<AnyTLSDemuxSession*>(p);
                self->write_busy_ = false;
                self->WakeWriter();
            }};
        (void)guard;

        co_return co_await anytls::WriteMultiBufferAsFrameBatch(
            *stream_, cmd, sid, std::move(mb));
    }

    net::awaitable<std::expected<void, ErrorCode>>
    WriteBuffersSerialized(uint8_t cmd,
                           uint32_t sid,
                           std::span<const net::const_buffer> buffers) {
        bool has_data = false;
        for (const net::const_buffer& buffer : buffers) {
            if (buffer.data() && buffer.size() > 0) {
                has_data = true;
                break;
            }
        }
        if (!has_data) {
            co_return std::expected<void, ErrorCode>{};
        }

        while (write_busy_ && !cancelled_) {
            auto [ec] = co_await write_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                co_return std::unexpected(ErrorCode::CANCELLED);
            }
        }
        if (cancelled_ || !stream_) {
            co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
        }

        write_busy_ = true;
        auto guard = std::unique_ptr<void, void(*)(void*)>{
            this,
            [](void* p) {
                auto* self = static_cast<AnyTLSDemuxSession*>(p);
                self->write_busy_ = false;
                self->WakeWriter();
            }};
        (void)guard;

        const PaddingScheme no_padding;
        co_return co_await anytls::WriteBuffersAsFramesWithPadding(
            *stream_, no_padding, 0, cmd, sid, buffers);
    }

    void RemoveStream(uint32_t sid) {
        auto it = streams_.find(sid);
        if (it == streams_.end()) {
            return;
        }
        it->second->Cancel();
        streams_.erase(it);
        stream_states_.erase(sid);
    }

private:
    enum class StreamState {
        PendingTarget,
        PendingUotRequest,
        Started,
    };

    std::shared_ptr<AnyTLSSubStream> GetOrCreateStream(uint32_t sid) {
        auto it = streams_.find(sid);
        if (it != streams_.end()) {
            return it->second;
        }
        auto sub = std::make_shared<AnyTLSSubStream>(io_context_, shared_from_this(), sid);
        streams_.emplace(sid, sub);
        return sub;
    }

    void CancelAll() noexcept {
        if (cancelled_) {
            return;
        }
        cancelled_ = true;
        WakeWriter();
        for (auto& [sid, sub] : streams_) {
            (void)sid;
            if (sub) {
                sub->Cancel();
            }
        }
        streams_.clear();
        if (stream_) {
            stream_->CloseAbortive();
        }
    }

    void WakeWriter() noexcept {
        if (io_context_.stopped()) {
            return;
        }
        (void)write_signal_.try_send(IoErrorCode{});
    }

    net::awaitable<void> StartDispatch(
        std::shared_ptr<AnyTLSSubStream> sub,
        TargetAddress target,
        buf::MultiBuffer initial_uot_payload,
        std::optional<proxy::uot::Version> uot_version);

    std::unique_ptr<AsyncStream> stream_;
    routing::Dispatcher& dispatcher_;
    const proxyman::inbound::ReceiverSettings& receiver_;
    net::io_context& io_context_;
    session::Context base_ctx_;
    StatsShard& stats_;
    TimeoutsConfig timeouts_;
    uint32_t pressure_idle_timeout_ = 0;
    std::string padding_scheme_raw_;
    std::string padding_scheme_md5_;
    net::experimental::channel<void(IoErrorCode)> write_signal_;
    memory::ThreadLocalUnorderedMap<uint32_t, std::shared_ptr<AnyTLSSubStream>>
        streams_;
    memory::ThreadLocalUnorderedMap<uint32_t, StreamState> stream_states_;
    bool write_busy_ = false;
    bool cancelled_ = false;
    bool handshake_done_ = false;
};

net::awaitable<void> AnyTLSSubStream::WriteMultiBuffer(buf::MultiBuffer mb) {
    auto session = session_;
    if (!session) {
        mb.clear();
        co_return;
    }
    auto ok = co_await session->WriteMultiBufferSerialized(anytls::kCmdPSH, sid_, std::move(mb));
    if (!ok) {
        throw IoSystemError(make_error_code(std::errc::io_error));
    }
}

net::awaitable<void> AnyTLSSubStream::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    auto session = session_;
    if (!session) {
        co_return;
    }
    auto ok = co_await session->WriteBuffersSerialized(anytls::kCmdPSH, sid_, buffers);
    if (!ok) {
        throw IoSystemError(make_error_code(std::errc::io_error));
    }
}

net::awaitable<void> AnyTLSSubStream::AsyncShutdownWrite() {
    auto session = session_;
    if (session) {
        (void)co_await session->WriteFrameSerialized(anytls::kCmdFIN, sid_, {});
    }
}

net::awaitable<void> AnyTLSDemuxSession::StartDispatch(
    std::shared_ptr<AnyTLSSubStream> sub,
    TargetAddress target,
    buf::MultiBuffer initial_uot_payload,
    std::optional<proxy::uot::Version> uot_version) {
    if (!sub) {
        co_return;
    }

    bool is_connect = false;
    std::optional<proxy::uot::PacketReader> uot_reader;
    std::optional<proxy::uot::PacketWriter> uot_writer;
    if (uot_version) {
        if (*uot_version == proxy::uot::Version::V2) {
            auto request = co_await proxy::uot::ReadRequest(
                *sub, initial_uot_payload);
            if (!request || !request->destination.IsValid()) {
                RemoveStream(sub->Sid());
                co_return;
            }
            is_connect = request->is_connect;
            target = std::move(request->destination);
        }

        uot_reader.emplace(
            *sub, is_connect, target, std::move(initial_uot_payload));
        if (*uot_version == proxy::uot::Version::V1) {
            try {
                auto first_packet = co_await uot_reader->ReadMultiBuffer();
                if (!buf::HasData(first_packet)) {
                    RemoveStream(sub->Sid());
                    co_return;
                }
                for (const buf::Buffer* buffer : first_packet) {
                    if (buffer && buffer->HasUDP()) {
                        target = buffer->UDP();
                        break;
                    }
                }
                if (!target.IsValid()) {
                    RemoveStream(sub->Sid());
                    co_return;
                }
                uot_reader->SetInitialDecoded(std::move(first_packet));
            } catch (...) {
                RemoveStream(sub->Sid());
                co_return;
            }
        }
        uot_writer.emplace(*sub, is_connect, target);
    }

    session::Context ctx;
    CopySessionContext(base_ctx_, ctx);
    ctx.outbound.original_target = target;
    ctx.outbound.target = target;
    ctx.outbound.route_target = target;
    ctx.content.network = uot_version ? Network::UDP : Network::TCP;

    RelayResult result;
    if (uot_version) {
        result = co_await dispatcher_.Dispatch(
            io_context_,
            receiver_,
            nullptr,
            transport::Link{std::addressof(*uot_reader), std::addressof(*uot_writer)},
            InitialPayload{},
            ctx,
            stats_,
            timeouts_,
            pressure_idle_timeout_);
    } else {
        result = co_await dispatcher_.Dispatch(
            io_context_,
            receiver_,
            nullptr,
            transport::Link{sub.get(), sub.get()},
            InitialPayload{},
            ctx,
            stats_,
            timeouts_,
            pressure_idle_timeout_);
    }
    (void)result;
    RemoveStream(sub->Sid());
}

net::awaitable<RelayResult> AnyTLSDemuxSession::Run() {
    RelayResult result;
    while (!cancelled_) {
        auto header = co_await anytls::ReadFrameHeader(*stream_);
        if (!header) {
            result.error = header.error();
            break;
        }

        if (header->cmd == anytls::kCmdSettings) {
            std::string client_padding_md5;
            if (header->length > 0) {
                auto settings_text = co_await anytls::ReadFrameText(*stream_, header->length);
                if (!settings_text) {
                    result.error = settings_text.error();
                    break;
                }
                client_padding_md5 = ParseSettingsPaddingMd5(*settings_text);
            }
            if (auto ok = co_await WriteFrameSerialized(
                    anytls::kCmdServerSettings,
                    0,
                    std::span<const uint8_t>(
                        reinterpret_cast<const uint8_t*>("v=2"),
                        3)); !ok) {
                result.error = ok.error();
                break;
            }
            if (!padding_scheme_raw_.empty() &&
                !client_padding_md5.empty() &&
                client_padding_md5 != padding_scheme_md5_) {
                if (auto ok = co_await WriteFrameSerialized(
                        anytls::kCmdUpdatePaddingScheme,
                        0,
                        std::span<const uint8_t>(
                            reinterpret_cast<const uint8_t*>(padding_scheme_raw_.data()),
                            padding_scheme_raw_.size())); !ok) {
                    result.error = ok.error();
                    break;
                }
            }
            handshake_done_ = true;
            continue;
        }
        if (header->cmd == anytls::kCmdWaste ||
            header->cmd == anytls::kCmdHeartResponse ||
            header->cmd == anytls::kCmdServerSettings ||
            header->cmd == anytls::kCmdUpdatePaddingScheme) {
            if (auto ok = co_await anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = ok.error();
                break;
            }
            continue;
        }
        if (header->cmd == anytls::kCmdHeartRequest) {
            if (auto ok = co_await anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = ok.error();
                break;
            }
            if (auto ok = co_await WriteFrameSerialized(anytls::kCmdHeartResponse, 0, {}); !ok) {
                result.error = ok.error();
                break;
            }
            continue;
        }

        if (header->sid == 0) {
            if (auto ok = co_await anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = ok.error();
                break;
            }
            result.error = ErrorCode::PROTOCOL_INVALID_COMMAND;
            break;
        }

        const uint32_t sid = header->sid;
        if (header->cmd == anytls::kCmdSYN) {
            if (!handshake_done_) {
                static constexpr std::string_view kAlert = "client did not send its settings";
                (void)co_await WriteFrameSerialized(
                    anytls::kCmdAlert,
                    0,
                    std::span<const uint8_t>(
                        reinterpret_cast<const uint8_t*>(kAlert.data()),
                        kAlert.size()));
                if (auto ok = co_await anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                    result.error = ok.error();
                    break;
                }
                result.error = ErrorCode::PROTOCOL_INVALID_COMMAND;
                break;
            }
            auto sub = GetOrCreateStream(sid);
            stream_states_[sid] = StreamState::PendingTarget;
            if (auto ok = co_await anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = ok.error();
                break;
            }
            continue;
        }

        auto state_it = stream_states_.find(sid);
        if (state_it == stream_states_.end()) {
            if (auto ok = co_await anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = ok.error();
                break;
            }
            continue;
        }
        auto sub = GetOrCreateStream(sid);

        if (header->cmd == anytls::kCmdFIN) {
            if (auto ok = co_await anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = ok.error();
                break;
            }
            sub->CloseInput();
            continue;
        }

        if (header->cmd != anytls::kCmdPSH) {
            if (auto ok = co_await anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = ok.error();
                break;
            }
            result.error = ErrorCode::PROTOCOL_INVALID_COMMAND;
            break;
        }

        auto payload = co_await anytls::ReadFramePayload(*stream_, header->length);
        if (!payload) {
            result.error = payload.error();
            break;
        }

        switch (state_it->second) {
            case StreamState::PendingTarget: {
                auto target = ParseSocksAddress(*payload, header->length);
                payload->clear();
                if (!target) {
                    result.error = ErrorCode::PROTOCOL_INVALID_ADDRESS;
                    CancelAll();
                    co_return result;
                }
                if (auto ok = co_await WriteFrameSerialized(anytls::kCmdSYNACK, sid, {}); !ok) {
                    result.error = ok.error();
                    CancelAll();
                    co_return result;
                }
                if (const auto uot_version =
                        proxy::uot::VersionFromMagicAddress(*target)) {
                    if (*uot_version == proxy::uot::Version::V2) {
                        state_it->second = StreamState::PendingUotRequest;
                        break;
                    }
                    state_it->second = StreamState::Started;
                    auto self = shared_from_this();
                    net::co_spawn(
                        io_context_.get_executor(),
                        [self, sub]() mutable -> net::awaitable<void> {
                            co_await self->StartDispatch(
                                std::move(sub), {}, {}, proxy::uot::Version::V1);
                        },
                        net::detached);
                    break;
                }
                state_it->second = StreamState::Started;
                auto self = shared_from_this();
                net::co_spawn(
                    io_context_.get_executor(),
                    [self, sub, target = std::move(*target)]() mutable -> net::awaitable<void> {
                        co_await self->StartDispatch(
                            std::move(sub), std::move(target), {}, std::nullopt);
                    },
                    net::detached);
                break;
            }
            case StreamState::PendingUotRequest: {
                state_it->second = StreamState::Started;
                auto self = shared_from_this();
                net::co_spawn(
                    io_context_.get_executor(),
                    [self,
                     sub,
                     initial = std::move(*payload)]() mutable -> net::awaitable<void> {
                        co_await self->StartDispatch(
                            std::move(sub), {}, std::move(initial), proxy::uot::Version::V2);
                    },
                    net::detached);
                break;
            }
            case StreamState::Started:
                if (!co_await sub->PushInput(std::move(*payload), header->length)) {
                    stream_states_.erase(sid);
                    RemoveStream(sid);
                    break;
                }
                break;
        }
    }

    CancelAll();
    if (result.error == ErrorCode::CONNECTION_CLOSED) {
        result.error = ErrorCode::OK;
    }
    co_return result;
}

net::awaitable<std::expected<void, ErrorCode>> ReadAuth(
    AsyncStream& stream,
    std::array<uint8_t, 32>& hash) {
    std::array<uint8_t, 34> auth{};
    size_t offset = 0;
    while (offset < auth.size()) {
        try {
            const auto n = co_await stream.AsyncRead(
                net::buffer(auth.data() + offset, auth.size() - offset));
            if (n == 0) {
                co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
            }
            offset += n;
        } catch (const IoSystemError& e) {
            co_return std::unexpected(MapAsioError(e.code()));
        } catch (...) {
            co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
        }
    }
    std::copy_n(auth.begin(), hash.size(), hash.begin());
    const uint16_t padding = static_cast<uint16_t>(
        (static_cast<uint16_t>(auth[32]) << 8) | auth[33]);
    if (auto ok = co_await anytls::DiscardFramePayload(stream, padding); !ok) {
        co_return std::unexpected(ok.error());
    }
    co_return std::expected<void, ErrorCode>{};
}

}  // namespace

net::awaitable<RelayResult>
Handler::Process(
    std::unique_ptr<AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    net::io_context& io_context,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout) {
    if (!stream) {
        RelayResult result;
        result.error = ErrorCode::PROTOCOL_DECODE_FAILED;
        co_return result;
    }

    std::array<uint8_t, 32> auth_hash{};
    if (auto ok = co_await ReadAuth(*stream, auth_hash); !ok) {
        stats_->OnError();
        RelayResult result;
        result.error = ok.error();
        co_return result;
    }
    auto user = validator_.Validate(ctx.inbound.tag, auth_hash);
    if (!user) {
        if (limiter_ && ban_tracking_enabled_) {
            limiter_->OnAuthFailTracked(ctx.inbound.tag, ctx.inbound.source_ip);
        }
        stats_->OnError();
        RelayResult result;
        result.error = ErrorCode::PROTOCOL_AUTH_FAILED;
        co_return result;
    }

    stream->SetIdleTimeout(timeouts.StreamIdleTimeout());
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(std::min(timeouts.WriteTimeout(), timeouts.StreamIdleTimeout()));
    stream->ClearPhaseDeadline();

    std::optional<AnyTLSOnlineSession> user_session;
    if (user->profile) {
        const auto& profile = *user->profile;
        ctx.inbound.user_email = profile.email;
        ctx.inbound.user_id = profile.user_id;
        ctx.content.speed_limit = profile.speed_limit;

        const uint64_t uid = static_cast<uint64_t>(profile.user_id);
        if (uid != 0) {
            if (!validator_.CanAcceptDevice(
                    ctx.inbound.tag, uid, ctx.inbound.source_ip, profile.device_limit)) {
                LOG_ACCESS_FMT("{} from {}:{} rejected device_limit [{}] user={} limit={} online_devices={}",
                    FormatTimestamp(ctx.accept_time_us),
                    ctx.inbound.source_ip,
                    ctx.inbound.source_port,
                    ctx.inbound.tag,
                    ctx.inbound.user_email,
                    profile.device_limit,
                    validator_.OnlineDeviceCount(ctx.inbound.tag, uid));
                stats_->OnError();
                RelayResult result;
                result.error = ErrorCode::RESOURCE_EXHAUSTED;
                co_return result;
            }
            validator_.OnUserConnected(ctx.inbound.tag, uid, ctx.inbound.source_ip);
            user_session.emplace(validator_, ctx.inbound.tag, uid, ctx.inbound.source_ip);
        }
    }

    auto demux = std::make_shared<AnyTLSDemuxSession>(
        std::move(stream),
        dispatcher,
        receiver,
        io_context,
        ctx,
        *stats_,
        timeouts,
        pressure_idle_timeout,
        padding_scheme_raw_,
        padding_scheme_md5_);
    co_return co_await demux->Run();
}

}  // namespace acpp::proxy::anytls::inbound

namespace {
const bool kInboundRegistered = [] {
    acpp::proxyman::inbound::ProxyRegistration reg;

    reg.create_tcp_handler =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::proxyman::inbound::BuildRequest& req) -> std::unique_ptr<acpp::Inbound> {
            auto* validator = deps.ValidatorAs<acpp::anytls::Validator>();
            if (!deps.stats || !validator) {
                return nullptr;
            }
            return std::make_unique<acpp::proxy::anytls::inbound::Handler>(
                *validator, *deps.stats, limiter, req.anytls_padding_scheme);
        };

    reg.build_static_users =
        [](std::string_view tag, const acpp::StaticUserConfig& config)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::proxyman::inbound::PreparedAnyTlsUser> users;
            users.reserve(config.clients.size());
            for (const auto& client : config.clients) {
                const std::string& password =
                    client.password.empty() ? client.id : client.password;
                if (password.empty()) {
                    LOG_WARN("AnyTLS inbound '{}': static user password is empty", tag);
                    return std::nullopt;
                }
                acpp::proxyman::inbound::PreparedAnyTlsUser info;
                info.password_hash = acpp::anytls::PasswordHash(password);
                info.profile.email = client.email.empty() ? std::string(tag) : client.email;
                users.push_back(std::move(info));
            }
            acpp::proxyman::inbound::UserSet result;
            result.anytls_users = std::move(users);
            return result;
        };

    reg.build_users =
        [](const acpp::proxyman::inbound::BuildRequest& /*req*/,
           std::span<const acpp::proxyman::inbound::RuntimeUser> runtime_users)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::proxyman::inbound::PreparedAnyTlsUser> users;
            users.reserve(runtime_users.size());
            for (const auto& runtime_user : runtime_users) {
                if (runtime_user.password.empty()) {
                    continue;
                }
                acpp::proxyman::inbound::PreparedAnyTlsUser info;
                info.password_hash = acpp::anytls::PasswordHash(runtime_user.password);
                info.profile.email = runtime_user.email;
                info.profile.user_id = runtime_user.user_id;
                info.profile.speed_limit = runtime_user.speed_limit;
                info.profile.device_limit = runtime_user.device_limit;
                users.push_back(std::move(info));
            }
            acpp::proxyman::inbound::UserSet result;
            result.anytls_users = std::move(users);
            return result;
        };

    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kAnyTLS, std::move(reg));
    return true;
}();
}  // namespace
