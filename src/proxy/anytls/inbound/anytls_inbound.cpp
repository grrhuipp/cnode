#include "acppnode/proxy/anytls/inbound/anytls_inbound.hpp"

#include "../anytls_codec.hpp"
#include "acppnode/app/stats.hpp"
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
#include <asio/steady_timer.hpp>
#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace acpp::anytls::inbound {

namespace {

constexpr size_t kMaxSubStreamQueuedPayloadBytes = buf::Buffer::kSize * 4;

struct PendingWait {
    virtual ~PendingWait() = default;
    virtual void Complete() noexcept = 0;
};

template <typename Handler>
struct PendingWaitOp final : PendingWait {
    template <typename H>
    explicit PendingWaitOp(H&& h) : handler(std::forward<H>(h)) {}

    void Complete() noexcept override {
        try {
            std::move(handler)();
        } catch (...) {}
    }

    Handler handler;
};

template <typename Handler>
std::unique_ptr<PendingWait> MakePendingWait(Handler&& handler) {
    using StoredHandler = std::decay_t<Handler>;
    return std::make_unique<PendingWaitOp<StoredHandler>>(
        std::forward<Handler>(handler));
}

void ResumeWaiter(net::io_context& io_context,
                  std::unique_ptr<PendingWait>& waiter) noexcept {
    if (auto pending = std::exchange(waiter, {}); pending) {
        try {
            net::post(io_context, [pending = std::move(pending)]() mutable {
                pending->Complete();
            });
        } catch (...) {
            pending->Complete();
        }
    }
}

void CopySessionContext(const session::Context& source, session::Context& target) {
    target.conn_id = source.conn_id;
    target.inbound = source.inbound;
    target.outbound = source.outbound;
    target.outbounds = source.outbounds;
    target.content = source.content;
    target.traffic = source.traffic;
    target.sockopt = source.sockopt;
    target.accept_time_us = source.accept_time_us;
    target.worker_id = source.worker_id;
}

}  // namespace

Handler::Handler(StatsShard& stats,
                 Validator& validator,
                 ConnectionLimiterPtr limiter,
                 std::string padding_scheme)
    : stats_(&stats)
    , validator_(&validator)
{
    (void)limiter;
    if (!padding_scheme.empty()) {
        auto parsed = ParsePaddingScheme(padding_scheme);
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

std::string FlattenToString(const buf::MultiBuffer& mb) {
    std::string out;
    out.reserve(buf::TotalLen(mb));
    for (const auto* buffer : mb) {
        if (buffer && !buffer->IsEmpty()) {
            auto bytes = buffer->Bytes();
            out.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        }
    }
    return out;
}

net::awaitable<std::expected<buf::MultiBuffer, ErrorCode>>
ReadNextPshPayload(AsyncStream& stream, uint32_t sid) {
    while (true) {
        auto header = co_await anytls::ReadFrameHeader(stream);
        if (!header) {
            co_return std::unexpected(header.error());
        }
        if (header->sid != 0 && header->sid != sid) {
            if (auto ok = co_await anytls::DiscardFramePayload(stream, header->length); !ok) {
                co_return std::unexpected(ok.error());
            }
            continue;
        }
        switch (header->cmd) {
            case anytls::kCmdWaste:
            case anytls::kCmdHeartRequest:
            case anytls::kCmdHeartResponse:
            case anytls::kCmdServerSettings:
            case anytls::kCmdUpdatePaddingScheme:
                if (auto ok = co_await anytls::DiscardFramePayload(stream, header->length); !ok) {
                    co_return std::unexpected(ok.error());
                }
                break;
            case anytls::kCmdPSH:
                co_return co_await anytls::ReadFramePayload(stream, header->length);
            case anytls::kCmdFIN:
                (void)co_await anytls::DiscardFramePayload(stream, header->length);
                co_return std::unexpected(ErrorCode::CONNECTION_CLOSED);
            default:
                (void)co_await anytls::DiscardFramePayload(stream, header->length);
                co_return std::unexpected(ErrorCode::PROTOCOL_INVALID_COMMAND);
        }
    }
}

class AnyTLSStreamReader final : public transport::MultiBufferReader {
public:
    AnyTLSStreamReader(AsyncStream& stream, uint32_t sid) noexcept
        : stream_(stream), sid_(sid) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (true) {
            auto header = co_await anytls::ReadFrameHeader(stream_);
            if (!header) {
                co_return buf::MultiBuffer{};
            }
            if (header->sid != 0 && header->sid != sid_) {
                (void)co_await anytls::DiscardFramePayload(stream_, header->length);
                continue;
            }
            switch (header->cmd) {
                case anytls::kCmdWaste:
                case anytls::kCmdHeartRequest:
                case anytls::kCmdHeartResponse:
                case anytls::kCmdServerSettings:
                case anytls::kCmdUpdatePaddingScheme:
                    (void)co_await anytls::DiscardFramePayload(stream_, header->length);
                    break;
                case anytls::kCmdPSH: {
                    auto payload = co_await anytls::ReadFramePayload(stream_, header->length);
                    if (!payload) {
                        co_return buf::MultiBuffer{};
                    }
                    co_return std::move(*payload);
                }
                case anytls::kCmdFIN:
                    (void)co_await anytls::DiscardFramePayload(stream_, header->length);
                    co_return buf::MultiBuffer{};
                default:
                    (void)co_await anytls::DiscardFramePayload(stream_, header->length);
                    co_return buf::MultiBuffer{};
            }
        }
    }

private:
    AsyncStream& stream_;
    uint32_t sid_;
};

class AnyTLSUotReader final : public transport::MultiBufferReader {
public:
    AnyTLSUotReader(AsyncStream& stream,
                    uint32_t sid,
                    TargetAddress source,
                    std::string initial_pending)
        : stream_(stream)
        , sid_(sid)
        , source_(std::move(source))
        , initial_pending_(std::move(initial_pending)) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (true) {
            if (!initial_pending_.empty()) {
                buf::MultiBuffer out;
                buf::BufferGuard buffer{buf::Buffer::New()};
                if (!buffer || initial_pending_.size() > buffer->Available()) {
                    initial_pending_.clear();
                    co_return buf::MultiBuffer{};
                }
                std::memcpy(buffer->Tail().data(), initial_pending_.data(), initial_pending_.size());
                buffer->Produce(static_cast<uint32_t>(initial_pending_.size()));
                buffer->SetUDP(source_);
                out.push_back(buffer.release());
                initial_pending_.clear();
                co_return out;
            }

            auto payload = co_await ReadNextPshPayload(stream_, sid_);
            if (!payload) {
                co_return buf::MultiBuffer{};
            }
            for (auto* buffer : *payload) {
                if (buffer && !buffer->IsEmpty()) {
                    buffer->SetUDP(source_);
                }
            }
            co_return std::move(*payload);
        }
    }

private:
    AsyncStream& stream_;
    uint32_t sid_;
    TargetAddress source_;
    std::string initial_pending_;
};

class AnyTLSStreamWriter final : public transport::MultiBufferWriter {
public:
    AnyTLSStreamWriter(AsyncStream& stream, uint32_t sid) noexcept
        : stream_(stream), sid_(sid) {}

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        auto ok = co_await anytls::WriteMultiBufferAsFrames(
            stream_, anytls::kCmdPSH, sid_, std::move(mb));
        if (!ok) {
            throw IoSystemError(make_error_code(std::errc::io_error));
        }
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        (void)co_await anytls::WriteFrame(stream_, anytls::kCmdFIN, sid_, {});
    }

private:
    AsyncStream& stream_;
    uint32_t sid_;
};

class AnyTLSUotWriter final : public transport::MultiBufferWriter {
public:
    AnyTLSUotWriter(AsyncStream& stream, uint32_t sid) noexcept
        : stream_(stream), sid_(sid) {}

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        for (auto* buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            auto ok = co_await anytls::WriteFrame(
                stream_,
                anytls::kCmdPSH,
                sid_,
                buffer->Bytes());
            if (!ok) {
                throw IoSystemError(make_error_code(std::errc::io_error));
            }
        }
        mb.clear();
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        (void)co_await anytls::WriteFrame(stream_, anytls::kCmdFIN, sid_, {});
    }

private:
    AsyncStream& stream_;
    uint32_t sid_;
};

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

    void PushInput(buf::MultiBuffer mb) {
        if (cancelled_ || input_done_) {
            mb.clear();
            return;
        }
        const size_t bytes = buf::TotalLen(mb);
        if (bytes == 0) {
            mb.clear();
            return;
        }
        if (queued_bytes_ + bytes > kMaxSubStreamQueuedPayloadBytes) {
            Cancel();
            mb.clear();
            return;
        }
        input_queue_.push_back(std::move(mb));
        queued_bytes_ += bytes;
        WakeInputReader();
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
        WakeInputReader();
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (!cancelled_) {
            if (!input_queue_.empty()) {
                buf::MultiBuffer mb = std::move(input_queue_.front());
                queued_bytes_ -= std::min(queued_bytes_, buf::TotalLen(mb));
                input_queue_.pop_front();
                co_return mb;
            }
            if (input_done_) {
                co_return buf::MultiBuffer{};
            }
            co_await AsyncWaitInput(net::use_awaitable);
        }
        co_return buf::MultiBuffer{};
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> AsyncShutdownWrite() override;

private:
    template <typename CompletionToken>
    auto AsyncWaitInput(CompletionToken&& token) {
        return net::async_initiate<CompletionToken, void()>(
            [this](auto&& handler) {
                input_waiter_ = MakePendingWait(
                    std::forward<decltype(handler)>(handler));
            },
            token);
    }

    void WakeInputReader() noexcept {
        ResumeWaiter(io_context_, input_waiter_);
    }

    std::unique_ptr<PendingWait> input_waiter_;
    net::io_context& io_context_;
    std::shared_ptr<AnyTLSDemuxSession> session_;
    uint32_t sid_ = 0;
    std::deque<buf::MultiBuffer> input_queue_;
    size_t queued_bytes_ = 0;
    bool input_done_ = false;
    bool cancelled_ = false;
};

class AnyTLSUotSubReader final : public transport::MultiBufferReader {
public:
    AnyTLSUotSubReader(std::shared_ptr<AnyTLSSubStream> sub,
                       TargetAddress source,
                       std::string initial_pending)
        : sub_(std::move(sub))
        , source_(std::move(source))
        , initial_pending_(std::move(initial_pending)) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!initial_pending_.empty()) {
            buf::MultiBuffer out;
            buf::BufferGuard buffer{buf::Buffer::New()};
            if (!buffer || initial_pending_.size() > buffer->Available()) {
                initial_pending_.clear();
                co_return buf::MultiBuffer{};
            }
            std::memcpy(buffer->Tail().data(), initial_pending_.data(), initial_pending_.size());
            buffer->Produce(static_cast<uint32_t>(initial_pending_.size()));
            buffer->SetUDP(source_);
            out.push_back(buffer.release());
            initial_pending_.clear();
            co_return out;
        }

        auto mb = co_await sub_->ReadMultiBuffer();
        for (auto* buffer : mb) {
            if (buffer && !buffer->IsEmpty()) {
                buffer->SetUDP(source_);
            }
        }
        co_return mb;
    }

private:
    std::shared_ptr<AnyTLSSubStream> sub_;
    TargetAddress source_;
    std::string initial_pending_;
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
        , write_timer_(io_context) {
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
            write_timer_.expires_after(std::chrono::hours(24));
            auto [ec] = co_await write_timer_.async_wait(net::as_tuple(net::use_awaitable));
            if (ec == io_error::operation_aborted) {
                continue;
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
                self->write_timer_.cancel();
            }};
        (void)guard;

        co_return co_await anytls::WriteFrame(*stream_, cmd, sid, payload);
    }

    net::awaitable<std::expected<void, ErrorCode>>
    WriteMultiBufferSerialized(uint8_t cmd, uint32_t sid, buf::MultiBuffer mb) {
        for (auto* buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            auto ok = co_await WriteFrameSerialized(cmd, sid, buffer->Bytes());
            if (!ok) {
                mb.clear();
                co_return std::unexpected(ok.error());
            }
        }
        mb.clear();
        co_return std::expected<void, ErrorCode>{};
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
        write_timer_.cancel();
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

    net::awaitable<void> StartDispatch(std::shared_ptr<AnyTLSSubStream> sub,
                                       Network network,
                                       TargetAddress target,
                                       std::string initial_uot_payload);

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
    net::steady_timer write_timer_;
    std::unordered_map<uint32_t, std::shared_ptr<AnyTLSSubStream>> streams_;
    std::unordered_map<uint32_t, StreamState> stream_states_;
    bool write_busy_ = false;
    bool cancelled_ = false;
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

net::awaitable<void> AnyTLSSubStream::AsyncShutdownWrite() {
    auto session = session_;
    if (session) {
        (void)co_await session->WriteFrameSerialized(anytls::kCmdFIN, sid_, {});
    }
}

net::awaitable<void> AnyTLSDemuxSession::StartDispatch(
    std::shared_ptr<AnyTLSSubStream> sub,
    Network network,
    TargetAddress target,
    std::string initial_uot_payload) {
    if (!sub) {
        co_return;
    }

    session::Context ctx;
    CopySessionContext(base_ctx_, ctx);
    ctx.outbound.original_target = target;
    ctx.outbound.target = target;
    ctx.outbound.route_target = target;
    ctx.content.network = network;

    RelayResult result;
    if (ctx.content.network == Network::UDP) {
        AnyTLSUotSubReader reader{sub, target, std::move(initial_uot_payload)};
        result = co_await dispatcher_.Dispatch(
            io_context_,
            receiver_,
            nullptr,
            transport::Link{&reader, sub.get()},
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
                std::string target_bytes = FlattenToString(*payload);
                payload->clear();
                auto target = ParseSocksAddress(
                    std::span<const uint8_t>(
                        reinterpret_cast<const uint8_t*>(target_bytes.data()),
                        target_bytes.size()));
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
                if (anytls::IsUotMagicAddress(*target)) {
                    state_it->second = StreamState::PendingUotRequest;
                    break;
                }
                state_it->second = StreamState::Started;
                auto self = shared_from_this();
                net::co_spawn(
                    io_context_.get_executor(),
                    [self, sub, target = std::move(*target)]() mutable -> net::awaitable<void> {
                        co_await self->StartDispatch(
                            std::move(sub), Network::TCP, std::move(target), {});
                    },
                    net::detached);
                break;
            }
            case StreamState::PendingUotRequest: {
                std::string request_bytes = FlattenToString(*payload);
                payload->clear();
                auto request = anytls::DecodeUotRequest(
                    std::span<const uint8_t>(
                        reinterpret_cast<const uint8_t*>(request_bytes.data()),
                        request_bytes.size()));
                if (!request || !request->destination.IsValid()) {
                    result.error = request ? ErrorCode::PROTOCOL_INVALID_ADDRESS : request.error();
                    CancelAll();
                    co_return result;
                }
                std::string initial_pending;
                if (request->consumed < request_bytes.size()) {
                    initial_pending.assign(
                        request_bytes.data() + request->consumed,
                        request_bytes.size() - request->consumed);
                }
                state_it->second = StreamState::Started;
                auto self = shared_from_this();
                net::co_spawn(
                    io_context_.get_executor(),
                    [self,
                     sub,
                     target = std::move(request->destination),
                     initial = std::move(initial_pending)]() mutable -> net::awaitable<void> {
                        co_await self->StartDispatch(
                            std::move(sub), Network::UDP, std::move(target), std::move(initial));
                    },
                    net::detached);
                break;
            }
            case StreamState::Started:
                sub->PushInput(std::move(*payload));
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

    if (!validator_) {
        stats_->OnError();
        RelayResult result;
        result.error = ErrorCode::PROTOCOL_AUTH_FAILED;
        co_return result;
    }

    std::array<uint8_t, 32> auth_hash{};
    if (auto ok = co_await ReadAuth(*stream, auth_hash); !ok) {
        stats_->OnError();
        RelayResult result;
        result.error = ok.error();
        co_return result;
    }
    auto user = validator_->Validate(ctx.inbound.tag, auth_hash);
    if (!user) {
        stats_->OnError();
        RelayResult result;
        result.error = ErrorCode::PROTOCOL_AUTH_FAILED;
        co_return result;
    }

    ctx.inbound.user_email = user->email;
    ctx.inbound.user_id = user->user_id;
    ctx.content.speed_limit = user->speed_limit;

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

}  // namespace acpp::anytls::inbound

namespace {
const bool kInboundRegistered = [] {
    acpp::proxyman::inbound::ProxyRegistration reg;

    reg.create_tcp_handler =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::proxyman::inbound::BuildRequest& req) -> std::unique_ptr<acpp::Inbound> {
            if (!deps.stats || !deps.anytls_validator) {
                return nullptr;
            }
            return std::make_unique<acpp::anytls::inbound::Handler>(
                *deps.stats, *deps.anytls_validator, limiter, req.anytls_padding_scheme);
        };

    reg.build_static_users =
        [](std::string_view tag, const acpp::StaticUserConfig& config)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::anytls::UserInfo> users;
            users.reserve(config.clients.size());
            for (const auto& client : config.clients) {
                const std::string& password =
                    client.password.empty() ? client.id : client.password;
                if (password.empty()) {
                    continue;
                }
                acpp::anytls::UserInfo info;
                info.password_hash = acpp::anytls::PasswordHash(password);
                info.email = client.email.empty() ? std::string(tag) : client.email;
                users.push_back(std::move(info));
            }
            acpp::proxyman::inbound::UserSet result;
            result.anytls_users = std::move(users);
            return result;
        };

    reg.apply_worker_users =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           std::string_view tag,
           const acpp::proxyman::inbound::UserSet& users) {
            if (deps.anytls_validator) deps.anytls_validator->ApplyUsers(tag, users.anytls_users);
        };

    reg.add_worker_users =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           std::string_view tag,
           const acpp::proxyman::inbound::UserSet& users) {
            if (deps.anytls_validator) deps.anytls_validator->AddUsers(tag, users.anytls_users);
        };

    reg.remove_worker_users =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           std::string_view tag,
           const acpp::proxyman::inbound::UserSet& users) {
            if (deps.anytls_validator) deps.anytls_validator->RemoveUsers(tag, users.anytls_users);
        };

    reg.clear_worker_users =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps, std::string_view tag) {
            if (deps.anytls_validator) deps.anytls_validator->ClearUsers(tag);
        };

    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kAnyTLS, std::move(reg));
    return true;
}();
}  // namespace
