#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/transport/internet/transport_stack.hpp"
#include "acppnode/infra/log.hpp"

#include <array>
#include <charconv>
#include <chrono>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace acpp {

namespace {

net::awaitable<DialResult> DialSingleCandidate(
    net::io_context& io_context,
    const OutboundTransportTarget& target,
    const OutboundDialCandidate& candidate);

enum class XHttpOutboundMode {
    StreamOne,
    PacketUp,
    StreamUp,
    Unsupported,
};

[[nodiscard]] bool HasOnlyHttp11Alpn(const StreamSettings& settings) noexcept {
    return settings.tls.alpn.size() == 1 &&
           settings.tls.alpn.front() == "http/1.1";
}

[[nodiscard]] XHttpOutboundMode ResolveXHttpOutboundMode(
    const StreamSettings& settings) noexcept {
    const XHttpConfig& cfg = settings.xhttp;
    if (cfg.mode.empty() || cfg.mode == "auto") {
        if (cfg.download_settings) {
            return XHttpOutboundMode::StreamUp;
        }
        if (settings.IsReality()) {
            return XHttpOutboundMode::StreamOne;
        }
        if (settings.IsTls() && !HasOnlyHttp11Alpn(settings)) {
            return XHttpOutboundMode::StreamUp;
        }
        return XHttpOutboundMode::PacketUp;
    }
    if (cfg.mode == "packet-up") {
        return XHttpOutboundMode::PacketUp;
    }
    if (cfg.mode == "stream-up") {
        return XHttpOutboundMode::StreamUp;
    }
    if (cfg.mode == "stream-one") {
        return XHttpOutboundMode::StreamOne;
    }
    return XHttpOutboundMode::Unsupported;
}

[[nodiscard]] bool IsXHttpSplitOutbound(const OutboundTransportTarget& target) noexcept {
    if (!target.stream_settings || !target.stream_settings->IsXHttp()) {
        return false;
    }
    const auto mode = ResolveXHttpOutboundMode(*target.stream_settings);
    return mode == XHttpOutboundMode::PacketUp || mode == XHttpOutboundMode::StreamUp;
}

[[nodiscard]] std::optional<OutboundDialCandidate> FirstDialCandidate(
    const OutboundTransportTarget& target) {
    if (target.single_candidate) {
        return target.single_candidate;
    }
    if (!target.candidates.empty()) {
        return target.candidates.front();
    }
    return std::nullopt;
}

[[nodiscard]] std::string AppendU64Hex(std::string out, uint64_t value) {
    std::array<char, 16> buf{};
    auto [ptr, ec] = std::to_chars(buf.data(), buf.data() + buf.size(), value, 16);
    if (ec == std::errc{}) {
        out.append(buf.data(), static_cast<size_t>(ptr - buf.data()));
    }
    return out;
}

[[nodiscard]] std::string MakeXHttpSessionId(uint64_t conn_id) {
    thread_local uint64_t sequence = 0;
    const auto now = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());

    std::string id;
    id.reserve(48);
    id = AppendU64Hex(std::move(id), now);
    id.push_back('-');
    id = AppendU64Hex(std::move(id), conn_id);
    id.push_back('-');
    id = AppendU64Hex(std::move(id), ++sequence);
    return id;
}

[[nodiscard]] std::string BuildXHttpSplitPath(const XHttpConfig& cfg,
                                              std::string_view session_id,
                                              std::optional<uint64_t> seq) {
    std::string path = cfg.NormalizedPath();
    path.append(session_id);
    if (seq) {
        path.push_back('/');
        std::array<char, 32> buf{};
        auto [ptr, ec] = std::to_chars(buf.data(), buf.data() + buf.size(), *seq);
        if (ec == std::errc{}) {
            path.append(buf.data(), static_cast<size_t>(ptr - buf.data()));
        }
    }
    return path;
}

[[noreturn]] void ThrowXHttpPacketError(const char* what) {
    throw IoSystemError(io_error::broken_pipe, what);
}

class XHttpSplitClientStream final : public AsyncStream {
public:
    XHttpSplitClientStream(std::unique_ptr<AsyncStream> downlink,
                           std::unique_ptr<AsyncStream> upload,
                           uint64_t conn_id)
        : downlink_(std::move(downlink))
        , upload_(std::move(upload))
        , conn_id_(conn_id) {}

    XHttpSplitClientStream(net::io_context& io_context,
                           std::unique_ptr<AsyncStream> downlink,
                           const OutboundTransportTarget& target,
                           const OutboundDialCandidate& candidate,
                           std::string upload_path,
                           uint64_t conn_id)
        : io_context_(&io_context)
        , downlink_(std::move(downlink))
        , target_(target)
        , stream_settings_(*target.stream_settings)
        , candidate_(candidate)
        , upload_path_(std::move(upload_path))
        , conn_id_(conn_id) {
        target_.stream_settings = &stream_settings_;
        target_.single_candidate = candidate_;
        target_.candidates.clear();
    }

    ~XHttpSplitClientStream() noexcept override {
        Close();
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        if (!downlink_) {
            co_return 0;
        }
        if (!upload_ && buf::HasData(pending_initial_)) {
            co_await OpenUploadWithPendingInitial();
        }
        co_return co_await downlink_->AsyncRead(buffer);
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (buffer.size() == 0) {
            co_return 0;
        }
        if (!upload_) {
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            if (!buf::AppendSpanToMultiBuffer(
                    std::span<const uint8_t>(data, buffer.size()),
                    pending_initial_)) {
                throw std::bad_alloc();
            }
            co_return buffer.size();
        }
        co_return co_await upload_->AsyncWrite(buffer);
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!downlink_) {
            co_return buf::MultiBuffer{};
        }
        if (!upload_ && buf::HasData(pending_initial_)) {
            co_await OpenUploadWithPendingInitial();
        }
        co_return co_await downlink_->ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!upload_) {
            ConstBufferSpanBuilder<16> payloads;
            AppendPendingInitialBuffers(payloads);
            payloads.AppendMultiBuffer(mb);
            try {
                if (!payloads.empty()) {
                    co_await OpenUploadWithInitial(payloads.Span());
                }
            } catch (...) {
                mb.clear();
                throw;
            }
            mb.clear();
            co_return;
        }
        co_await upload_->WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (!upload_) {
            bool has_data = buf::HasData(pending_initial_);
            for (const auto& buffer : buffers) {
                if (buffer.size() > 0) {
                    has_data = true;
                    break;
                }
            }
            if (!has_data) {
                co_return;
            }
            if (!buf::HasData(pending_initial_)) {
                co_await OpenUploadWithInitial(buffers);
            } else {
                ConstBufferSpanBuilder<16> payloads;
                AppendPendingInitialBuffers(payloads);
                payloads.AppendBuffers(buffers);
                co_await OpenUploadWithInitial(payloads.Span());
            }
            co_return;
        }
        co_await upload_->WriteBuffers(buffers);
    }

    void ShutdownRead() override {
        if (downlink_) {
            downlink_->ShutdownRead();
        }
    }

    void ShutdownWrite() override {
        if (upload_) {
            upload_->ShutdownWrite();
        }
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (!upload_ && buf::HasData(pending_initial_)) {
            co_await OpenUploadWithPendingInitial();
        }
        if (upload_) {
            co_await upload_->AsyncShutdownWrite();
        }
    }

    void Cancel() noexcept override {
        if (downlink_) {
            downlink_->Cancel();
        }
        if (upload_) {
            upload_->Cancel();
        }
    }

    void Close() override {
        if (closed_) {
            return;
        }
        closed_ = true;
        if (upload_) {
            upload_->Close();
        }
        if (downlink_) {
            downlink_->Close();
        }
    }

    void CloseAbortive() override {
        if (closed_) {
            return;
        }
        closed_ = true;
        if (upload_) {
            upload_->CloseAbortive();
        }
        if (downlink_) {
            downlink_->CloseAbortive();
        }
    }

    int NativeHandle() const override {
        return downlink_ ? downlink_->NativeHandle() : -1;
    }

    bool IsOpen() const override {
        return !closed_ && downlink_ && downlink_->IsOpen();
    }

protected:
    TcpStream* BaseTcpStream() override {
        return downlink_ ? BaseTcpStreamOf(*downlink_) : nullptr;
    }

    const TcpStream* BaseTcpStream() const override {
        return downlink_ ? BaseTcpStreamOf(*downlink_) : nullptr;
    }

private:
    void AppendPendingInitialBuffers(ConstBufferSpanBuilder<16>& out) {
        out.AppendMultiBuffer(pending_initial_);
    }

    net::awaitable<void> OpenUploadWithPendingInitial() {
        ConstBufferSpanBuilder<16> payloads;
        AppendPendingInitialBuffers(payloads);
        co_await OpenUploadWithInitial(payloads.Span());
    }

    net::awaitable<void> OpenUploadWithInitial(
        std::span<const net::const_buffer> initial_payload) {
        if (upload_) {
            co_await upload_->WriteBuffers(initial_payload);
            co_return;
        }
        if (!io_context_ || !target_.stream_settings) {
            ThrowXHttpPacketError("xhttp stream-up missing target");
        }

        auto tcp_result = co_await DialSingleCandidate(*io_context_, target_, candidate_);
        if (!tcp_result.Ok()) {
            ThrowXHttpPacketError("xhttp stream-up dial failed");
        }
        tcp_result.stream->SetIdleTimeout(target_.timeout);
        (void)tcp_result.stream->StartPhaseDeadline(target_.timeout);

        auto build_result = co_await BuildOutboundXHttpClientRequest(
            std::move(tcp_result.stream),
            *target_.stream_settings,
            target_.tls_server_name,
            target_.ws_host,
            upload_path_,
            XHttpClientRequestKind::StreamUp,
            initial_payload,
            conn_id_);
        if (!build_result || !*build_result) {
            ThrowXHttpPacketError("xhttp stream-up request failed");
        }
        upload_ = std::move(*build_result);
        upload_->ClearPhaseDeadline();
        upload_->SetIdleTimeout(std::chrono::seconds(0));
        pending_initial_.clear();
    }

    net::io_context* io_context_ = nullptr;
    std::unique_ptr<AsyncStream> downlink_;
    std::unique_ptr<AsyncStream> upload_;
    OutboundTransportTarget target_;
    StreamSettings stream_settings_;
    OutboundDialCandidate candidate_;
    std::string upload_path_;
    buf::MultiBuffer pending_initial_;
    uint64_t conn_id_ = 0;
    bool closed_ = false;
};

class XHttpPacketUpClientStream final : public AsyncStream {
public:
    XHttpPacketUpClientStream(net::io_context& io_context,
                              std::unique_ptr<AsyncStream> downlink,
                              const OutboundTransportTarget& target,
                              const OutboundDialCandidate& candidate,
                              std::string session_id,
                              uint64_t conn_id)
        : io_context_(io_context)
        , downlink_(std::move(downlink))
        , target_(target)
        , stream_settings_(*target.stream_settings)
        , candidate_(candidate)
        , session_id_(std::move(session_id))
        , conn_id_(conn_id) {
        target_.stream_settings = &stream_settings_;
        target_.single_candidate = candidate_;
        target_.candidates.clear();
    }

    ~XHttpPacketUpClientStream() noexcept override {
        Close();
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        if (!downlink_) {
            co_return 0;
        }
        co_return co_await downlink_->AsyncRead(buffer);
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (write_closed_) {
            ThrowXHttpPacketError("xhttp packet-up write after shutdown");
        }
        if (buffer.size() == 0) {
            co_return 0;
        }
        std::array<net::const_buffer, 1> buffers{buffer};
        co_await SendPacket(buffers);
        co_return buffer.size();
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!downlink_) {
            co_return buf::MultiBuffer{};
        }
        co_return co_await downlink_->ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (write_closed_) {
            mb.clear();
            ThrowXHttpPacketError("xhttp packet-up write after shutdown");
        }

        ConstBufferSpanBuilder<16> payloads;
        payloads.AppendMultiBuffer(mb);

        try {
            if (!payloads.empty()) {
                co_await SendPacket(payloads.Span());
            }
        } catch (...) {
            mb.clear();
            throw;
        }
        mb.clear();
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (write_closed_) {
            ThrowXHttpPacketError("xhttp packet-up write after shutdown");
        }
        bool has_data = false;
        for (const auto& buffer : buffers) {
            if (buffer.size() > 0) {
                has_data = true;
                break;
            }
        }
        if (!has_data) {
            co_return;
        }
        co_await SendPacket(buffers);
    }

    void ShutdownRead() override {
        if (downlink_) {
            downlink_->ShutdownRead();
        }
    }

    void ShutdownWrite() override {
        write_closed_ = true;
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        write_closed_ = true;
        co_return;
    }

    void Cancel() noexcept override {
        if (downlink_) {
            downlink_->Cancel();
        }
    }

    void Close() override {
        if (closed_) {
            return;
        }
        closed_ = true;
        write_closed_ = true;
        if (downlink_) {
            downlink_->Close();
        }
    }

    void CloseAbortive() override {
        if (closed_) {
            return;
        }
        closed_ = true;
        write_closed_ = true;
        if (downlink_) {
            downlink_->CloseAbortive();
        }
    }

    int NativeHandle() const override {
        return downlink_ ? downlink_->NativeHandle() : -1;
    }

    bool IsOpen() const override {
        return !closed_ && downlink_ && downlink_->IsOpen();
    }

protected:
    TcpStream* BaseTcpStream() override {
        return downlink_ ? BaseTcpStreamOf(*downlink_) : nullptr;
    }

    const TcpStream* BaseTcpStream() const override {
        return downlink_ ? BaseTcpStreamOf(*downlink_) : nullptr;
    }

private:
    net::awaitable<void> SendPacket(std::span<const net::const_buffer> payloads) {
        if (!target_.stream_settings) {
            ThrowXHttpPacketError("xhttp packet-up missing stream settings");
        }
        std::string path = BuildXHttpSplitPath(
            target_.stream_settings->xhttp,
            session_id_,
            next_seq_);

        auto tcp_result = co_await DialSingleCandidate(io_context_, target_, candidate_);
        if (!tcp_result.Ok()) {
            ThrowXHttpPacketError("xhttp packet-up dial failed");
        }
        tcp_result.stream->SetIdleTimeout(target_.timeout);
        (void)tcp_result.stream->StartPhaseDeadline(target_.timeout);

        auto build_result = co_await BuildOutboundXHttpClientRequest(
            std::move(tcp_result.stream),
            *target_.stream_settings,
            target_.tls_server_name,
            target_.ws_host,
            path,
            XHttpClientRequestKind::PacketUp,
            payloads,
            conn_id_);
        if (!build_result) {
            ThrowXHttpPacketError("xhttp packet-up request failed");
        }
        ++next_seq_;
    }

    net::io_context& io_context_;
    std::unique_ptr<AsyncStream> downlink_;
    OutboundTransportTarget target_;
    StreamSettings stream_settings_;
    OutboundDialCandidate candidate_;
    std::string session_id_;
    uint64_t conn_id_ = 0;
    uint64_t next_seq_ = 0;
    bool write_closed_ = false;
    bool closed_ = false;
};

net::awaitable<DialResult> DialSingleCandidate(
    net::io_context& io_context,
    const OutboundTransportTarget& target,
    const OutboundDialCandidate& candidate) {

    auto bind_local = candidate.bind_local;

    DialResult tcp_result;
    if (bind_local) {
        tcp_result = co_await TcpStream::ConnectWithBind(
            io_context, *bind_local, candidate.endpoint, target.timeout);
    } else {
        tcp_result = co_await TcpStream::Connect(
            io_context, candidate.endpoint, target.timeout);
    }

    co_return tcp_result;
}

net::awaitable<DialResult> DialAndBuildXHttpRequestCandidate(
    net::io_context& io_context,
    session::Context& ctx,
    const OutboundTransportTarget& target,
    const OutboundDialCandidate& candidate,
    std::string_view path,
    XHttpClientRequestKind kind,
    std::span<const net::const_buffer> packet_payload = {}) {

    auto tcp_result = co_await DialSingleCandidate(io_context, target, candidate);
    if (!tcp_result.Ok()) {
        co_return tcp_result;
    }

    tcp_result.stream->SetIdleTimeout(target.timeout);
    (void)tcp_result.stream->StartPhaseDeadline(target.timeout);

    auto build_result = co_await BuildOutboundXHttpClientRequest(
        std::move(tcp_result.stream),
        *target.stream_settings,
        target.tls_server_name,
        target.ws_host,
        path,
        kind,
        packet_payload,
        ctx.conn_id);
    if (!build_result) {
        const ErrorCode code = build_result.error();
        co_return DialResult::Fail(
            code,
            std::string("xhttp client request failed: ") +
                std::string(ErrorCodeToString(code)));
    }

    auto stream = std::move(*build_result);
    if (kind != XHttpClientRequestKind::PacketUp && !stream) {
        co_return DialResult::Fail(
            ErrorCode::SOCKET_EOF,
            "xhttp client request returned no stream");
    }
    if (stream) {
        stream->ClearPhaseDeadline();
        stream->SetIdleTimeout(std::chrono::seconds(0));
    }

    co_return DialResult::Success(std::move(stream));
}

net::awaitable<DialResult> DialAndBuildSingleCandidate(
    net::io_context& io_context,
    session::Context& ctx,
    const OutboundTransportTarget& target,
    const OutboundDialCandidate& candidate) {

    auto tcp_result = co_await DialSingleCandidate(io_context, target, candidate);
    if (!tcp_result.Ok()) {
        co_return tcp_result;
    }

    tcp_result.stream->SetIdleTimeout(target.timeout);
    (void)tcp_result.stream->StartPhaseDeadline(target.timeout);

    auto build_result = co_await BuildOutboundTransport(
        std::move(tcp_result.stream),
        *target.stream_settings,
        target.tls_server_name,
        target.ws_host,
        ctx.conn_id);
    if (!build_result) {
        const ErrorCode code = build_result.error();
        co_return DialResult::Fail(
            code,
            std::string("outbound transport build failed: ") +
                std::string(ErrorCodeToString(code)));
    }

    auto stream = std::move(*build_result);
    stream->ClearPhaseDeadline();
    // 后续 outbound handler / relay 阶段会重新设置 idle/read/write timeout。
    stream->SetIdleTimeout(std::chrono::seconds(0));

    co_return DialResult::Success(std::move(stream));
}

net::awaitable<DialResult> DialAndBuildCandidatesSequential(
    net::io_context& io_context,
    session::Context& ctx,
    const OutboundTransportTarget& target,
    std::span<const OutboundDialCandidate> candidates) {

    DialResult last_result =
        DialResult::Fail(ErrorCode::DIAL_CONNECT_FAILED, "all dial candidates failed");

    for (const auto& candidate : candidates) {
        auto attempt = co_await DialAndBuildSingleCandidate(
            io_context, ctx, target, candidate);
        if (attempt.Ok()) {
            co_return attempt;
        }

        LOG_CONN_DEBUG(ctx,
                       "DIAL_CANDIDATE_FAILED endpoint={}:{} error={}",
                       candidate.endpoint.address().to_string(),
                       candidate.endpoint.port(),
                       attempt.error_msg);
        last_result = std::move(attempt);
    }

    co_return last_result;
}

net::awaitable<DialResult> DialXHttpSplitOutboundTransport(
    net::io_context& io_context,
    session::Context& ctx,
    const OutboundTransportTarget& target,
    std::span<const OutboundDialCandidate> candidates) {

    if (!target.stream_settings) {
        co_return DialResult::Fail(ErrorCode::INVALID_ARGUMENT, "missing stream settings");
    }

    const auto mode = ResolveXHttpOutboundMode(*target.stream_settings);
    if (mode != XHttpOutboundMode::PacketUp && mode != XHttpOutboundMode::StreamUp) {
        co_return DialResult::Fail(ErrorCode::PROTOCOL_UNSUPPORTED, "unsupported xhttp mode");
    }

    const OutboundTransportTarget& downlink_target =
        target.xhttp_download_target ? *target.xhttp_download_target : target;
    if (!downlink_target.stream_settings || !downlink_target.stream_settings->IsXHttp()) {
        co_return DialResult::Fail(
            ErrorCode::INVALID_ARGUMENT,
            "invalid xhttp downlink target");
    }

    const std::string session_id = MakeXHttpSessionId(ctx.conn_id);
    const std::string downlink_path = BuildXHttpSplitPath(
        downlink_target.stream_settings->xhttp,
        session_id,
        std::nullopt);
    const std::string upload_path = BuildXHttpSplitPath(
        target.stream_settings->xhttp,
        session_id,
        std::nullopt);

    DialResult last_result =
        DialResult::Fail(ErrorCode::DIAL_CONNECT_FAILED, "all xhttp candidates failed");
    std::optional<OutboundDialCandidate> selected;
    std::unique_ptr<AsyncStream> downlink;

    auto try_downlink_candidate = [&](const OutboundDialCandidate& candidate)
        -> net::awaitable<bool> {
        auto attempt = co_await DialAndBuildXHttpRequestCandidate(
            io_context,
            ctx,
            downlink_target,
            candidate,
            downlink_path,
            XHttpClientRequestKind::Downlink);
        if (attempt.Ok()) {
            selected = candidate;
            downlink = std::move(attempt.stream);
            co_return true;
        }

        LOG_CONN_DEBUG(ctx,
                       "XHTTP_DOWNLINK_CANDIDATE_FAILED endpoint={}:{} error={}",
                       candidate.endpoint.address().to_string(),
                       candidate.endpoint.port(),
                       attempt.error_msg);
        last_result = std::move(attempt);
        co_return false;
    };

    if (downlink_target.single_candidate) {
        (void)co_await try_downlink_candidate(*downlink_target.single_candidate);
    } else {
        for (const auto& candidate : downlink_target.candidates) {
            if (co_await try_downlink_candidate(candidate)) {
                break;
            }
        }
    }

    if (!downlink || !selected) {
        co_return last_result;
    }

    std::optional<OutboundDialCandidate> upload_candidate =
        target.xhttp_download_target ? FirstDialCandidate(target) : selected;
    if (!upload_candidate) {
        co_return DialResult::Fail(
            ErrorCode::INVALID_ARGUMENT,
            "missing xhttp upload candidate");
    }

    if (mode == XHttpOutboundMode::PacketUp) {
        co_return DialResult::Success(
            std::make_unique<XHttpPacketUpClientStream>(
                io_context,
                std::move(downlink),
                target,
                *upload_candidate,
                session_id,
                ctx.conn_id));
    }

    co_return DialResult::Success(
        std::make_unique<XHttpSplitClientStream>(
            io_context,
            std::move(downlink),
            target,
            *upload_candidate,
            upload_path,
            ctx.conn_id));
}

}  // namespace

net::awaitable<DialResult> DialOutboundTransport(
    net::io_context& io_context,
    session::Context& ctx,
    const OutboundTransportTarget& target) {

    if ((!target.single_candidate && target.candidates.empty()) || target.stream_settings == nullptr) {
        co_return DialResult::Fail(ErrorCode::INVALID_ARGUMENT, "invalid outbound transport target");
    }

    if (IsXHttpSplitOutbound(target)) {
        if (target.single_candidate) {
            std::array<OutboundDialCandidate, 1> candidates{*target.single_candidate};
            co_return co_await DialXHttpSplitOutboundTransport(
                io_context,
                ctx,
                target,
                candidates);
        }
        co_return co_await DialXHttpSplitOutboundTransport(
            io_context,
            ctx,
            target,
            target.candidates);
    }

    if (target.single_candidate) {
        co_return co_await DialAndBuildSingleCandidate(
            io_context, ctx, target, *target.single_candidate);
    }
    if (target.candidates.size() == 1) {
        co_return co_await DialAndBuildSingleCandidate(
            io_context, ctx, target, target.candidates.front());
    }
    co_return co_await DialAndBuildCandidatesSequential(
        io_context, ctx, target, target.candidates);
}

}  // namespace acpp
