#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/transport/internet/async_write_gate.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/transport/internet/transport_stack.hpp"
#include "acppnode/infra/log.hpp"

#include <array>
#include <charconv>
#include <chrono>
#include <limits>
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

[[nodiscard]] bool IsXHttpSplitOutbound(const OutboundTransportTarget& target) noexcept {
    if (!target.stream_settings || !target.stream_settings->IsXHttp()) {
        return false;
    }
    const auto mode = ResolveXHttpOutboundMode(*target.stream_settings);
    return mode == XHttpMode::PacketUp || mode == XHttpMode::StreamUp;
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

void AppendU64Hex(memory::ThreadLocalString& out, uint64_t value) {
    std::array<char, 16> buf{};
    auto [ptr, ec] = std::to_chars(buf.data(), buf.data() + buf.size(), value, 16);
    if (ec == std::errc{}) {
        out.append(buf.data(), static_cast<size_t>(ptr - buf.data()));
    }
}

[[nodiscard]] memory::ThreadLocalString MakeXHttpSessionId(uint64_t conn_id) {
    thread_local uint64_t sequence = 0;
    const auto now = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());

    memory::ThreadLocalString id;
    id.reserve(48);
    AppendU64Hex(id, now);
    id.push_back('-');
    AppendU64Hex(id, conn_id);
    id.push_back('-');
    AppendU64Hex(id, ++sequence);
    return id;
}

[[nodiscard]] memory::ThreadLocalString BuildXHttpSplitPath(
    const XHttpConfig& cfg,
    std::string_view session_id) {
    memory::ThreadLocalString path(cfg.normalized_path);
    path.append(session_id);
    return path;
}

[[noreturn]] void ThrowXHttpPacketError(const char* what) {
    throw IoSystemError(io_error::broken_pipe, what);
}

// Upload bytes written before the first upload request are coalesced into it,
// so the protocol header shares that request; the limit bounds that deferral.
constexpr size_t kMaxDeferredUploadBytes = 64 * 1024;

class XHttpSplitClientStream final : public AsyncStream {
public:
    XHttpSplitClientStream(net::io_context& io_context,
                           std::unique_ptr<AsyncStream> downlink,
                           const OutboundTransportTarget& target,
                           const OutboundDialCandidate& candidate,
                           memory::ThreadLocalString upload_path,
                           uint64_t conn_id)
        : io_context_(io_context)
        , downlink_(std::move(downlink))
        , target_(target)
        , candidate_(candidate)
        , upload_path_(std::move(upload_path))
        , conn_id_(conn_id) {
        if (!target_.stream_settings) {
            ThrowXHttpPacketError("xhttp stream-up missing stream settings");
        }
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
        if (ReaderMustSendDeferredUpload()) {
            co_await WriteUpload({});
        }
        co_return co_await downlink_->AsyncRead(buffer);
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (buffer.size() == 0) {
            co_return 0;
        }
        // upload_failed_ is provisionally set while an open is in flight;
        // only a finished failed open poisons the stream.
        if (closed_ || (upload_failed_ && !upload_opening_)) {
            ThrowXHttpPacketError("xhttp stream-up upload unavailable");
        }
        if (!upload_ && !upload_opening_ &&
            buffer.size() <= kMaxDeferredUploadBytes - pending_initial_.byte_size()) {
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            if (!buf::AppendSpanToMultiBuffer(
                    std::span<const uint8_t>(data, buffer.size()),
                    pending_initial_)) {
                throw std::bad_alloc();
            }
            co_return buffer.size();
        }
        if (upload_) co_return co_await upload_->AsyncWrite(buffer);
        co_await WriteUpload({&buffer, 1});
        co_return buffer.size();
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!downlink_) {
            co_return buf::MultiBuffer{};
        }
        if (ReaderMustSendDeferredUpload()) {
            co_await WriteUpload({});
        }
        co_return co_await downlink_->ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (upload_) {
            co_await upload_->WriteMultiBuffer(std::move(mb));
            co_return;
        }
        ConstBufferSpanBuilder<16> payloads;
        payloads.AppendMultiBuffer(mb);
        co_await WriteUpload(payloads.Span());
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (upload_) {
            co_await upload_->WriteBuffers(buffers);
            co_return;
        }
        co_await WriteUpload(buffers);
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
        if (!upload_ && (upload_opening_ || pending_initial_.byte_size() != 0)) {
            co_await WriteUpload({});
        }
        if (upload_) {
            co_await upload_->AsyncShutdownWrite();
        }
    }

    void Cancel() noexcept override {
        NotifyCancellation();
        if (downlink_) {
            downlink_->Cancel();
        }
        if (upload_) {
            upload_->Cancel();
        }
    }

    void Close() override {
        NotifyClosed();
        if (closed_) {
            return;
        }
        closed_ = true;
        upload_gate_.Cancel();
        if (upload_) {
            upload_->Close();
        }
        if (downlink_) {
            downlink_->Close();
        }
    }

    void CloseAbortive() override {
        NotifyClosed();
        if (closed_) {
            return;
        }
        closed_ = true;
        upload_gate_.Cancel();
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
    // A reader may wait for the reply to deferred bytes (e.g. a protocol
    // header); it sends them unless a writer is already opening the upload.
    [[nodiscard]] bool ReaderMustSendDeferredUpload() const noexcept {
        return !upload_ && !upload_opening_ && pending_initial_.byte_size() != 0;
    }

    // Single-flight: the first caller opens the upload request carrying the
    // deferred bytes followed by |payload|; callers queued behind it write
    // |payload| to the opened upload. A failed open poisons the stream, since
    // the deferred bytes are gone with it.
    net::awaitable<void> WriteUpload(std::span<const net::const_buffer> payload) {
        auto lease = upload_gate_.TryAcquire();
        if (!lease) lease = co_await upload_gate_.Acquire();
        if (!lease || closed_ || upload_failed_) {
            ThrowXHttpPacketError("xhttp stream-up upload unavailable");
        }
        if (upload_) {
            if (!payload.empty()) co_await upload_->WriteBuffers(payload);
            co_return;
        }

        const buf::MultiBuffer initial = std::move(pending_initial_);
        ConstBufferSpanBuilder<16> initial_payload;
        initial_payload.AppendMultiBuffer(initial);
        initial_payload.AppendBuffers(payload);
        if (initial_payload.empty()) co_return;

        upload_failed_ = true;
        upload_opening_ = true;
        struct OpeningScope {
            bool& opening;
            ~OpeningScope() { opening = false; }
        } opening_scope{upload_opening_};

        auto tcp_result = co_await DialSingleCandidate(io_context_, target_, candidate_);
        if (!tcp_result.Ok()) {
            ThrowXHttpPacketError("xhttp stream-up dial failed");
        }
        tcp_result.stream->SetIdleTimeout(target_.timeout);
        (void)tcp_result.stream->StartPhaseDeadline(target_.timeout);

        auto build_result = co_await BuildOutboundXHttpClientRequest(
            std::move(tcp_result.stream),
            *target_.stream_settings,
            target_.security_context,
            target_.tls_server_name,
            target_.ws_host,
            upload_path_,
            XHttpClientRequestKind::StreamUp,
            initial_payload.Span(),
            conn_id_);
        if (!build_result || !*build_result) {
            ThrowXHttpPacketError("xhttp stream-up request failed");
        }
        if (closed_) {
            (*build_result)->CloseAbortive();
            ThrowXHttpPacketError("xhttp stream-up closed while opening");
        }
        upload_ = std::move(*build_result);
        upload_->ClearPhaseDeadline();
        upload_->SetIdleTimeout(std::chrono::seconds(0));
        upload_failed_ = false;
    }

    net::io_context& io_context_;
    std::unique_ptr<AsyncStream> downlink_;
    std::unique_ptr<AsyncStream> upload_;
    OutboundTransportTarget target_;
    OutboundDialCandidate candidate_;
    memory::ThreadLocalString upload_path_;
    buf::MultiBuffer pending_initial_;
    transport::internet::AsyncWriteGate upload_gate_;
    uint64_t conn_id_ = 0;
    bool upload_opening_ = false;
    bool upload_failed_ = false;
    bool closed_ = false;
};

class XHttpPacketUpClientStream final : public AsyncStream {
public:
    XHttpPacketUpClientStream(net::io_context& io_context,
                              std::unique_ptr<AsyncStream> downlink,
                              const OutboundTransportTarget& target,
                              const OutboundDialCandidate& candidate,
                              memory::ThreadLocalString upload_path,
                              uint64_t conn_id)
        : io_context_(io_context)
        , downlink_(std::move(downlink))
        , target_(target)
        , candidate_(candidate)
        , upload_path_(std::move(upload_path))
        , conn_id_(conn_id) {
        if (!target_.stream_settings) {
            ThrowXHttpPacketError("xhttp packet-up missing stream settings");
        }
        target_.single_candidate = candidate_;
        target_.candidates.clear();
    }

    ~XHttpPacketUpClientStream() noexcept override {
        Close();
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        return downlink_->AsyncRead(buffer);
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
        return downlink_->ReadMultiBuffer();
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
        NotifyCancellation();
        if (downlink_) {
            downlink_->Cancel();
        }
    }

    void Close() override {
        NotifyClosed();
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
        NotifyClosed();
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
        // Packet-up request target: "<upload path>/<seq>".
        memory::ThreadLocalString path(upload_path_);
        path.push_back('/');
        std::array<char, 20> seq_text{};
        const auto [seq_end, ec] = std::to_chars(
            seq_text.data(), seq_text.data() + seq_text.size(), next_seq_);
        (void)ec;  // 20 digits always fit a uint64_t.
        path.append(seq_text.data(), static_cast<size_t>(seq_end - seq_text.data()));

        auto tcp_result = co_await DialSingleCandidate(io_context_, target_, candidate_);
        if (!tcp_result.Ok()) {
            ThrowXHttpPacketError("xhttp packet-up dial failed");
        }
        tcp_result.stream->SetIdleTimeout(target_.timeout);
        (void)tcp_result.stream->StartPhaseDeadline(target_.timeout);

        auto build_result = co_await BuildOutboundXHttpClientRequest(
            std::move(tcp_result.stream),
            *target_.stream_settings,
            target_.security_context,
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
    OutboundDialCandidate candidate_;
    memory::ThreadLocalString upload_path_;
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

    tcp_result.attempted_remote_addr = candidate.endpoint.address();
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
        target.security_context,
        target.tls_server_name,
        target.ws_host,
        path,
        kind,
        packet_payload,
        ctx.conn_id);
    if (!build_result) {
        const ErrorCode code = build_result.error();
        auto result = DialResult::Fail(
            code,
            std::string("xhttp client request failed: ") +
                std::string(ErrorCodeToString(code)));
        result.attempted_remote_addr = candidate.endpoint.address();
        co_return result;
    }

    auto stream = std::move(*build_result);
    if (kind != XHttpClientRequestKind::PacketUp && !stream) {
        auto result = DialResult::Fail(
            ErrorCode::SOCKET_EOF,
            "xhttp client request returned no stream");
        result.attempted_remote_addr = candidate.endpoint.address();
        co_return result;
    }
    if (stream) {
        stream->ClearPhaseDeadline();
        stream->SetIdleTimeout(std::chrono::seconds(0));
    }

    auto result = DialResult::Success(std::move(stream));
    result.attempted_remote_addr = candidate.endpoint.address();
    co_return result;
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
        target.security_context,
        target.tls_server_name,
        target.ws_host,
        ctx.conn_id);
    if (!build_result) {
        const ErrorCode code = build_result.error();
        auto result = DialResult::Fail(
            code,
            std::string("outbound transport build failed: ") +
                std::string(ErrorCodeToString(code)));
        result.attempted_remote_addr = candidate.endpoint.address();
        co_return result;
    }

    auto stream = std::move(*build_result);
    stream->ClearPhaseDeadline();
    // 后续 outbound handler / relay 阶段会重新设置 idle/read/write timeout。
    stream->SetIdleTimeout(std::chrono::seconds(0));

    auto result = DialResult::Success(std::move(stream));
    result.attempted_remote_addr = candidate.endpoint.address();
    co_return result;
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
                       "dial candidate failed endpoint={}:{} > {}",
                       iputil::AddressText(candidate.endpoint.address()).View(),
                       candidate.endpoint.port(),
                       attempt.error_msg);
        last_result = std::move(attempt);
    }

    co_return last_result;
}

net::awaitable<DialResult> DialXHttpSplitOutboundTransport(
    net::io_context& io_context,
    session::Context& ctx,
    const OutboundTransportTarget& target) {

    if (!target.stream_settings) {
        co_return DialResult::Fail(ErrorCode::INVALID_ARGUMENT, "missing stream settings");
    }

    const auto mode = ResolveXHttpOutboundMode(*target.stream_settings);
    if (mode != XHttpMode::PacketUp && mode != XHttpMode::StreamUp) {
        co_return DialResult::Fail(ErrorCode::PROTOCOL_UNSUPPORTED, "unsupported xhttp mode");
    }

    const OutboundTransportTarget& downlink_target =
        target.xhttp_download_target ? *target.xhttp_download_target : target;
    if (!downlink_target.stream_settings || !downlink_target.stream_settings->IsXHttp()) {
        co_return DialResult::Fail(
            ErrorCode::INVALID_ARGUMENT,
            "invalid xhttp downlink target");
    }

    const memory::ThreadLocalString session_id = MakeXHttpSessionId(ctx.conn_id);
    const memory::ThreadLocalString downlink_path = BuildXHttpSplitPath(
        downlink_target.stream_settings->xhttp, session_id);
    const memory::ThreadLocalString upload_path = BuildXHttpSplitPath(
        target.stream_settings->xhttp, session_id);

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
                       "XHTTP downlink candidate failed endpoint={}:{} > {}",
                       iputil::AddressText(candidate.endpoint.address()).View(),
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

    if (mode == XHttpMode::PacketUp) {
        auto result = DialResult::Success(
            std::make_unique<XHttpPacketUpClientStream>(
                io_context,
                std::move(downlink),
                target,
                *upload_candidate,
                upload_path,
                ctx.conn_id));
        result.attempted_remote_addr = selected->endpoint.address();
        co_return result;
    }

    auto result = DialResult::Success(
        std::make_unique<XHttpSplitClientStream>(
            io_context,
            std::move(downlink),
            target,
            *upload_candidate,
            upload_path,
            ctx.conn_id));
    result.attempted_remote_addr = selected->endpoint.address();
    co_return result;
}

}  // namespace

net::awaitable<DialResult> DialOutboundTransport(
    net::io_context& io_context,
    session::Context& ctx,
    const OutboundTransportTarget& target) {


    DialResult result;
    if ((!target.single_candidate && target.candidates.empty()) ||
        target.stream_settings == nullptr) {
        result = DialResult::Fail(
            ErrorCode::INVALID_ARGUMENT, "invalid outbound transport target");
    } else if (IsXHttpSplitOutbound(target)) {
        result = co_await DialXHttpSplitOutboundTransport(io_context, ctx, target);
    } else if (target.single_candidate) {
        result = co_await DialAndBuildSingleCandidate(
            io_context, ctx, target, *target.single_candidate);
    } else if (target.candidates.size() == 1) {
        result = co_await DialAndBuildSingleCandidate(
            io_context, ctx, target, target.candidates.front());
    } else {
        result = co_await DialAndBuildCandidatesSequential(
            io_context, ctx, target, target.candidates);
    }

    co_return result;
}

}  // namespace acpp
