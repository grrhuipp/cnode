#include "transport/internet/outbound_target_builder.hpp"
#include "app/dns/dns.hpp"
#include "common/allocator.hpp"
#include "common/ip_utils.hpp"
#include "core/constants.hpp"
#include "transport/internet/http_headers.hpp"
#include "common/buffer_util.hpp"
#include "transport/internet/async_write_gate.hpp"
#include "common/session.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "transport/internet/transport_stack.hpp"
#include "infra/log.hpp"

#include <asio/ip/network_v4.hpp>
#include <asio/ip/network_v6.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>


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
    const auto candidates = target.Candidates();
    if (!candidates.empty()) {
        return candidates.front();
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

class XHttpSplitOutboundStreamBase : public AsyncStream {
protected:
    struct DownlinkCancellation final : transport::CancellationSubscription {
        explicit DownlinkCancellation(XHttpSplitOutboundStreamBase& owner) noexcept
            : owner(owner) {}
        XHttpSplitOutboundStreamBase& owner;

    private:
        void OnCancellation(transport::Cancellation event) noexcept override {
            owner.OnDownlinkCancellation(event);
        }
    };

    struct InFlightUploadScope final : transport::CancellationSubscription {
        XHttpSplitOutboundStreamBase& owner;
        TcpStream* tcp;

        InFlightUploadScope(XHttpSplitOutboundStreamBase& owner, TcpStream* tcp) noexcept
            : owner(owner), tcp(tcp) {
            owner.in_flight_upload_tcp_ = tcp;
            if (tcp) {
                Resubscribe(tcp->Cancellation());
            }
        }

        ~InFlightUploadScope() noexcept {
            Unsubscribe();
            if (tcp) {
                const bool write_expired = tcp->ConsumeWriteTimeout();
                const bool idle_expired = tcp->ConsumeIdleTimeout();
                const bool deadline_expired = tcp->ConsumePhaseDeadline();
                if (write_expired || idle_expired || deadline_expired) {
                    owner.upload_write_expired_ = true;
                }
            }
            if (owner.in_flight_upload_tcp_ == tcp) {
                owner.in_flight_upload_tcp_ = nullptr;
            }
        }

    private:
        void OnCancellation(transport::Cancellation event) noexcept override {
            if (!tcp) return;
            const bool write_expired = tcp->ConsumeWriteTimeout();
            const bool idle_expired = tcp->ConsumeIdleTimeout();
            const bool deadline_expired = tcp->ConsumePhaseDeadline();
            if (write_expired || idle_expired || deadline_expired) {
                owner.upload_write_expired_ = true;
            }
            if (event.terminal) {
                if (owner.in_flight_upload_tcp_ == tcp) {
                    owner.in_flight_upload_tcp_ = nullptr;
                }
                tcp = nullptr;
            } else {
                Resubscribe(tcp->Cancellation());
            }
        }
    };

    XHttpSplitOutboundStreamBase(net::io_context& io_context,
                                 std::unique_ptr<AsyncStream> downlink,
                                 const OutboundTransportTarget& target,
                                 const OutboundDialCandidate& candidate,
                                 memory::ThreadLocalString upload_path,
                                 uint64_t conn_id,
                                 const char* missing_settings_error)
        : io_context_(io_context)
        , downlink_(std::move(downlink))
        , target_(target)
        , candidate_(candidate)
        , upload_path_(std::move(upload_path))
        , base_upload_path_size_(upload_path_.size())
        , conn_id_(conn_id) {
        if (!target_.stream_settings) {
            ThrowXHttpPacketError(missing_settings_error);
        }
        upload_path_.reserve(base_upload_path_size_ + 21);
        target_.single_candidate = candidate_;
        memory::ThreadLocalVector<OutboundDialCandidate>{target_.candidates.get_allocator()}.swap(target_.candidates);
        target_.xhttp_download_target.reset();
    }

public:
    void ShutdownRead() override {
        if (downlink_) {
            downlink_->ShutdownRead();
        }
    }

    void SetWriteTimeout(std::chrono::seconds timeout) override {
        write_timeout_ = timeout;
        upload_write_expired_ = false;
        if (downlink_) {
            downlink_->SetWriteTimeout(timeout);
        }
        if (in_flight_upload_tcp_) {
            in_flight_upload_tcp_->SetWriteTimeout(timeout);
        }
    }

    bool ConsumeWriteTimeout() noexcept override {
        const bool downlink_expired = downlink_ && downlink_->ConsumeWriteTimeout();
        const bool in_flight_expired =
            in_flight_upload_tcp_ && in_flight_upload_tcp_->ConsumeWriteTimeout();
        const bool prior_upload_expired = std::exchange(upload_write_expired_, false);
        return downlink_expired || in_flight_expired || prior_upload_expired;
    }

    void Cancel() noexcept override {
        NotifyCancellation();
        if (downlink_) {
            downlink_->Cancel();
        }
        if (in_flight_upload_tcp_) {
            in_flight_upload_tcp_->Cancel();
        }
    }

    void Close() override {
        CloseImpl(false);
    }

    void CloseAbortive() override {
        CloseImpl(true);
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

    void SubscribeDownlink() noexcept {
        if (downlink_) {
            downlink_cancel_.Resubscribe(downlink_->Cancellation());
        }
    }

    void TouchDownlinkActivity() noexcept {
        if (downlink_) {
            if (auto* tcp = BaseTcpStreamOf(*downlink_)) {
                tcp->TouchActivity();
            }
        }
    }

    virtual void CloseUpload(bool /*abortive*/) {}
    virtual void CancelUpload() noexcept {}

    void OnDownlinkCancellation(transport::Cancellation event) noexcept {
        if (event.terminal) {
            if (downlink_ && (downlink_->ConsumeWriteTimeout() ||
                              downlink_->ConsumeIdleTimeout() ||
                              downlink_->ConsumePhaseDeadline())) {
                upload_write_expired_ = true;
            }
            write_closed_ = true;
            upload_gate_.Cancel();
            if (in_flight_upload_tcp_) {
                in_flight_upload_tcp_->CloseAbortive();
            }
            CloseUpload(true);
            this->NotifyClosed(event.reason);
        } else {
            if (downlink_ && (downlink_->ConsumeWriteTimeout() ||
                              downlink_->ConsumeIdleTimeout() ||
                              downlink_->ConsumePhaseDeadline())) {
                upload_write_expired_ = true;
            }
            if (in_flight_upload_tcp_) {
                in_flight_upload_tcp_->Cancel();
            }
            CancelUpload();
            if (downlink_) {
                downlink_cancel_.Resubscribe(downlink_->Cancellation());
            }
            this->NotifyCancellation(event.reason);
        }
    }

    void CloseImpl(bool abortive) {
        downlink_cancel_.Unsubscribe();
        NotifyClosed();
        if (closed_) {
            return;
        }
        closed_ = true;
        write_closed_ = true;
        upload_gate_.Cancel();
        if (in_flight_upload_tcp_) {
            in_flight_upload_tcp_->CloseAbortive();
        }
        CloseUpload(abortive);
        if (downlink_) {
            if (abortive) {
                downlink_->CloseAbortive();
            } else {
                downlink_->Close();
            }
        }
    }
    net::awaitable<std::unique_ptr<AsyncStream>> DialAndBuildUploadRequest(
        std::string_view path,
        XHttpClientRequestKind kind,
        std::span<const net::const_buffer> payloads) {
        const bool stream_up = kind == XHttpClientRequestKind::StreamUp;
        auto tcp_result = co_await DialSingleCandidate(io_context_, target_, candidate_);
        if (!tcp_result.Ok()) {
            if (tcp_result.error == ErrorCode::DIAL_TIMEOUT) {
                upload_write_expired_ = true;
                throw IoSystemError(io_error::timed_out,
                    stream_up ? "xhttp stream-up dial timed out"
                              : "xhttp packet-up dial timed out");
            }
            ThrowXHttpPacketError(
                stream_up ? "xhttp stream-up dial failed"
                          : "xhttp packet-up dial failed");
        }
        if (closed_ || write_closed_) {
            tcp_result.stream->CloseAbortive();
            ThrowXHttpPacketError(
                stream_up ? "xhttp stream-up closed while dialing"
                          : "xhttp packet-up closed while dialing");
        }
        tcp_result.stream->SetIdleTimeout(target_.timeout);
        tcp_result.stream->SetWriteTimeout(write_timeout_);
        (void)tcp_result.stream->StartPhaseDeadline(target_.timeout);

        TransportBuildResult build_result;
        {
            InFlightUploadScope in_flight_scope(*this, BaseTcpStreamOf(*tcp_result.stream));
            build_result = co_await BuildOutboundXHttpClientRequest(
                std::move(tcp_result.stream),
                *target_.stream_settings,
                target_.security_context,
                target_.tls_server_name,
                target_.ws_host,
                path,
                kind,
                payloads,
                conn_id_);
        }
        if (!build_result || (stream_up && !*build_result)) {
            if ((!build_result && build_result.error() == ErrorCode::TIMEOUT) ||
                upload_write_expired_) {
                upload_write_expired_ = true;
                throw IoSystemError(io_error::timed_out,
                    stream_up ? "xhttp stream-up request timed out"
                              : "xhttp packet-up request timed out");
            }
            ThrowXHttpPacketError(
                stream_up ? "xhttp stream-up request failed"
                          : "xhttp packet-up request failed");
        }
        if (stream_up && (closed_ || write_closed_)) {
            (*build_result)->CloseAbortive();
            ThrowXHttpPacketError("xhttp stream-up closed while opening");
        }
        co_return std::move(*build_result);
    }

    net::io_context& io_context_;
    std::unique_ptr<AsyncStream> downlink_;
    TcpStream* in_flight_upload_tcp_ = nullptr;
    OutboundTransportTarget target_;
    OutboundDialCandidate candidate_;
    memory::ThreadLocalString upload_path_;
    size_t base_upload_path_size_ = 0;
    transport::internet::AsyncWriteGate upload_gate_;
    DownlinkCancellation downlink_cancel_{*this};
    std::chrono::seconds write_timeout_{0};
    uint64_t conn_id_ = 0;
    bool upload_write_expired_ = false;
    bool write_closed_ = false;
    bool closed_ = false;
};

class XHttpSplitClientStream final : public XHttpSplitOutboundStreamBase {
    struct UploadCancellation final : transport::CancellationSubscription {
        explicit UploadCancellation(XHttpSplitClientStream& owner) noexcept : owner(owner) {}
        XHttpSplitClientStream& owner;

    private:
        void OnCancellation(transport::Cancellation event) noexcept override {
            owner.OnUploadCancellation(event);
        }
    };

public:
    XHttpSplitClientStream(net::io_context& io_context,
                           std::unique_ptr<AsyncStream> downlink,
                           const OutboundTransportTarget& target,
                           const OutboundDialCandidate& candidate,
                           memory::ThreadLocalString upload_path,
                           uint64_t conn_id)
        : XHttpSplitOutboundStreamBase(
              io_context,
              std::move(downlink),
              target,
              candidate,
              std::move(upload_path),
              conn_id,
              "xhttp stream-up missing stream settings") {
        SubscribeDownlink();
    }

    ~XHttpSplitClientStream() noexcept override {
        upload_cancel_.Unsubscribe();
        downlink_cancel_.Unsubscribe();
        Close();
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        if (!downlink_) {
            co_return 0;
        }
        if (ReaderMustSendDeferredUpload()) {
            co_await FlushDeferredUploadForRead();
        }
        co_return co_await downlink_->AsyncRead(buffer);
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        // upload_failed_ is provisionally set while an open is in flight;
        // only a finished failed open poisons the stream.
        if (closed_ || write_closed_ || (upload_failed_ && !upload_opening_)) {
            ThrowXHttpPacketError("xhttp stream-up upload unavailable");
        }
        if (buffer.size() == 0) {
            co_return 0;
        }
        auto lease = co_await AcquireUploadGate();
        if (!upload_ &&
            buffer.size() <= kMaxDeferredUploadBytes - pending_initial_.byte_size()) {
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            if (!buf::AppendSpanToMultiBuffer(
                    std::span<const uint8_t>(data, buffer.size()),
                    pending_initial_)) {
                throw std::bad_alloc();
            }
            co_return buffer.size();
        }
        if (upload_) {
            const size_t n = co_await upload_->AsyncWrite(buffer);
            TouchDownlinkActivity();
            co_return n;
        }
        co_await OpenUploadLocked({&buffer, 1});
        TouchDownlinkActivity();
        co_return buffer.size();
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!downlink_) {
            co_return buf::MultiBuffer{};
        }
        if (ReaderMustSendDeferredUpload()) {
            co_await FlushDeferredUploadForRead();
        }
        co_return co_await downlink_->ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (closed_ || write_closed_ || (upload_failed_ && !upload_opening_)) {
            mb.clear();
            ThrowXHttpPacketError("xhttp stream-up upload unavailable");
        }
        if (mb.byte_size() == 0) {
            mb.clear();
            co_return;
        }
        transport::internet::AsyncWriteGate::Lease lease;
        try {
            lease = co_await AcquireUploadGate();
            if (upload_) {
                co_await upload_->WriteMultiBuffer(std::move(mb));
                TouchDownlinkActivity();
                co_return;
            }
            ConstBufferSpanBuilder<16> payloads;
            payloads.AppendMultiBuffer(mb);
            if (!payloads.empty()) {
                co_await OpenUploadLocked(payloads.Span());
                TouchDownlinkActivity();
            }
        } catch (...) {
            mb.clear();
            throw;
        }
        mb.clear();
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (closed_ || write_closed_ || (upload_failed_ && !upload_opening_)) {
            ThrowXHttpPacketError("xhttp stream-up upload unavailable");
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
        auto lease = co_await AcquireUploadGate();
        if (upload_) {
            co_await upload_->WriteBuffers(buffers);
            TouchDownlinkActivity();
            co_return;
        }
        co_await OpenUploadLocked(buffers);
        TouchDownlinkActivity();
    }

    void ShutdownWrite() override {
        if (write_closed_) {
            return;
        }
        write_closed_ = true;
        upload_cancel_.Unsubscribe();
        pending_initial_.clear();
        if (upload_) {
            upload_->ShutdownWrite();
        }
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (closed_ || write_closed_) {
            co_return;
        }
        auto lease = upload_gate_.TryAcquire();
        if (!lease) lease = co_await upload_gate_.Acquire();
        if (!lease || closed_ || write_closed_) {
            co_return;
        }
        if (!upload_ && pending_initial_.byte_size() != 0) {
            if (upload_failed_) {
                ThrowXHttpPacketError("xhttp stream-up upload unavailable");
            }
            co_await OpenUploadLocked({});
        }
        write_closed_ = true;
        if (upload_) {
            try {
                co_await upload_->AsyncShutdownWrite();
            } catch (...) {
                upload_cancel_.Unsubscribe();
                throw;
            }
        }
        upload_cancel_.Unsubscribe();
    }

    void SetWriteTimeout(std::chrono::seconds timeout) override {
        XHttpSplitOutboundStreamBase::SetWriteTimeout(timeout);
        if (upload_) {
            upload_->SetWriteTimeout(timeout);
        }
    }

    bool ConsumeWriteTimeout() noexcept override {
        const bool base_expired = XHttpSplitOutboundStreamBase::ConsumeWriteTimeout();
        const bool upload_expired = upload_ && upload_->ConsumeWriteTimeout();
        return base_expired || upload_expired;
    }

    void Cancel() noexcept override {
        XHttpSplitOutboundStreamBase::Cancel();
        if (upload_) {
            upload_->Cancel();
        }
    }

    void Close() override {
        upload_cancel_.Unsubscribe();
        XHttpSplitOutboundStreamBase::Close();
    }

    void CloseAbortive() override {
        upload_cancel_.Unsubscribe();
        XHttpSplitOutboundStreamBase::CloseAbortive();
    }

protected:
    void CloseUpload(bool abortive) override {
        upload_cancel_.Unsubscribe();
        pending_initial_.clear();
        if (!upload_) {
            return;
        }
        if (abortive) {
            upload_->CloseAbortive();
        } else {
            upload_->Close();
        }
    }

    void CancelUpload() noexcept override {
        if (upload_) {
            upload_->Cancel();
        }
    }

private:
    void OnUploadCancellation(transport::Cancellation event) noexcept {
        if (!upload_) {
            return;
        }
        if (upload_->ConsumeWriteTimeout()) {
            upload_write_expired_ = true;
        }
        if (write_closed_) {
            upload_cancel_.Unsubscribe();
            return;
        }
        if (event.terminal) {
            write_closed_ = true;
            upload_gate_.Cancel();
            downlink_cancel_.Unsubscribe();
            if (downlink_) {
                downlink_->CloseAbortive();
            }
            NotifyClosed(event.reason);
        } else {
            upload_cancel_.Resubscribe(upload_->Cancellation());
            this->NotifyCancellation(event.reason);
        }
    }

    // A reader may wait for the reply to deferred bytes (e.g. a protocol
    // header); it sends them unless a writer is already opening the upload.
    [[nodiscard]] bool ReaderMustSendDeferredUpload() const noexcept {
        return !upload_ && !upload_opening_ && !write_closed_ &&
               pending_initial_.byte_size() != 0;
    }

    net::awaitable<transport::internet::AsyncWriteGate::Lease> AcquireUploadGate() {
        auto lease = upload_gate_.TryAcquire();
        if (!lease) lease = co_await upload_gate_.Acquire();
        if (!lease || closed_ || write_closed_ || upload_failed_) {
            ThrowXHttpPacketError("xhttp stream-up upload unavailable");
        }
        co_return lease;
    }

    net::awaitable<void> FlushDeferredUploadForRead() {
        auto lease = upload_gate_.TryAcquire();
        if (!lease) lease = co_await upload_gate_.Acquire();
        if (!lease || closed_ || upload_failed_) {
            ThrowXHttpPacketError("xhttp stream-up upload unavailable");
        }
        if (!upload_ && !write_closed_ && pending_initial_.byte_size() != 0) {
            co_await OpenUploadLocked({});
        }
    }

    // Single-flight under upload_gate_: the first caller opens the upload
    // request carrying the deferred bytes followed by |payload|. A failed open
    // poisons the stream, since the deferred bytes are gone with it.
    net::awaitable<void> OpenUploadLocked(std::span<const net::const_buffer> payload) {
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

        upload_ = co_await DialAndBuildUploadRequest(
            upload_path_, XHttpClientRequestKind::StreamUp, initial_payload.Span());
        upload_->ClearPhaseDeadline();
        upload_->SetIdleTimeout(std::chrono::seconds(0));
        upload_->SetWriteTimeout(write_timeout_);
        upload_failed_ = false;
        upload_cancel_.Resubscribe(upload_->Cancellation());
    }

    std::unique_ptr<AsyncStream> upload_;
    buf::MultiBuffer pending_initial_;
    UploadCancellation upload_cancel_{*this};
    bool upload_opening_ = false;
    bool upload_failed_ = false;
};

class XHttpPacketUpClientStream final : public XHttpSplitOutboundStreamBase {
public:
    XHttpPacketUpClientStream(net::io_context& io_context,
                              std::unique_ptr<AsyncStream> downlink,
                              const OutboundTransportTarget& target,
                              const OutboundDialCandidate& candidate,
                              memory::ThreadLocalString upload_path,
                              uint64_t conn_id)
        : XHttpSplitOutboundStreamBase(
              io_context,
              std::move(downlink),
              target,
              candidate,
              std::move(upload_path),
              conn_id,
              "xhttp packet-up missing stream settings") {
        SubscribeDownlink();
    }

    ~XHttpPacketUpClientStream() noexcept override {
        downlink_cancel_.Unsubscribe();
        Close();
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        return downlink_->AsyncRead(buffer);
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (closed_ || write_closed_) {
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
        if (closed_ || write_closed_) {
            mb.clear();
            ThrowXHttpPacketError("xhttp packet-up write after shutdown");
        }
        return AsyncStream::WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (closed_ || write_closed_) {
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

    void ShutdownWrite() override {
        write_closed_ = true;
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        write_closed_ = true;
        co_return;
    }

private:
    net::awaitable<void> SendPacket(std::span<const net::const_buffer> payloads) {
        auto lease = upload_gate_.TryAcquire();
        if (!lease) lease = co_await upload_gate_.Acquire();
        if (!lease || closed_ || write_closed_) {
            ThrowXHttpPacketError("xhttp packet-up write after shutdown");
        }

        const uint64_t seq = next_seq_++;
        // Packet-up request target: "<upload path>/<seq>".
        upload_path_.resize(base_upload_path_size_);
        upload_path_.push_back('/');
        std::array<char, 20> seq_text{};
        const auto [seq_end, ec] = std::to_chars(
            seq_text.data(), seq_text.data() + seq_text.size(), seq);
        (void)ec;  // 20 digits always fit a uint64_t.
        upload_path_.append(seq_text.data(), static_cast<size_t>(seq_end - seq_text.data()));

        (void)co_await DialAndBuildUploadRequest(
            upload_path_, XHttpClientRequestKind::PacketUp, payloads);
        TouchDownlinkActivity();
    }

    uint64_t next_seq_ = 0;
};

net::awaitable<DialResult> DialSingleCandidate(
    net::io_context& io_context,
    const OutboundTransportTarget& target,
    const OutboundDialCandidate& candidate) {

    auto bind_local = candidate.bind_local;

    if (bind_local) {
        co_return co_await TcpStream::ConnectWithBind(
            io_context, *bind_local, candidate.endpoint, target.timeout);
    }
    co_return co_await TcpStream::Connect(
        io_context, candidate.endpoint, target.timeout);
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
        co_return DialResult::Fail(build_result.error());
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
        target.security_context,
        target.tls_server_name,
        target.ws_host,
        ctx.conn_id);
    if (!build_result) {
        co_return DialResult::Fail(build_result.error());
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

    for (const auto& candidate : downlink_target.Candidates()) {
        if (co_await try_downlink_candidate(candidate)) {
            break;
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
        co_return DialResult::Success(
            std::make_unique<XHttpPacketUpClientStream>(
                io_context,
                std::move(downlink),
                target,
                *upload_candidate,
                upload_path,
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


uint64_t MixHash(uint64_t value) noexcept {
    value += 0x9e3779b97f4a7c15ull;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ull;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebull;
    return value ^ (value >> 31);
}

uint64_t IpKeyHash(std::string_view ip) noexcept {
    uint64_t value = 14695981039346656037ull;
    for (const unsigned char byte : ip) {
        value = (value ^ byte) * 1099511628211ull;
    }
    return MixHash(value);
}

uint64_t UserKeyHash(
    int64_t user_id,
    std::string_view user_email,
    std::string_view fallback_ip,
    std::string_view inbound_tag) noexcept {
    if (user_id <= 0 && user_email.empty()) {
        return IpKeyHash(fallback_ip);
    }
    uint64_t value = 14695981039346656037ull;
    for (const unsigned char byte : inbound_tag) {
        value = (value ^ byte) * 1099511628211ull;
    }
    value = (value ^ 0xffu) * 1099511628211ull;
    const uint64_t uid = user_id > 0 ? static_cast<uint64_t>(user_id) : 0;
    for (unsigned shift = 0; shift < 64; shift += 8) {
        value = (value ^ static_cast<unsigned char>(uid >> shift)) *
                1099511628211ull;
    }
    value = (value ^ 0xffu) * 1099511628211ull;
    for (const unsigned char byte : user_email) {
        value = (value ^ byte) * 1099511628211ull;
    }
    return MixHash(value);
}

uint64_t RandomIndex() noexcept {
    static thread_local uint64_t state =
        static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()) ^
        std::hash<std::thread::id>{}(std::this_thread::get_id()) ^
        0x9e3779b97f4a7c15ull;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return state * 2685821657736338717ull;
}

[[nodiscard]] std::optional<OutboundDialer::OrderedBind> SelectOrderedBind(
    const OutboundBind& bind,
    std::string_view source_ip,
    int64_t user_id,
    std::string_view user_email,
    std::string_view inbound_tag) {
    if (bind.GetMode() != OutboundBind::Mode::Ordered) return std::nullopt;
    return OutboundDialer::OrderedBind{
        .v4 = bind.Select(net::ip::address_v4::any(), source_ip, user_id, user_email, inbound_tag),
        .v6 = bind.Select(net::ip::address_v6::any(), source_ip, user_id, user_email, inbound_tag),
    };
}

bool AutoPrefersIPv6(const OutboundBind& bind,
                     const tcp::endpoint* inbound_local_addr) noexcept {
    if (bind.GetMode() != OutboundBind::Mode::Auto || !inbound_local_addr) {
        return false;
    }
    const auto inbound_local =
        iputil::NormalizeAddress(inbound_local_addr->address());
    return inbound_local.is_v6() && !inbound_local.is_unspecified() &&
           !inbound_local.is_loopback() &&
           !inbound_local.to_v6().is_link_local();
}

// The explicit host is resolved once by stream-settings normalization; only
// the dial-address fallback is formatted per target.
[[nodiscard]] memory::ThreadLocalString BuildHttpHostHeader(
    const StreamSettings& settings,
    std::string_view fallback_host,
    uint16_t port) {
    if (!settings.IsWs() && !settings.IsHttpUpgrade() &&
        !settings.IsHttp() && !settings.IsGrpc() && !settings.IsXHttp()) {
        return {};
    }
    if (!settings.configured_http_host.empty()) {
        return memory::ThreadLocalString(settings.configured_http_host);
    }
    if (settings.IsGrpc() && settings.IsReality()) {
        return {};
    }
    const std::string_view effective_host =
        (settings.IsReality() && !settings.reality.server_name.empty())
            ? std::string_view(settings.reality.server_name)
            : fallback_host;
    memory::ThreadLocalString out;
    iputil::FormatHttpHostHeaderInto(
        out, effective_host, port, settings.IsTlsLike());
    return out;
}

net::awaitable<tl::expected<OutboundTransportTarget, ErrorCode>>
AttachXHttpDownloadTarget(
    OutboundTransportTarget target,
    const OutboundTargetOptions& options,
    const tcp::endpoint* inbound_local_addr,
    const std::optional<OutboundDialer::OrderedBind>& download_ordered) {
    if (!options.stream_settings ||
        !options.stream_settings->IsXHttp() ||
        !options.stream_settings->xhttp.download_settings) {
        co_return target;
    }

    const auto& upload_xhttp = options.stream_settings->xhttp;
    if (upload_xhttp.IsStreamOne()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    const auto& download = *upload_xhttp.download_settings;
    if (download.address.empty() || download.port == 0) {
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    // A download target never carries its own downloadSettings; reject rather
    // than silently ignore a nested one.
    if (!download.stream_settings.IsXHttp() ||
        download.stream_settings.IsUnsupported() ||
        download.stream_settings.xhttp.IsStreamOne() ||
        download.stream_settings.xhttp.download_settings) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    auto download_target = co_await BuildOutboundTransportTarget(
        OutboundTargetOptions{
            .dns_service = options.dns_service,
            .address = download.address,
            .literal_address = std::nullopt,
            .port = download.port,
            .stream_settings = &download.stream_settings,
            .security = options.security ? options.security->XHttpDownload() : nullptr,
            .timeout = options.timeout,
            .send_through = &download.send_through,
            .inbound_local_addr = inbound_local_addr,
            .inbound_user_id = options.inbound_user_id,
            .ordered_bind_v4 = download_ordered ? std::optional{download_ordered->v4} : std::nullopt,
            .ordered_bind_v6 = download_ordered ? std::optional{download_ordered->v6} : std::nullopt,
        });
    if (!download_target) {
        co_return tl::unexpected(download_target.error());
    }

    target.xhttp_download_target =
        memory::AllocateShared<OutboundTransportTarget>(std::move(*download_target));
    co_return target;
}
}  // namespace

__attribute__((weak)) net::awaitable<DialResult> DialOutboundTransport(
    net::io_context& io_context,
    session::Context& ctx,
    const OutboundTransportTarget& target) {


    const auto candidates = target.Candidates();
    DialResult result;
    if (candidates.empty() || target.stream_settings == nullptr) {
        result = DialResult::Fail(
            ErrorCode::INVALID_ARGUMENT, "invalid outbound transport target");
    } else if (IsXHttpSplitOutbound(target)) {
        result = co_await DialXHttpSplitOutboundTransport(io_context, ctx, target);
    } else if (candidates.size() == 1) {
        result = co_await DialAndBuildSingleCandidate(
            io_context, ctx, target, candidates.front());
    } else {
        result = co_await DialAndBuildCandidatesSequential(
            io_context, ctx, target, candidates);
    }

    co_return result;
}


OutboundBind OutboundBind::Auto() noexcept {
    OutboundBind bind;
    bind.mode_ = Mode::Auto;
    return bind;
}

std::optional<net::ip::address> OutboundBind::BindAddressFor(
    const tcp::endpoint* inbound_local, const net::ip::address& remote) const noexcept {
    if (mode_ == Mode::Explicit) {
        return explicit_address_;
    }
    if (mode_ != Mode::Auto || !inbound_local) {
        return std::nullopt;
    }
    // Same-in-same-out: reuse the inbound local address when it can source
    // a connection to `remote`.
    const auto local = iputil::NormalizeAddress(inbound_local->address());
    const auto normalized_remote = iputil::NormalizeAddress(remote);
    if (local.is_unspecified() || local.is_loopback() ||
        normalized_remote.is_unspecified() || normalized_remote.is_loopback() ||
        local.is_v4() != normalized_remote.is_v4()) {
        return std::nullopt;
    }
    if (local.is_v6() &&
        (local.to_v6().is_link_local() || normalized_remote.to_v6().is_link_local())) {
        return std::nullopt;
    }
    return local;
}

std::optional<OutboundBind> OutboundBind::Parse(std::string_view value) {
    OutboundBind bind;
    if (value.empty()) return bind;
    if (transport::internet::EqualsAsciiCI(value, constants::binding::kAuto)) return Auto();

    auto address = iputil::ParseLiteral(value);
    if (!address) return std::nullopt;
    *address = iputil::NormalizeAddress(*address);
    if (address->is_unspecified()) return bind;
    bind.mode_ = Mode::Explicit;
    bind.explicit_address_ = std::move(*address);
    return bind;
}

std::optional<OutboundBind> OutboundBind::ParseCandidates(
    std::span<const std::string_view> entries, ChoicePolicy policy) {
    if (entries.empty()) return std::nullopt;
    OutboundBind bind;
    bind.mode_ = Mode::Ordered;
    bind.policy_ = policy;
    std::vector<Entry> prepared;
    prepared.reserve(entries.size());
    for (const auto text : entries) {
        if (text.empty() || text.find('\0') != std::string_view::npos) return std::nullopt;
        Entry entry;
        const auto slash = text.find('/');
        auto address = iputil::ParseLiteral(text.substr(0, slash));
        if (!address) return std::nullopt;
        const auto normalized = iputil::NormalizeAddress(*address);
        if (slash != std::string_view::npos && address->is_v6() != normalized.is_v6()) {
            return std::nullopt;
        }
        *address = normalized;
        entry.is_v6 = address->is_v6();
        const unsigned int max_prefix = entry.is_v6 ? 128 : 32;
        unsigned int prefix = max_prefix;
        if (slash != std::string_view::npos) {
            const auto length = text.substr(slash + 1);
            if (length.empty() || (length.size() > 1 && length.front() == '0')) {
                return std::nullopt;
            }
            const auto [end, error] = std::from_chars(
                length.data(), length.data() + length.size(), prefix);
            if (error != std::errc{} || end != length.data() + length.size() ||
                prefix > max_prefix) return std::nullopt;
        }
        entry.prefix_length = static_cast<uint8_t>(prefix);
        entry.network_or_ip = slash == std::string_view::npos ? *address :
            entry.is_v6
                ? net::ip::address(net::ip::network_v6(
                    address->to_v6(), static_cast<unsigned short>(prefix)).network())
                : net::ip::address(net::ip::network_v4(
                    address->to_v4(), static_cast<unsigned short>(prefix)).network());
        if (entry.network_or_ip.is_unspecified()) return std::nullopt;
        prepared.push_back(std::move(entry));
    }
    bind.entries_ = std::make_shared<const std::vector<Entry>>(std::move(prepared));
    return bind;
}

OutboundBind::Selection OutboundBind::Select(
    const net::ip::address& remote,
    std::string_view client_ip,
    int64_t user_id,
    std::string_view user_email,
    std::string_view inbound_tag) const noexcept {
    if (mode_ == Mode::Explicit) return {.address = explicit_address_};
    if (mode_ != Mode::Ordered) return {};

    const auto normalized_remote = iputil::NormalizeAddress(remote);
    for (const auto& entry : *entries_) {
        if (entry.is_v6 != normalized_remote.is_v6()) continue;
        if (entry.prefix_length == (entry.is_v6 ? 128 : 32)) {
            return {.address = entry.network_or_ip};
        }
        const uint64_t key = policy_ == ChoicePolicy::Random
            ? RandomIndex()
            : policy_ == ChoicePolicy::UserHash
                ? UserKeyHash(user_id, user_email, client_ip, inbound_tag)
                : IpKeyHash(client_ip);
        if (!entry.is_v6) {
            const auto prefix = entry.prefix_length;
            const uint32_t mask = prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
            const uint32_t ip = (entry.network_or_ip.to_v4().to_uint() & mask) |
                (static_cast<uint32_t>(key) & ~mask);
            return {.address = net::ip::address_v4(ip)};
        }
        const auto v6 = entry.network_or_ip.to_v6();
        auto bytes = v6.to_bytes();
        const uint64_t high = key;
        const uint64_t low = policy_ == ChoicePolicy::Random ? RandomIndex() : MixHash(key);
        for (size_t i = 0; i < bytes.size(); ++i) {
            const unsigned bits = entry.prefix_length > i * 8
                ? std::min<unsigned>(8, entry.prefix_length - static_cast<unsigned>(i * 8))
                : 0;
            const uint8_t mask = bits == 0 ? 0 : static_cast<uint8_t>(0xffu << (8 - bits));
            const uint64_t word = i < 8 ? high : low;
            const unsigned shift = static_cast<unsigned>(i < 8 ? (7 - i) * 8 : (15 - i) * 8);
            const auto suffix = static_cast<uint8_t>(word >> shift);
            bytes[i] = (bytes[i] & mask) | (suffix & static_cast<uint8_t>(~mask));
        }
        return {.address = net::ip::address_v6(bytes, v6.scope_id())};
    }
    return {};
}

std::string_view ResolveOutboundTlsServerName(
    const StreamSettings& settings,
    std::string_view fallback_server_name) {
    if (settings.IsReality() && !settings.reality.server_name.empty()) {
        return settings.reality.server_name;
    }
    if (!settings.tls.server_name.empty()) {
        return settings.tls.server_name;
    }
    return fallback_server_name;
}

net::awaitable<tl::expected<OutboundTransportTarget, ErrorCode>>
BuildOutboundTransportTarget(OutboundTargetOptions options) {
    if (!options.stream_settings || options.port == 0) {
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    if (!options.literal_address && options.address.empty()) {
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    const std::optional<tcp::endpoint> inbound_local = options.inbound_local_addr
        ? std::optional<tcp::endpoint>(*options.inbound_local_addr)
        : std::nullopt;
    const tcp::endpoint* const inbound_local_ptr =
        inbound_local ? &*inbound_local : nullptr;

    const OutboundBind unbound;
    const auto& bind = options.send_through ? *options.send_through : unbound;
    const auto default_ordered =
        (!options.ordered_bind_v4 || !options.ordered_bind_v6)
            ? SelectOrderedBind(
                  bind,
                  options.inbound_source_ip,
                  options.inbound_user_id,
                  options.inbound_user_email,
                  options.inbound_tag)
            : std::nullopt;
    const auto ordered_v4 = options.ordered_bind_v4
        ? *options.ordered_bind_v4
        : (default_ordered ? default_ordered->v4 : OutboundBind::Selection{});
    const auto ordered_v6 = options.ordered_bind_v6
        ? *options.ordered_bind_v6
        : (default_ordered ? default_ordered->v6 : OutboundBind::Selection{});

    std::optional<OutboundDialer::OrderedBind> download_ordered;
    if (options.stream_settings->IsXHttp() &&
        options.stream_settings->xhttp.download_settings) {
        download_ordered = SelectOrderedBind(
            options.stream_settings->xhttp.download_settings->send_through,
            options.inbound_source_ip,
            options.inbound_user_id,
            options.inbound_user_email,
            options.inbound_tag);
    }

    options.inbound_local_addr = nullptr;
    options.inbound_source_ip = {};
    options.inbound_user_email = {};
    options.inbound_tag = {};

    OutboundTransportTarget target;
    target.timeout = options.timeout;
    target.stream_settings = options.stream_settings;
    target.security_context = options.security ? options.security->Context() : nullptr;
    target.tls_server_name = ResolveOutboundTlsServerName(
        *options.stream_settings, options.address);
    target.ws_host = BuildHttpHostHeader(
        *options.stream_settings, options.address, options.port);

    auto make_candidate = [&](const net::ip::address& raw_remote_addr) {
        const net::ip::address remote_addr = iputil::NormalizeAddress(raw_remote_addr);
        OutboundDialCandidate candidate;
        candidate.endpoint = tcp::endpoint(remote_addr, options.port);
        if (bind.GetMode() == OutboundBind::Mode::Ordered) {
            const auto& selected = remote_addr.is_v6() ? ordered_v6 : ordered_v4;
            candidate.bind_local = selected.address;
        } else {
            candidate.bind_local = bind.BindAddressFor(inbound_local_ptr, remote_addr);
        }
        return candidate;
    };
    auto append_single = [&](const net::ip::address& raw_remote_addr) {
        target.single_candidate = make_candidate(raw_remote_addr);
    };

    if (options.literal_address) {
        append_single(*options.literal_address);
        co_return co_await AttachXHttpDownloadTarget(
            std::move(target),
            options,
            inbound_local_ptr,
            download_ordered);
    }
    if (auto literal = iputil::ParseLiteral(options.address)) {
        append_single(*literal);
        co_return co_await AttachXHttpDownloadTarget(
            std::move(target),
            options,
            inbound_local_ptr,
            download_ordered);
    }
    if (!options.dns_service) {
        co_return tl::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }

    auto dns_result = co_await options.dns_service->Resolve(options.address);
    if (!dns_result.Ok() || dns_result.addresses.empty()) {
        co_return tl::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }
    const size_t max_candidates = dns_result.addresses.size();
    auto add_candidate = [&](const net::ip::address& addr) {
        OutboundDialCandidate candidate = make_candidate(addr);
        if (!target.single_candidate && target.candidates.empty()) {
            target.single_candidate = std::move(candidate);
            return;
        }
        if (target.single_candidate) {
            target.candidates.reserve(max_candidates);
            target.candidates.push_back(std::move(*target.single_candidate));
            target.single_candidate.reset();
        }
        target.candidates.push_back(std::move(candidate));
    };
    auto finalize_candidates = [&]()
        -> net::awaitable<tl::expected<OutboundTransportTarget, ErrorCode>> {
        if (target.candidates.empty() && !target.single_candidate) {
            co_return tl::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
        }
        co_return co_await AttachXHttpDownloadTarget(
            std::move(target),
            options,
            inbound_local_ptr,
            download_ordered);
    };

    if (bind.GetMode() == OutboundBind::Mode::Explicit) {
        const bool want_v6 = bind.ExplicitAddress() &&
            iputil::NormalizeAddress(*bind.ExplicitAddress()).is_v6();
        for (const auto& raw_addr : dns_result.addresses) {
            const auto addr = iputil::NormalizeAddress(raw_addr);
            if (addr.is_v6() == want_v6) {
                add_candidate(addr);
            }
        }
        co_return co_await finalize_candidates();
    }

    if (bind.GetMode() == OutboundBind::Mode::Ordered ||
        AutoPrefersIPv6(bind, inbound_local_ptr)) {
        const bool prefer_v6 = bind.GetMode() == OutboundBind::Mode::Ordered
            ? bind.PrefersIPv6()
            : true;
        for (const bool ipv6 : {prefer_v6, !prefer_v6}) {
            for (const auto& raw_addr : dns_result.addresses) {
                const auto addr = iputil::NormalizeAddress(raw_addr);
                if (addr.is_v6() == ipv6) {
                    add_candidate(addr);
                }
            }
        }
        co_return co_await finalize_candidates();
    }

    for (const auto& raw_addr : dns_result.addresses) {
        const auto addr = iputil::NormalizeAddress(raw_addr);
        if (addr.is_v4()) {
            add_candidate(addr);
        }
    }
    if (target.single_candidate || !target.candidates.empty()) {
        co_return co_await finalize_candidates();
    }

    for (const auto& raw_addr : dns_result.addresses) {
        add_candidate(iputil::NormalizeAddress(raw_addr));
    }
    co_return co_await finalize_candidates();
}

OutboundDialer::OutboundDialer(net::io_context& io_context,
                               app::dns::DNS& dns,
                               const OutboundSenderSettings& sender,
                               std::chrono::seconds timeout)
    : io_context_(io_context)
    , dns_(dns)
    , sender_(sender)
    , security_(sender.stream_settings, StreamEndpointRole::Outbound)
    , timeout_(timeout) {}

ForwardedMetadataView OutboundDialer::ForwardedMetadata(
    const session::Context& ctx) const noexcept {
    return sender_.passthrough ? ctx.inbound.MakeForwardedMetadata()
                               : ForwardedMetadataView{};
}

std::optional<OutboundDialer::OrderedBind> OutboundDialer::SelectOrderedBind(
    const session::Context& ctx) const {
    return ::SelectOrderedBind(
        sender_.send_through,
        ctx.inbound.EffectiveClientIp(),
        ctx.inbound.EffectiveUserId(),
        ctx.inbound.EffectiveUserEmail(),
        ctx.inbound.EffectiveInboundTag());
}

net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
OutboundDialer::Dial(session::Context& ctx, const OutboundServer& server,
                     const OrderedBind* ordered) {
    auto target = co_await BuildOutboundTransportTarget(OutboundTargetOptions{
        .dns_service = &dns_,
        .address = server.address,
        .literal_address = server.literal_address,
        .port = server.port,
        .stream_settings = &sender_.stream_settings,
        .security = &security_,
        .timeout = timeout_,
        .send_through = &sender_.send_through,
        .inbound_local_addr = ctx.inbound.local_endpoint
            ? &*ctx.inbound.local_endpoint : nullptr,
        .inbound_source_ip = ctx.inbound.EffectiveClientIp(),
        .inbound_user_id = ctx.inbound.EffectiveUserId(),
        .inbound_user_email = ctx.inbound.EffectiveUserEmail(),
        .inbound_tag = ctx.inbound.EffectiveInboundTag(),
        .ordered_bind_v4 = ordered ? std::optional{ordered->v4} : std::nullopt,
        .ordered_bind_v6 = ordered ? std::optional{ordered->v6} : std::nullopt,
    });
    if (!target) {
        if (target.error() == ErrorCode::DNS_RESOLVE_FAILED) {
            LOG_CONN_WARN(ctx, "DNS resolve failed for {}", server.address);
        }
        co_return tl::unexpected(target.error());
    }
    co_return co_await DialTarget(ctx, *target);
}

net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
OutboundDialer::Dial(session::Context& ctx,
                     std::span<const net::ip::address> addresses,
                     uint16_t port) {
    if (addresses.empty() || port == 0) {
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    const auto& bind = sender_.send_through;
    const auto ordered = SelectOrderedBind(ctx);
    const tcp::endpoint* inbound_local =
        ctx.inbound.local_endpoint ? &*ctx.inbound.local_endpoint : nullptr;
    auto candidate_for = [&](const net::ip::address& raw_remote) {
        const net::ip::address remote = iputil::NormalizeAddress(raw_remote);
        return OutboundDialCandidate{
            .endpoint = tcp::endpoint(remote, port),
            .bind_local = ordered
                ? (remote.is_v6() ? ordered->v6.address : ordered->v4.address)
                : bind.BindAddressFor(inbound_local, remote),
        };
    };

    OutboundTransportTarget target;
    target.timeout = timeout_;
    target.stream_settings = &sender_.stream_settings;
    target.security_context = security_.Context();
    if (addresses.size() == 1) {
        target.single_candidate = candidate_for(addresses.front());
    } else {
        target.candidates.reserve(addresses.size());
        for (const auto& remote : addresses) {
            target.candidates.push_back(candidate_for(remote));
        }
    }
    LOG_CONN_DEBUG(ctx, "dialing {} resolved candidates port={}", addresses.size(), port);
    co_return co_await DialTarget(ctx, target);
}

net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
OutboundDialer::DialTarget(session::Context& ctx, const OutboundTransportTarget& target) {
    auto dialed = co_await DialOutboundTransport(IoContext(), ctx, target);
    if (!dialed.Ok()) {
        ctx.outbound.connected_local_addr.reset();
        // The dispatcher reports every non-cancellation failure once.
        LOG_CONN_DEBUG(ctx, "dial failed {} -> {} > {}",
                       ctx.inbound.source_ip, ctx.outbound.target, dialed.error_msg);
        co_return tl::unexpected(dialed.error);
    }
    RecordConnected(ctx, *dialed.stream);
    co_return std::move(dialed.stream);
}

tl::expected<net::ip::address, ErrorCode> OutboundDialer::SelectDatagramBind(
    const session::Context& ctx, const DatagramRemote& remote) const {
    const auto& bind = sender_.send_through;
    if (bind.GetMode() == OutboundBind::Mode::Explicit) {
        return iputil::NormalizeAddress(*bind.ExplicitAddress());
    }
    const std::optional<net::ip::address> remote_addr = remote.address
        ? std::optional<net::ip::address>(iputil::NormalizeAddress(*remote.address))
        : std::nullopt;
    const std::optional<net::ip::address> family_hint = remote.family_hint
        ? std::optional<net::ip::address>(iputil::NormalizeAddress(*remote.family_hint))
        : std::nullopt;
    // Same-in-same-out: reuse the inbound local address when it can source
    // the association (OutboundBind owns the family/scope rules).
    if (bind.GetMode() == OutboundBind::Mode::Auto && ctx.inbound.local_endpoint) {
        const auto* local = &*ctx.inbound.local_endpoint;
        if (remote_addr) {
            if (auto bound = bind.BindAddressFor(local, *remote_addr)) return *bound;
        } else {
            const auto local_ip = iputil::NormalizeAddress(local->address());
            if (local_ip.is_v6() ? remote.accepts_v6 : remote.accepts_v4) {
                if (auto bound = bind.BindAddressFor(local, local_ip)) return *bound;
            }
        }
    }
    const bool v6 = remote_addr ? remote_addr->is_v6()
        : (remote.prefers_v6 && remote.accepts_v6) ? true
        : !remote.accepts_v6 ? false
        : family_hint ? family_hint->is_v6()
        : bind.PrefersIPv6();
    const net::ip::address any = v6
        ? net::ip::address(net::ip::address_v6::any())
        : net::ip::address(net::ip::address_v4::any());
    if (bind.GetMode() != OutboundBind::Mode::Ordered) return any;

    const auto client_ip = ctx.inbound.EffectiveClientIp();
    const auto user_id = ctx.inbound.EffectiveUserId();
    const auto user_email = ctx.inbound.EffectiveUserEmail();
    const auto inbound_tag = ctx.inbound.EffectiveInboundTag();
    auto selected = bind.Select(remote_addr.value_or(any),
                                client_ip, user_id, user_email, inbound_tag);
    // A hostname may still be reached over the other accepted family.
    if (!selected.address && !remote_addr && (v6 ? remote.accepts_v4 : remote.accepts_v6)) {
        const net::ip::address other = v6
            ? net::ip::address(net::ip::address_v4::any())
            : net::ip::address(net::ip::address_v6::any());
        selected = bind.Select(other, client_ip, user_id, user_email, inbound_tag);
    }
    if (!selected.address) return tl::unexpected(ErrorCode::SOCKET_BIND_FAILED);
    return *selected.address;
}

void OutboundDialer::ReportDatagramFailure(const session::Context& ctx,
                                           const net::ip::address& bind,
                                           std::string_view reason) const {
    LOG_CONN_DEBUG(ctx, "failed to open UDP {} via {} > {}",
                   ctx.outbound.target, iputil::AddressText(bind).View(), reason);
}

void OutboundDialer::RecordConnected(session::Context& ctx, const AsyncStream& stream) const {
    const auto local = stream.LocalEndpoint();
    RecordEgress(ctx, local ? std::optional{local->address()} : std::nullopt);
}

void OutboundDialer::RecordEgress(session::Context& ctx,
                                  const std::optional<net::ip::address>& local) const {
    ctx.outbound.connected_local_addr.reset();
    if (local) {
        const auto local_ip = iputil::NormalizeAddress(*local);
        if (!local_ip.is_unspecified()) {
            ctx.outbound.connected_local_addr = local_ip;
        }
    }
    LOG_ACCESS(FormatAccessLog(ctx));
}
