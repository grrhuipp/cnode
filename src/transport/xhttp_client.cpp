#include "transport/xhttp_client.hpp"

#include "common/multi_buffer.hpp"
#include "common/binary_text_codec.hpp"
#include "common/const_buffer_span.hpp"
#include "common/ip_address.hpp"
#include "infra/log.hpp"
#include "transport/async_write_gate.hpp"
#include "transport/tcp_stream.hpp"
#include "transport/transport_stack.hpp"

#include <openssl/rand.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <string>
#include <vector>

namespace transport {

namespace {

[[nodiscard]] std::optional<OutboundDialCandidate> FirstDialCandidate(
    const OutboundTransportTarget& target) {
    const auto candidates = target.Candidates();
    if (!candidates.empty()) {
        return candidates.front();
    }
    return std::nullopt;
}

[[nodiscard]] std::string BuildXHttpSplitPath(
    const XHttpConfig& cfg,
    std::string_view session_id) {
    std::string path(cfg.normalized_path);
    path.append(session_id);
    return path;
}

[[nodiscard]] bool HasNonEmptyBuffer(std::span<const net::const_buffer> buffers) noexcept {
    for (const auto& buffer : buffers) {
        if (buffer.size() > 0) {
            return true;
        }
    }
    return false;
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
                                 std::string upload_path,
                                 uint64_t conn_id,
                                 const char* missing_settings_error)
        : io_context_(io_context)
        , downlink_(std::move(downlink))
        , stream_settings_(target.stream_settings)
        , security_context_(target.security_context)
        , tls_server_name_(target.tls_server_name)
        , ws_host_(target.HttpHost())
        , candidate_(candidate)
        , upload_path_(std::move(upload_path))
        , base_upload_path_size_(upload_path_.size())
        , timeout_(target.timeout)
        , conn_id_(conn_id) {
        if (!stream_settings_) {
            throw IoSystemError(io_error::broken_pipe, missing_settings_error);
        }
        upload_path_.reserve(base_upload_path_size_ + 21);
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
        auto tcp_result = co_await ConnectOutboundCandidate(io_context_, candidate_, timeout_);
        if (!tcp_result.Ok()) {
            if (tcp_result.error == common::ErrorCode::DIAL_TIMEOUT) {
                upload_write_expired_ = true;
                throw IoSystemError(io_error::timed_out,
                    stream_up ? "xhttp stream-up dial timed out"
                              : "xhttp packet-up dial timed out");
            }
            throw IoSystemError(io_error::broken_pipe,
                stream_up ? "xhttp stream-up dial failed"
                          : "xhttp packet-up dial failed");
        }
        if (closed_ || write_closed_) {
            tcp_result.stream->CloseAbortive();
            throw IoSystemError(io_error::broken_pipe,
                stream_up ? "xhttp stream-up closed while dialing"
                          : "xhttp packet-up closed while dialing");
        }
        tcp_result.stream->SetIdleTimeout(timeout_);
        tcp_result.stream->SetWriteTimeout(write_timeout_);
        (void)tcp_result.stream->StartPhaseDeadline(timeout_);

        TransportBuildResult build_result;
        {
            InFlightUploadScope in_flight_scope(*this, BaseTcpStreamOf(*tcp_result.stream));
            build_result = co_await BuildOutboundXHttpClientRequest(
                std::move(tcp_result.stream),
                *stream_settings_,
                security_context_,
                tls_server_name_,
                ws_host_,
                path,
                kind,
                payloads,
                conn_id_);
        }
        if (!build_result || (stream_up && !*build_result)) {
            if ((!build_result && build_result.error() == common::ErrorCode::TIMEOUT) ||
                upload_write_expired_) {
                upload_write_expired_ = true;
                throw IoSystemError(io_error::timed_out,
                    stream_up ? "xhttp stream-up request timed out"
                              : "xhttp packet-up request timed out");
            }
            throw IoSystemError(io_error::broken_pipe,
                stream_up ? "xhttp stream-up request failed"
                          : "xhttp packet-up request failed");
        }
        if (stream_up && (closed_ || write_closed_)) {
            (*build_result)->CloseAbortive();
            throw IoSystemError(io_error::broken_pipe, "xhttp stream-up closed while opening");
        }
        co_return std::move(*build_result);
    }

    net::io_context& io_context_;
    std::unique_ptr<AsyncStream> downlink_;
    TcpStream* in_flight_upload_tcp_ = nullptr;
    const StreamSettings* stream_settings_ = nullptr;
    SslContext* security_context_ = nullptr;
    std::string tls_server_name_;
    std::string ws_host_;
    OutboundDialCandidate candidate_;
    std::string upload_path_;
    size_t base_upload_path_size_ = 0;
    AsyncWriteGate upload_gate_;
    DownlinkCancellation downlink_cancel_{*this};
    std::chrono::seconds timeout_{0};
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
                           std::string upload_path,
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
        if (downlink_ && !ReaderMustSendDeferredUpload()) {
            return downlink_->AsyncRead(buffer);
        }
        return AsyncReadSlow(buffer);
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        CheckUploadWritableBeforeAcquire();
        if (buffer.size() == 0) {
            co_return 0;
        }
        auto lease = co_await AcquireUploadWriteLease();
        if (!upload_ &&
            buffer.size() <= kMaxDeferredUploadBytes - pending_initial_.byte_size()) {
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            if (!pending_initial_.AppendSpan(
                    std::span<const uint8_t>(data, buffer.size()))) {
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

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        if (downlink_ && !ReaderMustSendDeferredUpload()) {
            return downlink_->ReadMultiBuffer();
        }
        return ReadMultiBufferSlow();
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override {
        struct ClearGuard {
            common::MultiBuffer& mb;
            ~ClearGuard() noexcept { mb.clear(); }
        } clear_guard{mb};
        CheckUploadWritableBeforeAcquire();
        if (mb.byte_size() == 0) {
            co_return;
        }
        auto lease = co_await AcquireUploadWriteLease();
        if (upload_) {
            co_await upload_->WriteMultiBuffer(std::move(mb));
            TouchDownlinkActivity();
            co_return;
        }
        if (const auto bytes = mb.FrontSpan(); !bytes.empty()) {
            const net::const_buffer payload(bytes.data(), bytes.size());
            co_await OpenUploadLocked({&payload, 1});
            TouchDownlinkActivity();
        }
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        CheckUploadWritableBeforeAcquire();
        if (!HasNonEmptyBuffer(buffers)) {
            co_return;
        }
        auto lease = co_await AcquireUploadWriteLease();
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
                throw IoSystemError(io_error::broken_pipe, "xhttp stream-up upload unavailable");
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
    net::awaitable<size_t> AsyncReadSlow(net::mutable_buffer buffer) {
        if (!downlink_) {
            co_return 0;
        }
        if (ReaderMustSendDeferredUpload()) {
            co_await FlushDeferredUploadForRead();
        }
        co_return co_await downlink_->AsyncRead(buffer);
    }

    net::awaitable<common::MultiBuffer> ReadMultiBufferSlow() {
        if (!downlink_) {
            co_return common::MultiBuffer{};
        }
        if (ReaderMustSendDeferredUpload()) {
            co_await FlushDeferredUploadForRead();
        }
        co_return co_await downlink_->ReadMultiBuffer();
    }

    void CheckUploadWritableBeforeAcquire() const {
        // upload_failed_ is provisionally set while an open is in flight;
        // only a finished failed open poisons the stream.
        if (closed_ || write_closed_ || (upload_failed_ && !upload_opening_)) {
            throw IoSystemError(io_error::broken_pipe, "xhttp stream-up upload unavailable");
        }
    }

    net::awaitable<AsyncWriteGate::Lease> AcquireUploadWriteLease() {
        auto lease = upload_gate_.TryAcquire();
        if (!lease) lease = co_await upload_gate_.Acquire();
        if (!lease || closed_ || write_closed_ || upload_failed_) {
            throw IoSystemError(io_error::broken_pipe, "xhttp stream-up upload unavailable");
        }
        co_return lease;
    }

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

    net::awaitable<void> FlushDeferredUploadForRead() {
        auto lease = upload_gate_.TryAcquire();
        if (!lease) lease = co_await upload_gate_.Acquire();
        if (!lease || closed_ || upload_failed_) {
            throw IoSystemError(io_error::broken_pipe, "xhttp stream-up upload unavailable");
        }
        if (!upload_ && !write_closed_ && pending_initial_.byte_size() != 0) {
            co_await OpenUploadLocked({});
        }
    }

    // Single-flight under upload_gate_: the first caller opens the upload
    // request carrying the deferred bytes followed by |payload|. A failed open
    // poisons the stream, since the deferred bytes are gone with it.
    net::awaitable<void> OpenUploadLocked(std::span<const net::const_buffer> payload) {
        const common::MultiBuffer initial = std::move(pending_initial_);
        common::ConstBufferSpanBuilder<4> combined;
        std::span<const net::const_buffer> request_payload = payload;
        if (const auto prefix = initial.FrontSpan(); !prefix.empty()) {
            combined.Append(net::buffer(prefix.data(), prefix.size()));
            combined.AppendBuffers(payload);
            request_payload = combined.Span();
        } else if (!HasNonEmptyBuffer(payload)) {
            co_return;
        }
        if (request_payload.empty()) co_return;

        upload_failed_ = true;
        upload_opening_ = true;
        struct OpeningScope {
            bool& opening;
            ~OpeningScope() { opening = false; }
        } opening_scope{upload_opening_};

        upload_ = co_await DialAndBuildUploadRequest(
            upload_path_, XHttpClientRequestKind::StreamUp, request_payload);
        upload_->ClearPhaseDeadline();
        upload_->SetIdleTimeout(std::chrono::seconds(0));
        upload_->SetWriteTimeout(write_timeout_);
        upload_failed_ = false;
        upload_cancel_.Resubscribe(upload_->Cancellation());
    }

    std::unique_ptr<AsyncStream> upload_;
    common::MultiBuffer pending_initial_;
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
                              std::string upload_path,
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
        CheckWritable();
        if (buffer.size() == 0) {
            co_return 0;
        }
        std::array<net::const_buffer, 1> buffers{buffer};
        co_await SendPacket(buffers);
        co_return buffer.size();
    }

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        return downlink_->ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override {
        if (closed_ || write_closed_) {
            mb.clear();
            CheckWritable();
        }
        return SendPacket({}, std::move(mb));
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        CheckWritable();
        return SendPacket(buffers);
    }

    void ShutdownWrite() override {
        write_closed_ = true;
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        write_closed_ = true;
        co_return;
    }

private:
    void CheckWritable() const {
        if (closed_ || write_closed_) {
            throw IoSystemError(io_error::broken_pipe, "xhttp packet-up write after shutdown");
        }
    }

    net::awaitable<void> SendPacket(
        std::span<const net::const_buffer> payloads,
        common::MultiBuffer owned = {}) {
        struct ClearOwned {
            common::MultiBuffer& mb;
            ~ClearOwned() noexcept { mb.clear(); }
        } clear_owned{owned};
        net::const_buffer single_owned;
        if (!owned.empty()) {
            const auto bytes = owned.FrontSpan();
            if (bytes.empty()) co_return;
            single_owned = net::buffer(bytes.data(), bytes.size());
            payloads = {&single_owned, 1};
        } else if (!HasNonEmptyBuffer(payloads)) {
            co_return;
        }
        auto lease = upload_gate_.TryAcquire();
        if (!lease) lease = co_await upload_gate_.Acquire();
        if (!lease) {
            throw IoSystemError(io_error::broken_pipe, "xhttp packet-up write after shutdown");
        }
        CheckWritable();

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

net::awaitable<DialResult> DialAndBuildXHttpRequestCandidate(
    net::io_context& io_context,
    common::Context& ctx,
    const OutboundTransportTarget& target,
    const OutboundDialCandidate& candidate,
    std::string_view path,
    XHttpClientRequestKind kind,
    std::span<const net::const_buffer> packet_payload = {}) {

    auto tcp_result = co_await ConnectOutboundCandidate(io_context, candidate, target.timeout);
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
        target.HttpHost(),
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
            common::ErrorCode::SOCKET_EOF,
            "xhttp client request returned no stream");
    }
    if (stream) {
        stream->ClearPhaseDeadline();
        stream->SetIdleTimeout(std::chrono::seconds(0));
    }

    co_return DialResult::Success(std::move(stream));
}

}  // namespace

XHttpSessionId GenerateXHttpSessionId() noexcept {
    std::array<uint8_t, kXHttpSessionIdLength / 2> random{};
    if (RAND_bytes(random.data(), random.size()) != 1) {
        // 随机源不可用时任何会话 ID 都可预测，不降级继续拨号。
        std::abort();
    }
    XHttpSessionId id{};
    common::EncodeHexLowerTo(random, id);
    return id;
}

net::awaitable<DialResult> DialXHttpSplitOutboundTransport(
    net::io_context& io_context,
    common::Context& ctx,
    const OutboundTransportTarget& target) {

    if (!target.stream_settings) {
        co_return DialResult::Fail(common::ErrorCode::INVALID_ARGUMENT, "missing stream settings");
    }

    const auto mode = ResolveXHttpOutboundMode(*target.stream_settings);
    if (mode != XHttpMode::PacketUp && mode != XHttpMode::StreamUp) {
        co_return DialResult::Fail(common::ErrorCode::PROTOCOL_UNSUPPORTED, "unsupported xhttp mode");
    }

    const OutboundTransportTarget& downlink_target =
        target.xhttp_download_target ? *target.xhttp_download_target : target;
    if (!downlink_target.stream_settings || !downlink_target.stream_settings->IsXHttp()) {
        co_return DialResult::Fail(
            common::ErrorCode::INVALID_ARGUMENT,
            "invalid xhttp downlink target");
    }

    const XHttpSessionId session_id = GenerateXHttpSessionId();
    const std::string_view session_id_text(session_id.data(), session_id.size());
    const std::string downlink_path = BuildXHttpSplitPath(
        downlink_target.stream_settings->xhttp, session_id_text);
    std::string upload_path = BuildXHttpSplitPath(
        target.stream_settings->xhttp, session_id_text);

    DialResult last_result =
        DialResult::Fail(common::ErrorCode::DIAL_CONNECT_FAILED, "all xhttp candidates failed");
    std::optional<OutboundDialCandidate> selected;
    std::unique_ptr<AsyncStream> downlink;

    for (const auto& candidate : downlink_target.Candidates()) {
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
            break;
        }
        LOG_CONN_DEBUG(ctx,
                       "XHTTP downlink candidate failed endpoint={}:{} > {}",
                       common::AddressText(candidate.endpoint.address()).View(),
                       candidate.endpoint.port(),
                       attempt.error_msg);
        last_result = std::move(attempt);
    }

    if (!downlink || !selected) {
        co_return last_result;
    }

    std::optional<OutboundDialCandidate> upload_candidate =
        target.xhttp_download_target ? FirstDialCandidate(target) : selected;
    if (!upload_candidate) {
        co_return DialResult::Fail(
            common::ErrorCode::INVALID_ARGUMENT,
            "missing xhttp upload candidate");
    }

    if (mode == XHttpMode::PacketUp) {
        co_return DialResult::Success(
            std::make_unique<XHttpPacketUpClientStream>(
                io_context,
                std::move(downlink),
                target,
                *upload_candidate,
                std::move(upload_path),
                ctx.conn_id));
    }

    co_return DialResult::Success(
        std::make_unique<XHttpSplitClientStream>(
            io_context,
            std::move(downlink),
            target,
            *upload_candidate,
            std::move(upload_path),
            ctx.conn_id));
}

}  // namespace transport

