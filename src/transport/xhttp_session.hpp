#pragma once

#include "common/allocator.hpp"
#include "common/multi_buffer.hpp"
#include "transport/async_stream.hpp"
#include "transport/transport_stack.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <map>
#include <string>

#include "transport/http2_session.hpp"
namespace transport {

struct XHttpPacketSessionKeyRef {
    std::string_view session_id;
    std::string_view session_namespace;
};

template <typename StringType>
struct BasicXHttpPacketSessionKey {
    StringType session_id{};
    StringType session_namespace{};

    [[nodiscard]] constexpr operator XHttpPacketSessionKeyRef() const noexcept {
        return {session_id, session_namespace};
    }
};

using XHttpPacketSessionKey =
    BasicXHttpPacketSessionKey<std::string>;

struct XHttpPacketSessionKeyHash {
    using is_transparent = void;

    [[nodiscard]] size_t operator()(
        XHttpPacketSessionKeyRef key) const noexcept {
        const size_t session_hash = std::hash<std::string_view>{}(key.session_id);
        const size_t namespace_hash = std::hash<std::string_view>{}(key.session_namespace);
        return namespace_hash ^
            (session_hash + size_t{0x9e3779b9} + (namespace_hash << 6) + (namespace_hash >> 2));
    }
};

struct XHttpPacketSessionKeyEq {
    using is_transparent = void;

    [[nodiscard]] bool operator()(
        XHttpPacketSessionKeyRef lhs,
        XHttpPacketSessionKeyRef rhs) const noexcept {
        return lhs.session_id == rhs.session_id &&
               lhs.session_namespace == rhs.session_namespace;
    }
};

// Worker-local single-upload owner. Readers take a shared snapshot across
// co_await so Close can cancel and detach the stream without destroying an
// object that still has an asynchronous member function in flight.
template <typename Stream>
class BasicXHttpUploadStreamSlot final {
public:
    [[nodiscard]] bool Attach(std::unique_ptr<Stream>&& stream) {
        if (!stream || current_) {
            return false;
        }
        // Commit the unique owner only after the shared control block exists.
        struct DeleteAfterCommit {
            bool committed = false;
            void operator()(Stream* value) const noexcept {
                if (committed) delete value;
            }
        };
        std::shared_ptr<Stream> shared(stream.get(), DeleteAfterCommit{});
        std::get_deleter<DeleteAfterCommit>(shared)->committed = true;
        (void)stream.release();
        current_ = std::move(shared);
        return true;
    }

    [[nodiscard]] std::shared_ptr<Stream> Snapshot() const noexcept {
        return current_;
    }

    [[nodiscard]] bool ReleaseIfCurrent(
        const std::shared_ptr<Stream>& expected) noexcept {
        if (current_ != expected) {
            return false;
        }
        current_.reset();
        return true;
    }

    [[nodiscard]] std::shared_ptr<Stream> Take() noexcept {
        return std::exchange(current_, {});
    }

    [[nodiscard]] bool Empty() const noexcept { return !current_; }

private:
    std::shared_ptr<Stream> current_;
};

using XHttpUploadStreamSlot = BasicXHttpUploadStreamSlot<AsyncStream>;

class XHttpPacketQueue final {
public:
    static constexpr size_t kMaxQueuedBytes = 4 * 1024 * 1024;
    static constexpr size_t kInOrderHeadroomBytes = 64 * 1024;
    static constexpr size_t kMaxQueuedPackets = 1024;
    static constexpr size_t kMaxUploads = 64;

    [[nodiscard]] bool AcquireUpload() noexcept {
        if (uploads_ == kMaxUploads) return false;
        ++uploads_;
        return true;
    }
    void ReleaseUpload() noexcept { --uploads_; }
    [[nodiscard]] bool Reserve(size_t bytes) noexcept {
        if (bytes > kMaxQueuedBytes - queued_capacity_ - reserved_) return false;
        reserved_ += bytes;
        return true;
    }
    void Release(size_t bytes) noexcept { reserved_ -= bytes; }
    [[nodiscard]] size_t UsedCapacity() const noexcept {
        return queued_capacity_ + reserved_;
    }
    [[nodiscard]] bool Push(uint64_t seq, common::MultiBuffer payload) {
        if (seq < next_seq_) {
            payload.clear();
            return true;
        }
        // Duplicate check and insertion share one search; the checks below
        // leave pending_ untouched, so the hint stays valid.
        auto hint = pending_.end();
        if (seq > next_seq_) {
            hint = pending_.lower_bound(seq);
            if (hint != pending_.end() && hint->first == seq) {
                payload.clear();
                return true;
            }
        }

        const size_t bytes = payload.byte_size();
        const size_t capacity = BlockCapacity(payload);
        if (seq > next_seq_) {
            const size_t out_of_order_budget = kMaxQueuedBytes - kInOrderHeadroomBytes;
            if (seq - next_seq_ > kMaxQueuedPackets ||
                (bytes != 0 && pending_.size() >= kMaxQueuedPackets / 2) ||
                queued_bytes_ + bytes > out_of_order_budget ||
                queued_capacity_ + reserved_ + capacity > out_of_order_budget) {
                payload.clear();
                return false;
            }
        }
        const size_t packet_limit =
            (seq == next_seq_ && ready_.empty()) ? kMaxQueuedPackets + 1 : kMaxQueuedPackets;
        if (queued_packets_ >= packet_limit ||
            capacity > kMaxQueuedBytes - queued_capacity_ - reserved_) {
            payload.clear();
            return false;
        }

        if (seq == next_seq_) {
            ready_.push_back(std::move(payload));
            ++queued_packets_;
            queued_bytes_ += bytes;
            queued_capacity_ += capacity;
            ++next_seq_;
            PromoteReadyPackets();
            return true;
        }

        pending_.emplace_hint(hint, seq, std::move(payload));
        ++queued_packets_;
        queued_bytes_ += bytes;
        queued_capacity_ += capacity;
        return true;
    }

    [[nodiscard]] size_t ConsumePrefixTo(std::span<uint8_t> out) {
        PruneEmptyFront();
        if (ready_.empty() || out.empty()) {
            return 0;
        }
        auto& front = ready_.front();
        const size_t old_cap = BlockCapacity(front);
        const size_t consumed = front.ConsumePrefixTo(out);
        queued_bytes_ -= std::min(queued_bytes_, consumed);
        queued_capacity_ -= (old_cap - BlockCapacity(front));
        PruneEmptyFront();
        return consumed;
    }

    [[nodiscard]] common::MultiBuffer Pop() {
        PruneEmptyFront();
        if (ready_.empty()) {
            return {};
        }
        common::MultiBuffer payload = std::move(ready_.front());
        ready_.pop_front();
        queued_capacity_ -= BlockCapacity(payload);
        queued_bytes_ -= std::min(queued_bytes_, payload.byte_size());
        queued_packets_ -= std::min<size_t>(queued_packets_, 1);
        return payload;
    }

    void Clear() noexcept {
        ready_.clear();
        pending_.clear();
        queued_bytes_ = 0;
        queued_packets_ = 0;
        queued_capacity_ = 0;
    }

    [[nodiscard]] bool HasReady() {
        PruneEmptyFront();
        return !ready_.empty();
    }

    [[nodiscard]] size_t QueuedBytes() const noexcept { return queued_bytes_; }
    [[nodiscard]] size_t QueuedPackets() const noexcept { return queued_packets_; }

private:
    [[nodiscard]] static size_t BlockCapacity(const common::MultiBuffer& payload) noexcept {
        if (payload.empty()) return 0;
        const size_t bytes = payload.byte_size();
        const size_t blocks = bytes == 0 ? 1 : 1 + (bytes - 1) / common::Buffer::kSize;
        return blocks * common::Buffer::kSize;
    }
    // Keys enter pending_ above next_seq_ and are unique, and next_seq_ only
    // advances one step before this runs, so no key is ever below next_seq_:
    // the next packet, if present, is the smallest key.
    void PromoteReadyPackets() {
        while (!pending_.empty() && pending_.begin()->first == next_seq_) {
            auto it = pending_.begin();
            ready_.push_back(std::move(it->second));
            pending_.erase(it);
            ++next_seq_;
        }
    }

    void PruneEmptyFront() {
        while (!ready_.empty() && ready_.front().byte_size() == 0) {
            queued_capacity_ -= BlockCapacity(ready_.front());
            queued_packets_ -= std::min<size_t>(queued_packets_, 1);
            ready_.pop_front();
        }
    }

    common::RingDeque<common::MultiBuffer> ready_;
    std::map<uint64_t, common::MultiBuffer> pending_;
    size_t queued_bytes_ = 0;
    size_t queued_packets_ = 0;
    size_t queued_capacity_ = 0;
    size_t reserved_ = 0;
    size_t uploads_ = 0;
    uint64_t next_seq_ = 0;
};


class XHttpSessionTable;
struct XHttpSessionTableEntry;

// Execution-group-local logical XHTTP session joining uploads to one downlink.
// Queued packets and in-flight uploads share one bounded payload budget.
class XHttpPacketUpSession final : private transport::CancellationSubscription {
public:
    explicit XHttpPacketUpSession(net::io_context& io_context);
    ~XHttpPacketUpSession() noexcept;

    transport::CancellationSource& Cancellation() noexcept { return cancellation_; }
    [[nodiscard]] net::io_context& IoContext() const noexcept;
    [[nodiscard]] bool Reserve(size_t bytes) noexcept {
        return !closed_ && packet_queue_.Reserve(bytes);
    }
    void Release(size_t bytes) noexcept { packet_queue_.Release(bytes); }

    // One admitted packet-up body. Holds an upload slot and the budget it has
    // reserved until Commit hands the payload to the session queue.
    class Upload final : private transport::CancellationSubscription {
    public:
        Upload(XHttpPacketUpSession& session, AsyncStream& stream);
        ~Upload() noexcept;
        net::awaitable<size_t> Read(common::MultiBuffer& payload, size_t limit);
        bool Commit(uint64_t seq, common::MultiBuffer payload);

    private:
        void OnCancellation(transport::Cancellation cancellation) noexcept override;

        XHttpPacketUpSession& session_;
        AsyncStream& stream_;
        size_t reserved_ = 0;
    };

    [[nodiscard]] bool AttachStream(std::unique_ptr<AsyncStream> stream);
    [[nodiscard]] bool CanAttachStream() const noexcept {
        return AcceptingInput() && stream_input_.Empty();
    }
    net::awaitable<void> JoinAttachedUpload();
    // Called once the split stream joining this session to its downlink exists.
    [[nodiscard]] bool AttachDownlink() noexcept;
    // Keeps a session that an upload reached before its downlink alive until
    // a downlink joins. False when `connection` is cancelled first (its
    // request deadline or close) or the session closes without a downlink.
    [[nodiscard]] net::awaitable<bool> AwaitDownlink(
        transport::CancellationSource& cancellation);
    [[nodiscard]] net::awaitable<bool> AwaitDownlink(AsyncStream& connection) {
        return AwaitDownlink(connection.Cancellation());
    }
    [[nodiscard]] bool DownlinkAttached() const noexcept { return downlink_attached_; }
    [[nodiscard]] bool Push(uint64_t seq, common::MultiBuffer payload);
    void CloseInput() noexcept;
    void Close() noexcept;
    void CancelPendingOperations() noexcept;
    [[nodiscard]] bool AcceptingInput() const noexcept {
        return !closed_ && !input_closed_;
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer);
    net::awaitable<common::MultiBuffer> ReadMultiBuffer();

private:
    friend class XHttpSessionTable;
    void Retire() noexcept;
    // Stable table entry; detached on retirement or table destruction.
    XHttpSessionTableEntry* table_entry_ = nullptr;
    // Counts a read in flight on the attached stream-up upload so Close can
    // wait for it before the upload stream is destroyed.
    struct UploadRead {
        XHttpPacketUpSession& session;
        std::shared_ptr<AsyncStream>& stream;
        UploadRead(XHttpPacketUpSession& session, std::shared_ptr<AsyncStream>& stream)
            : session(session), stream(stream) { ++session.upload_reads_; }
        ~UploadRead() {
            stream.reset();
            --session.upload_reads_;
            if (session.upload_signal_) (void)session.upload_signal_->try_send(IoErrorCode{});
        }
    };

    void OnCancellation(transport::Cancellation cancellation) noexcept override;
    void ReleaseAttachedUpload(const std::shared_ptr<AsyncStream>& stream) noexcept;
    void Wake() noexcept;

    net::io_context& io_context_;
    common::SignalChannel input_signal_;
    XHttpPacketQueue packet_queue_;
    XHttpUploadStreamSlot stream_input_;
    transport::CancellationSource cancellation_;
    // JoinAttachedUpload's frame-local channel, published only while it runs.
    common::SignalChannel* upload_signal_ = nullptr;
    // Event that AttachDownlink and Close broadcast to AwaitDownlink waiters.
    transport::CancellationSource downlink_ready_;
    size_t upload_reads_ = 0;
    bool downlink_attached_ = false;
    bool input_closed_ = false;
    bool closed_ = false;
    uint64_t read_abort_epoch_ = 0;
};

struct XHttpRequestMeta {
    enum class Kind {
        Unknown,
        StreamOne,
        PacketDown,
        PacketUp,
        StreamUp,
    };

    Kind kind = Kind::Unknown;
    // Borrowed from the request header storage, which outlives its handshake.
    std::string_view session_id;
    uint64_t seq = 0;
};

[[nodiscard]] inline bool XHttpKindAllowed(
    XHttpRequestMeta::Kind kind, const XHttpConfig& config) noexcept {
    switch (kind) {
    case XHttpRequestMeta::Kind::StreamOne: return config.AcceptsStreamOne();
    case XHttpRequestMeta::Kind::PacketDown:
        return config.AcceptsPacketUp() || config.AcceptsStreamUp();
    case XHttpRequestMeta::Kind::PacketUp: return config.AcceptsPacketUp();
    case XHttpRequestMeta::Kind::StreamUp: return config.AcceptsStreamUp();
    case XHttpRequestMeta::Kind::Unknown: return false;
    }
    return false;
}

// 成功占用下行后，直到组合流接管前任何失败都必须关闭会话。
class XHttpDownlinkClaim final {
public:
    explicit XHttpDownlinkClaim(XHttpPacketUpSession& session) noexcept
        : session_(session.AttachDownlink() ? &session : nullptr) {}
    ~XHttpDownlinkClaim() { if (session_) session_->Close(); }
    XHttpDownlinkClaim(const XHttpDownlinkClaim&) = delete;
    XHttpDownlinkClaim& operator=(const XHttpDownlinkClaim&) = delete;
    [[nodiscard]] explicit operator bool() const noexcept { return session_ != nullptr; }
    void Release() noexcept { session_ = nullptr; }
private:
    XHttpPacketUpSession* session_;
};

[[nodiscard]] XHttpRequestMeta ParseXHttpRequestMeta(std::string_view base_path,
                                                     std::string_view request_path,
                                                     std::string_view method);

// How a request meets its execution group's session table.
enum class XHttpSessionAccess : uint8_t {
    // A live session only.
    Join,
    // Joins, or starts a session, replacing one whose id already ended.
    Open,
    // Joins, or starts a session for an id absent from the bounded replay
    // window; an HTTP/1 upload may arrive before its downlink.
    Upload,
};

// Configuration namespace + id select a session on the Worker's session table.
// Retirement is allocation-free and reserves its own metadata queue node;
// the next lookup drains events, never scans the live table.
// Limits: 1024 live entries per Worker, 65536 live directory records per group,
// and the most recent 1024 ended ids in each bounded FIFO replay window.
[[nodiscard]] net::awaitable<std::shared_ptr<XHttpPacketUpSession>> GetXHttpPacketSession(
    app::GroupCoordinator& coordinator,
    net::io_context& io_context,
    std::string_view session_namespace,
    std::string_view session_id,
    XHttpSessionAccess access);

// Owner-thread fast path for Join/Upload when the session already lives on
// this Worker's local table (steady-state HTTP/2 and persistent HTTP/1.1
// packet-up uploads), avoiding two lookup coroutine frames per packet.
[[nodiscard]] std::shared_ptr<XHttpPacketUpSession> TryGetLocalXHttpPacketSession(
    net::io_context& io_context,
    std::string_view session_namespace,
    std::string_view session_id);

// Teardown joins upload-response readers before releasing their Worker's
// transport hosts. Standalone callers pass their io_context.
[[nodiscard]] net::awaitable<void> JoinXHttpClientTasks(net::execution_context& services);

// Logical stream reading the session uploads and writing the downlink.
[[nodiscard]] std::unique_ptr<AsyncStream> MakeXHttpSplitStream(
    std::shared_ptr<XHttpPacketUpSession> session,
    std::unique_ptr<AsyncStream> downlink);

struct XHttpRefererScratch {
    std::array<char, 512> inline_buf{};
    std::string overflow;

    [[nodiscard]] std::string_view Format(
        std::string_view host, std::string_view path, bool tls);
};

[[nodiscard]] HttpClientRequestView MakeXHttpClientRequestView(
    const XHttpConfig& cfg,
    std::string_view path,
    std::string_view method,
    bool tls,
    XHttpClientRequestKind kind,
    XHttpRefererScratch& referer_scratch);
[[nodiscard]] net::awaitable<TransportBuildResult> DoXHttp1ServerHandshake(
    app::GroupCoordinator& coordinator,
    net::io_context& io_context,
    std::unique_ptr<AsyncStream> stream,
    const XHttpConfig& xhttp_cfg,
    uint64_t conn_id,
    InboundTransportMetadata* transport_metadata,
    std::span<const uint8_t> initial,
    const std::shared_ptr<InboundTransportStreamHandler>& stream_handler);

[[nodiscard]] net::awaitable<TransportBuildResult> DoXHttp1ClientRequest(
    std::unique_ptr<AsyncStream> stream,
    HttpClientRequestView req,
    std::string_view host,
    XHttpClientRequestKind kind,
    std::span<const net::const_buffer> packet_payload,
    uint64_t conn_id);

}  // namespace transport
