#pragma once

#include "xhttp_packet_queue.hpp"
#include "xhttp_upload_stream_slot.hpp"
#include "common/allocator.hpp"
#include "common/buf/multi_buffer.hpp"
#include "transport/cancellation.hpp"
#include "transport/internet/transport_stack.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

 class ExecutionDomain; 

namespace transport::internet {

class XHttpSessionTable;
struct XHttpSessionTableEntry;

// Execution-group-local logical XHTTP session joining uploads to one downlink.
// Queued packets and in-flight uploads share one bounded payload budget.
class XHttpPacketUpSession final : public memory::ThreadAllocated,
                                   private transport::CancellationSubscription {
public:
    explicit XHttpPacketUpSession(net::io_context& io_context,
                                  std::shared_ptr<ExecutionDomain> owner = {});
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
        net::awaitable<size_t> Read(buf::MultiBuffer& payload, size_t limit);
        bool Commit(uint64_t seq, buf::MultiBuffer payload);

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
    [[nodiscard]] bool Push(uint64_t seq, buf::MultiBuffer payload);
    void CloseInput() noexcept;
    void Close() noexcept;
    void CancelPendingOperations() noexcept;
    [[nodiscard]] bool AcceptingInput() const noexcept {
        return !closed_ && !input_closed_;
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer);
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer();

private:
    friend class XHttpSessionTable;
    void Retire() noexcept;
    // Stable table entry; detached on retirement or table destruction.
    XHttpSessionTableEntry* table_entry_ = nullptr;
    // Services and the allocation arena outlive every session operation.
    std::shared_ptr<ExecutionDomain> owner_domain_;
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
            (void)session.upload_signal_.try_send(IoErrorCode{});
        }
    };

    void OnCancellation(transport::Cancellation cancellation) noexcept override;
    void ReleaseAttachedUpload(const std::shared_ptr<AsyncStream>& stream) noexcept;
    void Wake() noexcept;

    net::io_context& io_context_;
    SignalChannel input_signal_;
    ::detail::XHttpPacketQueue packet_queue_;
    ::detail::XHttpUploadStreamSlot stream_input_;
    transport::CancellationSource cancellation_;
    SignalChannel upload_signal_;
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

// Configuration namespace + id select an execution domain, then Join unifies
// the physical connection groups before touching that domain's session table.
// Retirement is allocation-free and reserves its own metadata queue node;
// the next coordinator lookup drains events, never scans the live table.
// Limits: 1024 live entries per domain, 65536 live directory records per pool,
// and the most recent 1024 ended ids in each bounded FIFO replay window.
[[nodiscard]] net::awaitable<std::shared_ptr<XHttpPacketUpSession>> GetXHttpPacketSession(
    net::io_context& io_context,
    std::string_view session_namespace,
    std::string_view session_id,
    XHttpSessionAccess access);

// Physical-session teardown joins upload-response readers before releasing
// their domain's transport hosts. Standalone callers pass their io_context.
[[nodiscard]] net::awaitable<void> JoinXHttpClientTasks(net::execution_context& services);

// Logical stream reading the session uploads and writing the downlink.
[[nodiscard]] std::unique_ptr<AsyncStream> MakeXHttpSplitStream(
    std::shared_ptr<XHttpPacketUpSession> session,
    std::unique_ptr<AsyncStream> downlink);

[[nodiscard]] HttpConfig XHttpStreamOneHttpConfig(const XHttpConfig& cfg, bool outbound);
[[nodiscard]] HttpConfig XHttpClientHttpConfig(const XHttpConfig& cfg,
                                               std::string_view path,
                                               std::string_view method,
                                               bool tls,
                                               XHttpClientRequestKind kind);

[[nodiscard]] net::awaitable<TransportBuildResult> DoXHttp1ServerHandshake(
    net::io_context& io_context,
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    const XHttpConfig& xhttp_cfg,
    uint64_t conn_id,
    InboundTransportMetadata* transport_metadata,
    std::span<const uint8_t> initial,
    const std::shared_ptr<InboundTransportStreamHandler>& stream_handler);

[[nodiscard]] net::awaitable<TransportBuildResult> DoXHttp1ClientRequest(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    std::string_view host,
    XHttpClientRequestKind kind,
    std::span<const net::const_buffer> packet_payload,
    uint64_t conn_id);

}  // namespace transport::internet
