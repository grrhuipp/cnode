#pragma once

#include "transport/internet/quic_listener.hpp"
#include "app/datagram_session_environment.hpp"
#include "app/rate_limiter.hpp"
#include "common/allocator.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/hash.hpp"
#include "common/session.hpp"
#include "common/sharded_user_stats.hpp"
#include "common/asio_types.hpp"
#include "common/string_hash.hpp"

#include "common/target_address.hpp"
#include "transport/async_stream.hpp"
#include "transport/internet/hysteria/hysteria_wire.hpp"
#include "transport/internet/hysteria/hysteria_settings.hpp"
#include <asio/steady_timer.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <bitset>
#include <limits>

#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <cstddef>
#include <vector>
#include <tl/expected.hpp>

namespace transport::internet {

class InboundTransportStreamHandler;

}  // namespace transport::internet
namespace common {

class AwaitableTaskGroup;

}  // namespace common
namespace transport::internet {

class SslContext;

}  // namespace transport::internet
struct ngtcp2_cid;
namespace proxyman::inbound { struct ReceiverSettings; }

namespace transport::internet::hysteria {


inline constexpr size_t kServerConnectionIdLength = 18;
inline constexpr uint8_t kServerCidMagic0 = 0xa5;
inline constexpr uint8_t kServerCidMagic1 = 0x5a;
inline constexpr uint16_t kServerCidMagicWord =
    (static_cast<uint16_t>(kServerCidMagic0) << 8) | kServerCidMagic1;

// 服务端签发的 SCID 前三字节为魔数与所属 worker_id，供内核 CBPF 按 DCID 分流。
void EncodeWorkerServerCid(ngtcp2_cid& cid, size_t length, uint32_t worker_id) noexcept;

// 在 SO_REUSEPORT 监听组上挂载按 DCID 内嵌 worker_id 投递的 CBPF 程序。
[[nodiscard]] bool AttachQuicReuseportBpf(int fd, uint32_t worker_count) noexcept;

// RFC 9000 §17.2：连接 ID 至多 20 字节。
inline constexpr size_t kMaxConnectionIdLength = 20;

struct ConnectionId {
    std::array<uint8_t, kMaxConnectionIdLength> bytes{};
    uint8_t size = 0;
    explicit ConnectionId(const ngtcp2_cid& cid) noexcept;
    ConnectionId(const uint8_t* data, size_t length) noexcept
        : size(static_cast<uint8_t>(length)) {
        std::copy_n(data, length, bytes.begin());
    }
    bool operator==(const ConnectionId&) const noexcept = default;
};

struct ConnectionIdHash {
    size_t operator()(const ConnectionId& id) const noexcept {
        return common::Fnv1a64(std::span<const uint8_t>(id.bytes.data(), id.size)) ^ id.size;
    }
};

class Connection;
struct SocketState;


class QuicStreamState final {
public:
    static constexpr size_t kMaxQueuedInputBytes = 512 * 1024;

    QuicStreamState(net::io_context& io_context, int64_t stream_id,
                    std::weak_ptr<Connection> owner);

    [[nodiscard]] net::io_context& IoContext() const noexcept { return io_context_; }
    transport::CancellationSource& Cancellation() noexcept { return cancellation_; }
    [[nodiscard]] bool PushInput(std::span<const uint8_t> data, bool fin);
    // Bytes received but not yet read; the transport inspects a request
    // prefix here before deciding who reads the stream.
    [[nodiscard]] const buf::MultiBuffer& PendingInput() const noexcept { return input_; }
    void DiscardInput(size_t bytes) noexcept;
    void OnStreamClosed() noexcept;
    void RemoteReset() noexcept;
    void Cancel() noexcept;
    net::awaitable<size_t> Read(net::mutable_buffer buffer);
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer();
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload);
    void ShutdownWrite() noexcept;
    void CheckWriteOpen() const;
    // A notification is only a hint: the connection must recheck its queue
    // and stream identity after every wait. ACKs broadcast to current waiters;
    // shutdown/reset/cancel also wake them, but make the wait fail.
    net::awaitable<void> WaitWritable();
    void NotifyWritable() noexcept;

    [[nodiscard]] bool Open() const noexcept { return !cancelled_; }
    // Application completion does not retire transport output: queued bytes
    // and FIN remain owned by the connection until native stream closure.
    [[nodiscard]] bool DuplexFinished() const noexcept {
        return !cancelled_ && input_done_ && input_.empty() && write_done_;
    }

private:
    struct OutputWait final {
        explicit OutputWait(net::any_io_executor executor)
            : ready(std::move(executor), 0) {}
        OutputWait(const OutputWait&) = delete;
        OutputWait& operator=(const OutputWait&) = delete;
        OutputWait(OutputWait&&) = delete;
        OutputWait& operator=(OutputWait&&) = delete;

        common::SignalChannel ready;
        size_t waiters = 0;
    };

    void AcknowledgeInput(size_t bytes) noexcept;
    void Abort(bool cancel_transport) noexcept;
    void WakeReader() noexcept;

    net::io_context& io_context_;
    int64_t stream_id_;
    std::weak_ptr<Connection> owner_;
    common::SignalChannel input_signal_;
    // Borrowed only while writers actually wait; idle streams retain no node.
    std::unique_ptr<OutputWait> output_wait_;
    buf::MultiBuffer input_;
    bool input_done_ = false;
    bool write_done_ = false;
    bool cancelled_ = false;
    transport::CancellationSource cancellation_;
};

// One Hysteria TCP request stream handed to the inbound handler.
class QuicStream final : public AsyncStream {
public:
    // |state| must be non-null.
    explicit QuicStream(std::shared_ptr<QuicStreamState> state);
    ~QuicStream() noexcept override;
    transport::CancellationSource& Cancellation() noexcept override { return state_->Cancellation(); }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override;
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override;
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) override;
    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override;
    void ShutdownWrite() override;
    void Cancel() noexcept override;
    void Close() override;
    void CloseAbortive() override;
    [[nodiscard]] int NativeHandle() const override { return -1; }
    [[nodiscard]] bool IsOpen() const override;

protected:
    StreamPhaseDeadline* LogicalPhaseDeadline() noexcept override { return &deadline_; }

private:
    std::shared_ptr<QuicStreamState> state_;
    StreamPhaseDeadline deadline_;
    bool closed_ = false;
};

// One Hysteria UDP session handed to the inbound handler. Every read yields
// one reassembled datagram tagged with its target; every write sends one
// datagram to the target it carries. Byte-stream I/O is not supported.
// The owning connection keeps a raw pointer while the session is registered;
// destruction unregisters it, and connection close detaches it first.
class UdpSessionStream final : public AsyncStream {
public:
    // Bounds queued Buffer data capacity, not only the datagrams' payload sizes.
    static constexpr size_t kMaxQueuedBytes = 512 * 1024;

    UdpSessionStream(net::io_context& io_context, uint32_t session_id,
                     std::weak_ptr<Connection> owner);
    ~UdpSessionStream() noexcept override;

    [[nodiscard]] bool Push(const common::TargetAddress& target, std::span<const uint8_t> payload);
    // The owning connection closed; pending reads end and writes fail.
    void Detach() noexcept;

    transport::EofAction ReadEofAction() const noexcept override {
        return transport::EofAction::WaitForPeer;
    }
    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override;
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override;
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer packet) override;
    void ShutdownWrite() override {}
    void Cancel() noexcept override;
    void Close() override;
    [[nodiscard]] int NativeHandle() const override { return -1; }
    [[nodiscard]] bool IsOpen() const override { return !closed_; }

protected:
    StreamPhaseDeadline* LogicalPhaseDeadline() noexcept override { return &deadline_; }

private:
    void WakeReader() noexcept;

    uint32_t session_id_;
    std::weak_ptr<Connection> owner_;
    common::SignalChannel signal_;
    memory::RingDeque<buf::MultiBuffer> input_;
    size_t queued_buffer_count_ = 0;
    bool cancelled_ = false;
    bool closed_ = false;
    StreamPhaseDeadline deadline_;
};
// Worker-local sockets, receive staging and native send ownership; connection
// expiry rides the Worker's TimeoutScheduler. Each accepted QUIC connection
// stays on its accepting Worker, shared by all its TCP streams and UDP
// sessions; listeners never transfer received payloads or move their shared
// sockets.
class HysteriaIngress final : public transport::internet::QuicListener {
public:
    using SocketPtr = std::shared_ptr<udp::socket>;

    HysteriaIngress(uint32_t worker_id, uint32_t worker_count, net::io_context& io_context,
                   app::DatagramSessionEnvironment environment);
    ~HysteriaIngress() noexcept;

    HysteriaIngress(const HysteriaIngress&) = delete;
    HysteriaIngress& operator=(const HysteriaIngress&) = delete;

    [[nodiscard]] SocketPtr MakeSocket();
    [[nodiscard]] SocketPtr AttachSocket(
        std::string_view socket_key, SocketPtr socket);

    void Start();
    void RequestStop() noexcept;
    net::awaitable<void> AsyncJoin();

private:
    friend class Connection;

    [[nodiscard]] const proxyman::inbound::ReceiverSettings& Receiver() const noexcept;
    void Spawn(net::awaitable<void> task);
    [[nodiscard]] bool Queue(SocketState& socket, std::span<const uint8_t> data,
                             const udp::endpoint& remote,
                             Connection& connection, bool terminal = false);
    void Associate(const ngtcp2_cid& cid, std::shared_ptr<Connection> connection);
    void Dissociate(const ngtcp2_cid& cid) noexcept;
    void DissociateAll(Connection& connection) noexcept;
    SocketState* Resolve(const udp::endpoint& local) noexcept;
    net::awaitable<void> ReceiveLoop(std::shared_ptr<SocketState> socket);
    void ProcessPacket(SocketState& socket, const udp::endpoint& remote,
                       std::span<const uint8_t> packet);
    net::awaitable<void> SendLoop(std::shared_ptr<SocketState> socket);

    app::DatagramSessionEnvironment environment;
    memory::UnorderedMap<Connection*, std::shared_ptr<Connection>> sessions;
    uint32_t worker_id;
    uint32_t worker_count;
    net::io_context& io;
    Version version = Version::V2;
    uint64_t upload_bytes_per_second = 0;
    uint64_t download_bytes_per_second = 0;
    std::unique_ptr<SslContext> ssl_context;
    memory::UnorderedMap<memory::String,
        std::shared_ptr<SocketState>, common::TransparentStringHash, common::TransparentStringEq> sockets;
    memory::UnorderedMap<
        ConnectionId, std::shared_ptr<Connection>, ConnectionIdHash> connections;
    // AsyncJoin 的唤醒信号：每个已启动任务结束时取消一次等待。
    net::steady_timer changed;
    size_t tasks = 0;
    bool stopping = false;
    bool started = false;
};


}  // namespace transport::internet::hysteria
