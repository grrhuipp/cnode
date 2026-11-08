#pragma once

#include "support.hpp"

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <deque>
#include <limits>
#include <map>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>

namespace cnode::e2e::quic {

// An independent, single-threaded wire peer. No production stream or codec is
// used: TLS, packet protection, retransmission and flow control are real.
class Peer final {
public:
    explicit Peer(uint16_t server_port, std::string_view auth = "smoke-secret",
                  uint64_t max_datagram_frame_size = 65535,
                  uint64_t initial_receive_stream_window = 4 * 1024 * 1024,
                  std::string_view expected_auth_status = "233",
                  std::string_view client_address = "127.0.0.1")
        : socket_(Socket::BindUdp(0, client_address)), context_(SSL_CTX_new(TLS_method()), SSL_CTX_free),
          ssl_(nullptr, SSL_free), http_(nullptr, nghttp3_conn_del),
          quic_(nullptr, ngtcp2_conn_del) {
        const auto deadline = Clock::now() + std::chrono::seconds(10);
        if (auth.empty() || auth.size() > 4096) throw std::runtime_error("QUIC peer auth size");
        remote_.sin_family = AF_INET;
        remote_.sin_port = htons(server_port);
        remote_.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::connect(socket_.Fd(), reinterpret_cast<const sockaddr*>(&remote_), sizeof(remote_)) != 0)
            SocketError("QUIC UDP connect");
        socklen_t local_length = sizeof(local_);
        if (::getsockname(socket_.Fd(), reinterpret_cast<sockaddr*>(&local_), &local_length) != 0)
            SocketError("QUIC UDP getsockname");
        if (!context_ || ngtcp2_crypto_boringssl_configure_client_context(context_.get()) != 0)
            throw std::runtime_error("QUIC TLS context");
        // The local E2E fixture has a self-signed certificate, just like the
        // existing TlsSettings(false). Certificate verification alone is off;
        // the entire TLS 1.3 handshake and all packet crypto remain enabled.
        SSL_CTX_set_verify(context_.get(), SSL_VERIFY_NONE, nullptr);
        ssl_.reset(SSL_new(context_.get()));
        if (!ssl_) throw std::runtime_error("QUIC SSL_new");
        conn_ref_ = {[](ngtcp2_crypto_conn_ref* ref) {
            return static_cast<Peer*>(ref->user_data)->quic_.get();
        }, this};
        SSL_set_app_data(ssl_.get(), &conn_ref_);
        SSL_set_connect_state(ssl_.get());
        constexpr std::array<uint8_t, 3> alpn{2, 'h', '3'};
        if (SSL_set_alpn_protos(ssl_.get(), alpn.data(), alpn.size()) != 0 ||
            SSL_set_tlsext_host_name(ssl_.get(), "localhost") != 1)
            throw std::runtime_error("QUIC TLS ALPN/SNI");
        InitializeQuic(max_datagram_frame_size, initial_receive_stream_window);
        WaitUntil([&] { return handshake_complete_ && http_ != nullptr; }, deadline);
        const uint8_t* selected = nullptr;
        unsigned selected_length = 0;
        SSL_get0_alpn_selected(ssl_.get(), &selected, &selected_length);
        if (selected_length != 2 || std::string_view(reinterpret_cast<const char*>(selected), 2) != "h3")
            Fail("QUIC server did not negotiate h3");
        CheckQuic(ngtcp2_conn_open_bidi_stream(quic_.get(), &auth_stream_, nullptr), "open auth stream");
        auto header = [](std::string_view name, std::string_view value) {
            return nghttp3_nv{reinterpret_cast<uint8_t*>(const_cast<char*>(name.data())),
                              reinterpret_cast<uint8_t*>(const_cast<char*>(value.data())),
                              name.size(), value.size(), NGHTTP3_NV_FLAG_NONE};
        };
        const std::array headers{header(":method", "POST"), header(":scheme", "https"),
            header(":authority", "hysteria"), header(":path", "/auth"),
            header("hysteria-auth", auth), header("hysteria-cc-rx", "0")};
        // Without NO_COPY flags nghttp3 owns the header bytes after this call.
        CheckHttp(nghttp3_conn_submit_request(http_.get(), auth_stream_, headers.data(),
                                             headers.size(), nullptr, nullptr), "submit auth");
        WaitUntil([&] { return auth_headers_complete_; }, deadline);
        if (auth_status_ != expected_auth_status)
            Fail("unexpected HY2 authentication status " + auth_status_ +
                 ", expected " + std::string(expected_auth_status));
    }

    ~Peer() {
        // ngtcp2 must stop borrowing application and nghttp3 buffers before
        // either is destroyed; its crypto destructors still have a live SSL.
        quic_.reset();
        http_.reset();
    }
    Peer(const Peer&) = delete;
    Peer& operator=(const Peer&) = delete;
    Peer(Peer&&) = delete;
    Peer& operator=(Peer&&) = delete;

    int64_t Open(std::string_view target, std::string_view initial = {}) {
        RequireOpen();
        if (target.empty() || target.size() > 4096 || streams_.size() >= MaxStreams)
            throw std::runtime_error("QUIC peer target/stream limit");
        std::string request;
        AppendVarint(request, 0x401);
        AppendVarint(request, target.size());
        request.append(target);
        AppendVarint(request, 0);
        if (initial.size() > MaxSendBytes - request.size())
            throw std::runtime_error("QUIC peer initial payload limit");
        request.append(initial);
        CheckQueue(request.size());
        int64_t id = -1;
        CheckQuic(ngtcp2_conn_open_bidi_stream(quic_.get(), &id, nullptr), "open TCP stream");
        try {
            auto [it, inserted] = streams_.try_emplace(id);
            if (!inserted) Fail("QUIC duplicate stream ID");
            Queue(it->second, std::move(request), false);
        } catch (...) {
            ngtcp2_conn_shutdown_stream(quic_.get(), 0, id, 0);
            throw;
        }
        Flush();
        return id;
    }

    void Send(int64_t id, std::string_view bytes, bool fin = false) {
        RequireOpen();
        auto& stream = Find(id);
        if (stream.closed || stream.reset || stream.fin_requested || stream.write_stopped)
            throw std::runtime_error("QUIC send on terminated stream");
        CheckQueue(bytes.size());
        Queue(stream, std::string(bytes), fin);
        Flush();
    }

    void Reset(int64_t id) {
        RequireOpen();
        auto& stream = Find(id);
        if (stream.closed || stream.reset) return;
        CheckQuic(ngtcp2_conn_shutdown_stream(quic_.get(), 0, id, 0), "reset TCP stream");
        stream.reset = true;
        // shutdown_stream does not end ngtcp2's borrow: only ACK/stream_close
        // or destruction of the QUIC connection permits freeing queued bytes.
        Flush();
    }

    void SendDatagram(std::string_view bytes) {
        RequireOpen();
        if (bytes.size() > packet_.size() - 128)
            throw std::runtime_error("QUIC peer single datagram budget");
        const auto deadline = Clock::now() + Milliseconds(5000);
        bool accepted = false;
        while (!accepted || pending_size_ != 0) {
            if (Clock::now() >= deadline) Fail("QUIC datagram send deadline");
            if (!SendPacket()) { Pump(Milliseconds(1)); continue; }
            if (accepted) break;
            ngtcp2_path_storage output_path;
            ngtcp2_path_storage_zero(&output_path);
            ngtcp2_pkt_info info{};
            int consumed = 0;
            const auto now = Timestamp();
            const auto result = ngtcp2_conn_write_datagram(quic_.get(),
                &output_path.path, &info, packet_.data(), packet_.size(), &consumed,
                NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 0,
                reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size(), now);
            if (result < 0) CheckQuic(static_cast<int>(result), "write datagram");
            ngtcp2_conn_update_pkt_tx_time(quic_.get(), now);
            if (result > 0) {
                pending_size_ = static_cast<size_t>(result);
                (void)SendPacket();
            }
            accepted = consumed != 0;
            if (!accepted) Pump(Milliseconds(1));
        }
    }

    std::string ReadDatagram(Milliseconds timeout = Milliseconds(5000)) {
        Wait([&] { return !datagrams_.empty(); }, timeout);
        auto result = std::move(datagrams_.front());
        datagrams_.pop_front();
        receive_bytes_ -= result.size();
        return result;
    }

    void Pump(Milliseconds timeout = Milliseconds(10)) {
        if (timeout < Milliseconds::zero()) throw std::runtime_error("negative QUIC pump timeout");
        if (closed_) return;
        const auto deadline = Clock::now() + timeout;
        HandleExpiry();
        if (closed_) return;
        Flush();
        auto wake = deadline;
        const auto now = Timestamp();
        const auto expiry = ngtcp2_conn_get_expiry2(quic_.get());
        if (expiry <= now) wake = Clock::now();
        else if (expiry != std::numeric_limits<ngtcp2_tstamp>::max()) {
            const auto delta = std::min<uint64_t>(expiry - now, 60 * NGTCP2_SECONDS);
            wake = std::min(wake, Clock::now() + std::chrono::nanoseconds(delta));
        }
        pollfd descriptor{socket_.Fd(), static_cast<short>(POLLIN | (pending_size_ ? POLLOUT : 0)), 0};
        for (;;) {
            const auto remaining = wake - Clock::now();
            const auto delay = remaining <= Clock::duration::zero() ? 0 :
                std::min<int64_t>(std::chrono::ceil<Milliseconds>(remaining).count(), 60000);
            const int result = ::poll(&descriptor, 1, static_cast<int>(delay));
            if (result >= 0) break;
            if (errno != EINTR) SocketError("QUIC poll");
            if (Clock::now() >= wake) break;
        }
        if (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) Fail("QUIC UDP socket failed");
        // A packet flood cannot extend a Pump call indefinitely.
        std::array<uint8_t, 65536> packet{};
        for (size_t received = 0; received < 64; ++received) {
            const auto length = ::recv(socket_.Fd(), packet.data(), packet.size(), MSG_DONTWAIT);
            if (length < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR) {
                    if (Clock::now() >= deadline) break;
                    continue;
                }
                SocketError("QUIC recv");
            }
            auto path = Path();
            ngtcp2_pkt_info info{};
            const int result = ngtcp2_conn_read_pkt(quic_.get(), &path, &info, packet.data(),
                                                   static_cast<size_t>(length), Timestamp());
            if (result == NGTCP2_ERR_DRAINING || result == NGTCP2_ERR_IDLE_CLOSE) {
                closed_ = true;
                return;
            }
            CheckQuic(result, "read packet");
            if (Clock::now() >= deadline) break;
        }
        HandleExpiry();
        if (!closed_) Flush();
    }

    void Wait(const std::function<bool()>& condition, Milliseconds timeout = Milliseconds(5000)) {
        if (timeout < Milliseconds::zero()) throw std::runtime_error("negative QUIC wait timeout");
        WaitUntil(condition, Clock::now() + timeout);
    }

    // Predicates inspect borrowed storage only during the call, never across Pump.
    void WaitStream(int64_t id, const std::function<bool()>& condition,
                    Milliseconds timeout = Milliseconds(5000)) {
        try {
            Wait([&] {
                const auto& stream = Find(id);
                if (stream.reset || stream.read_stopped || stream.write_stopped || stream.close_error)
                    throw std::runtime_error("TCP stream terminated abnormally");
                if (condition()) return true;
                RequireActiveStream(id);
                return false;
            }, timeout);
        } catch (const std::exception& error) {
            throw std::runtime_error(std::string(error.what()) + " (" + DescribeStream(id) + ")");
        }
    }

    void WaitPayload(int64_t id, std::string_view expected, bool normal_close = false,
                     Milliseconds timeout = Milliseconds(5000)) {
        WaitStream(id, [&] {
            const auto& stream = Find(id);
            const bool complete = PayloadEquals(id, expected);
            if (stream.fin_received && !complete)
                throw std::runtime_error("TCP FIN before exact payload");
            return complete && (!normal_close || (stream.closed && stream.fin_received));
        }, timeout);
    }

    void WaitClosed(int64_t id, Milliseconds timeout = Milliseconds(5000)) {
        try { Wait([&] { return StreamClosed(id); }, timeout); }
        catch (const std::exception& error) {
            throw std::runtime_error(std::string(error.what()) + " (" + DescribeStream(id) + ")");
        }
    }

    void HoldReceiveCredit(int64_t id, bool hold = true) {
        auto& stream = Find(id);
        stream.hold_receive_credit = hold;
        if (!hold && stream.withheld_receive_credit != 0) {
            CheckQuic(ngtcp2_conn_extend_max_stream_offset(quic_.get(), id,
                stream.withheld_receive_credit), "restore receive stream credit");
            stream.withheld_receive_credit = 0;
            Flush();
        }
    }

    uint64_t StreamSendCredit(int64_t id) const {
        return ngtcp2_conn_get_max_stream_data_left2(quic_.get(), id);
    }
    uint64_t Submitted(int64_t id) const { return Find(id).submitted; }
    uint64_t Acknowledged(int64_t id) const { return Find(id).acknowledged; }
    uint64_t Queued(int64_t id) const { return Find(id).queued; }
    size_t Received(int64_t id) const { return Find(id).received.size(); }
    bool PayloadEquals(int64_t id, std::string_view expected) const {
        return PayloadView(id) == expected;
    }
    std::string DescribeStream(int64_t id) const {
        const auto& stream = Find(id);
        const auto* error = ngtcp2_conn_get_ccerr2(quic_.get());
        return "stream=" + std::to_string(id) +
            " queued=" + std::to_string(stream.queued) +
            " submitted=" + std::to_string(stream.submitted) +
            " acknowledged=" + std::to_string(stream.acknowledged) +
            " received=" + std::to_string(stream.received.size()) +
            " fin_requested=" + std::to_string(stream.fin_requested) +
            " fin_submitted=" + std::to_string(stream.fin_submitted) +
            " fin_received=" + std::to_string(stream.fin_received) +
            " reset=" + std::to_string(stream.reset) +
            " reset_code=" + std::to_string(stream.reset_code) +
            " write_stopped=" + std::to_string(stream.write_stopped) +
            " local_read_stopped=" + std::to_string(stream.read_stopped) +
            " local_read_stop_code=" + std::to_string(stream.read_stop_code) +
            " closed=" + std::to_string(stream.closed) +
            " close_error=" + std::to_string(stream.close_error) +
            " close_code=" + std::to_string(stream.close_code) +
            " stream_send_credit=" + std::to_string(StreamSendCredit(id)) +
            " connection_send_credit=" + std::to_string(SendCredit()) +
            " withheld_receive_credit=" + std::to_string(stream.withheld_receive_credit) +
            " connection_closed=" + std::to_string(closed_) +
            " connection_close_type=" + std::to_string(error->type) +
            " connection_close_code=" + std::to_string(error->error_code);
    }

    bool AllAcknowledged(int64_t id) const {
        const auto& stream = Find(id);
        return stream.submitted == stream.queued && stream.acknowledged == stream.queued;
    }
    bool StreamClosed(int64_t id) const { return Find(id).closed; }
    bool Closed() const noexcept { return closed_; }
    uint64_t SendCredit() const { return ngtcp2_conn_get_max_data_left2(quic_.get()); }

    std::string Payload(int64_t id) const { return std::string(PayloadView(id)); }

private:
    std::string_view PayloadView(int64_t id) const {
        const auto& stream = Find(id);
        const std::string_view wire = stream.received;
        if (wire.empty()) return {};
        if (static_cast<uint8_t>(wire.front()) != 0)
            throw std::runtime_error("HY2 TCP request rejected");
        size_t cursor = 1;
        uint64_t length = 0;
        if (!ReadVarint(wire, cursor, length)) return {};
        if (length > MaxReceiveBytes) throw std::runtime_error("HY2 response message limit");
        if (length > wire.size() - cursor) return {};
        cursor += static_cast<size_t>(length);
        if (!ReadVarint(wire, cursor, length)) return {};
        if (length > MaxReceiveBytes) throw std::runtime_error("HY2 response padding limit");
        if (length > wire.size() - cursor) return {};
        cursor += static_cast<size_t>(length);
        return wire.substr(cursor);
    }

    using Clock = std::chrono::steady_clock;
    static constexpr size_t MaxStreams = 4096;
    static constexpr size_t MaxSendBytes = 64 * 1024 * 1024;
    static constexpr size_t MaxReceiveBytes = 64 * 1024 * 1024;
    static constexpr size_t MaxChunks = 16384;
    struct Chunk { uint64_t offset; std::string bytes; };
    struct Stream {
        std::deque<Chunk> output;
        std::map<uint64_t, uint64_t> ack_ranges;
        std::string received;
        uint64_t queued = 0;
        uint64_t submitted = 0;
        uint64_t acknowledged = 0;
        uint64_t withheld_receive_credit = 0;
        uint64_t reset_code = 0;
        uint64_t read_stop_code = 0;
        uint64_t close_code = 0;
        bool fin_requested = false;
        bool fin_submitted = false;
        bool fin_received = false;
        bool hold_receive_credit = false;
        bool close_error = false;
        bool reset = false;
        bool write_stopped = false;
        bool read_stopped = false;
        bool closed = false;
    };

    static ngtcp2_tstamp Timestamp() noexcept {
        return static_cast<ngtcp2_tstamp>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now().time_since_epoch()).count());
    }
    static void AppendVarint(std::string& out, uint64_t value) {
        const size_t width = value < 64 ? 1 : value < 16384 ? 2 : value < (uint64_t{1} << 30) ? 4 : 8;
        if (value >= (uint64_t{1} << 62)) throw std::runtime_error("QUIC varint overflow");
        const size_t start = out.size();
        for (size_t index = width; index != 0; --index)
            out.push_back(static_cast<char>(value >> ((index - 1) * 8)));
        const uint8_t prefix = width == 1 ? 0 : width == 2 ? 0x40 : width == 4 ? 0x80 : 0xc0;
        out[start] = static_cast<char>(static_cast<uint8_t>(out[start]) | prefix);
    }
    static bool ReadVarint(std::string_view bytes, size_t& cursor, uint64_t& value) {
        if (cursor == bytes.size()) return false;
        const size_t width = size_t{1} << (static_cast<uint8_t>(bytes[cursor]) >> 6);
        if (width > bytes.size() - cursor) return false;
        value = static_cast<uint8_t>(bytes[cursor]) & 0x3f;
        for (size_t index = 1; index < width; ++index)
            value = (value << 8) | static_cast<uint8_t>(bytes[cursor + index]);
        cursor += width;
        return true;
    }
    [[noreturn]] void SocketError(const char* operation) {
        closed_ = true;
        throw std::system_error(errno, std::generic_category(), operation);
    }
    [[noreturn]] void Fail(std::string message) {
        closed_ = true;
        throw std::runtime_error("QUIC peer: " + std::move(message));
    }
    void RequireOpen() const {
        if (callback_failure_) std::rethrow_exception(callback_failure_);
        if (closed_) throw std::runtime_error("QUIC peer connection closed");
    }
    void CheckQuic(int result, std::string_view operation) {
        if (callback_failure_) std::rethrow_exception(callback_failure_);
        if (result != 0) Fail(std::string(operation) + ": " + ngtcp2_strerror(result));
    }
    void CheckHttp(int result, std::string_view operation) {
        if (callback_failure_) std::rethrow_exception(callback_failure_);
        if (result != 0) Fail(std::string(operation) + ": " + nghttp3_strerror(result));
    }
    template<class F> int Callback(F&& action, int error = NGTCP2_ERR_CALLBACK_FAILURE) noexcept {
        try { action(); return 0; }
        catch (...) {
            if (!callback_failure_) callback_failure_ = std::current_exception();
            closed_ = true;
            return error;
        }
    }
    Stream& Find(int64_t id) {
        const auto it = streams_.find(id);
        if (it == streams_.end()) throw std::runtime_error("unknown QUIC TCP stream");
        return it->second;
    }
    const Stream& Find(int64_t id) const {
        const auto it = streams_.find(id);
        if (it == streams_.end()) throw std::runtime_error("unknown QUIC TCP stream");
        return it->second;
    }
    void RequireActiveStream(int64_t id) const {
        const auto& stream = Find(id);
        if (stream.closed || stream.reset || stream.read_stopped || stream.write_stopped)
            throw std::runtime_error("TCP stream terminated before wait condition");
    }
    ngtcp2_path Path() noexcept {
        return {{reinterpret_cast<sockaddr*>(&local_), sizeof(local_)},
                {reinterpret_cast<sockaddr*>(&remote_), sizeof(remote_)}, nullptr};
    }
    void CheckQueue(size_t bytes) const {
        if (bytes > MaxSendBytes - send_bytes_ || (bytes != 0 && chunks_ >= MaxChunks))
            throw std::runtime_error("QUIC peer send queue limit");
    }
    void Queue(Stream& stream, std::string bytes, bool fin) {
        if (bytes.size() > (uint64_t{1} << 62) - 1 - stream.queued)
            throw std::runtime_error("QUIC peer stream offset limit");
        if (!bytes.empty()) {
            const size_t size = bytes.size();
            stream.output.push_back({stream.queued, std::move(bytes)});
            stream.queued += size;
            send_bytes_ += size;
            ++chunks_;
        }
        stream.fin_requested = fin;
    }
    void ReleaseOutput(Stream& stream) noexcept {
        for (const auto& chunk : stream.output) send_bytes_ -= chunk.bytes.size();
        chunks_ -= stream.output.size();
        stream.output.clear();
        stream.ack_ranges.clear();
    }
    void Credit(int64_t id, size_t length) {
        CheckQuic(ngtcp2_conn_extend_max_stream_offset(quic_.get(), id, length), "receive stream credit");
        ngtcp2_conn_extend_max_offset(quic_.get(), length);
    }
    void WaitUntil(const std::function<bool()>& condition, Clock::time_point deadline) {
        while (!condition()) {
            RequireOpen();
            const auto remaining = deadline - Clock::now();
            if (remaining <= Clock::duration::zero())
                throw std::runtime_error("QUIC peer wait deadline (connection send credit=" +
                    std::to_string(SendCredit()) + ")");
            Pump(std::min(Milliseconds(10), std::chrono::ceil<Milliseconds>(remaining)));
        }
        RequireOpen();
    }

    void InitializeQuic(uint64_t max_datagram_frame_size, uint64_t initial_receive_stream_window) {
        ngtcp2_callbacks callbacks{};
        callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
        callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
        callbacks.update_key = ngtcp2_crypto_update_key_cb;
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
        callbacks.rand = [](uint8_t* bytes, size_t length, const ngtcp2_rand_ctx*) {
            if (RAND_bytes(bytes, length) != 1) std::terminate();
        };
        callbacks.get_new_connection_id2 = [](ngtcp2_conn*, ngtcp2_cid* cid,
            ngtcp2_stateless_reset_token* token, size_t length, void*) {
            cid->datalen = length;
            return RAND_bytes(cid->data, length) == 1 &&
                RAND_bytes(token->data, sizeof(token->data)) == 1 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
        };
        callbacks.handshake_completed = [](ngtcp2_conn*, void* data) {
            static_cast<Peer*>(data)->handshake_complete_ = true;
            return 0;
        };
        callbacks.recv_rx_key = [](ngtcp2_conn*, ngtcp2_encryption_level level, void* data) {
            auto& self = *static_cast<Peer*>(data);
            return self.Callback([&] {
                if (level == NGTCP2_ENCRYPTION_LEVEL_1RTT) self.SetupHttp();
            });
        };
        callbacks.recv_stream_data = [](ngtcp2_conn*, uint32_t flags, int64_t id, uint64_t offset,
            const uint8_t* bytes, size_t length, void* data, void*) {
            auto& self = *static_cast<Peer*>(data);
            return self.Callback([&] { self.Receive(id, flags, offset, bytes, length); });
        };
        callbacks.recv_datagram = [](ngtcp2_conn*, uint32_t, const uint8_t* bytes,
            size_t length, void* data) {
            auto& self = *static_cast<Peer*>(data);
            return self.Callback([&] {
                if (self.datagrams_.size() >= 64 ||
                    length > MaxReceiveBytes - self.receive_bytes_)
                    self.Fail("QUIC datagram receive budget");
                self.datagrams_.emplace_back(reinterpret_cast<const char*>(bytes), length);
                self.receive_bytes_ += length;
            });
        };
        callbacks.acked_stream_data_offset = [](ngtcp2_conn*, int64_t id, uint64_t offset,
            uint64_t length, void* data, void*) {
            auto& self = *static_cast<Peer*>(data);
            return self.Callback([&] { self.Ack(id, offset, length); });
        };
        callbacks.stream_close = [](ngtcp2_conn*, uint32_t flags, int64_t id, uint64_t code, void* data, void*) {
            auto& self = *static_cast<Peer*>(data);
            return self.Callback([&] {
                if (auto it = self.streams_.find(id); it != self.streams_.end()) {
                    it->second.closed = true;
                    it->second.close_error = (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) != 0;
                    it->second.close_code = code;
                    self.ReleaseOutput(it->second);
                } else if (self.http_) {
                    const int result = nghttp3_conn_close_stream(self.http_.get(), id, code);
                    if (result != NGHTTP3_ERR_STREAM_NOT_FOUND) self.CheckHttp(result, "HTTP stream close");
                }
            });
        };
        callbacks.stream_reset = [](ngtcp2_conn*, int64_t id, uint64_t, uint64_t code, void* data, void*) {
            auto& self = *static_cast<Peer*>(data);
            return self.Callback([&] {
                if (auto it = self.streams_.find(id); it != self.streams_.end()) {
                    it->second.reset = true;
                    it->second.reset_code = code;
                }
                else if (self.http_) self.CheckHttp(nghttp3_conn_shutdown_stream_read(self.http_.get(), id), "HTTP reset");
            });
        };
        callbacks.stream_stop_sending = [](ngtcp2_conn*, int64_t id, uint64_t code, void* data, void*) {
            auto& self = *static_cast<Peer*>(data);
            return self.Callback([&] {
                if (auto it = self.streams_.find(id); it != self.streams_.end()) {
                    it->second.read_stopped = true;
                    it->second.read_stop_code = code;
                }
                else if (self.http_)
                    self.CheckHttp(nghttp3_conn_shutdown_stream_read(self.http_.get(), id),
                        "HTTP local read shutdown");
            });
        };
        callbacks.extend_max_stream_data = [](ngtcp2_conn*, int64_t id, uint64_t, void* data, void*) {
            auto& self = *static_cast<Peer*>(data);
            return self.Callback([&] {
                if (self.http_ && !self.streams_.contains(id))
                    self.CheckHttp(nghttp3_conn_unblock_stream(self.http_.get(), id), "HTTP unblock");
            });
        };
        ngtcp2_settings settings;
        ngtcp2_settings_default(&settings);
        settings.initial_ts = Timestamp();
        settings.handshake_timeout = 10 * NGTCP2_SECONDS;
        settings.max_tx_udp_payload_size = packet_.size();
        settings.no_pmtud = 1;
        ngtcp2_transport_params params;
        ngtcp2_transport_params_default(&params);
        params.initial_max_stream_data_bidi_local = initial_receive_stream_window;
        params.initial_max_stream_data_bidi_remote = 64 * 1024;
        params.initial_max_stream_data_uni = 256 * 1024;
        params.initial_max_data = 16 * 1024 * 1024;
        params.initial_max_streams_uni = 16;
        params.initial_max_streams_bidi = 0;
        params.max_idle_timeout = 60 * NGTCP2_SECONDS;
        params.active_connection_id_limit = 4;
        params.disable_active_migration = 1;
        params.max_datagram_frame_size = max_datagram_frame_size;
        ngtcp2_cid destination{}, source{};
        destination.datalen = 16;
        source.datalen = 8;
        if (RAND_bytes(destination.data, destination.datalen) != 1 ||
            RAND_bytes(source.data, source.datalen) != 1) Fail("connection ID entropy");
        auto path = Path();
        ngtcp2_conn* connection = nullptr;
        CheckQuic(ngtcp2_conn_client_new(&connection, &destination, &source, &path,
            NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, nullptr, this), "client new");
        quic_.reset(connection);
        ngtcp2_conn_set_tls_native_handle(quic_.get(), ssl_.get());
    }

    void SetupHttp() {
        if (http_) return;
        nghttp3_callbacks callbacks{};
        callbacks.recv_header = [](nghttp3_conn*, int64_t id, int32_t token, nghttp3_rcbuf* name,
            nghttp3_rcbuf* value, uint8_t, void* data, void*) {
            auto& self = *static_cast<Peer*>(data);
            return self.Callback([&] {
                const auto key = nghttp3_rcbuf_get_buf(name);
                const auto val = nghttp3_rcbuf_get_buf(value);
                if (key.len > 8192 - self.header_bytes_ || val.len > 8192 - self.header_bytes_ - key.len)
                    self.Fail("HTTP response header limit");
                self.header_bytes_ += key.len + val.len;
                if (id == self.auth_stream_ && token == NGHTTP3_QPACK_TOKEN__STATUS) {
                    if (!self.auth_status_.empty() || val.len != 3) self.Fail("invalid auth status");
                    self.auth_status_.assign(reinterpret_cast<const char*>(val.base), val.len);
                }
            }, NGHTTP3_ERR_CALLBACK_FAILURE);
        };
        callbacks.end_headers = [](nghttp3_conn*, int64_t id, int, void* data, void*) {
            auto& self = *static_cast<Peer*>(data);
            if (id == self.auth_stream_) self.auth_headers_complete_ = true;
            return 0;
        };
        callbacks.recv_data = [](nghttp3_conn*, int64_t id, const uint8_t*, size_t length, void* data, void*) {
            auto& self = *static_cast<Peer*>(data);
            return self.Callback([&] {
                if (length > 65536 - self.http_body_bytes_) self.Fail("HTTP response body limit");
                self.http_body_bytes_ += length;
                self.Credit(id, length);
            }, NGHTTP3_ERR_CALLBACK_FAILURE);
        };
        callbacks.deferred_consume = [](nghttp3_conn*, int64_t id, size_t length, void* data, void*) {
            auto& self = *static_cast<Peer*>(data);
            return self.Callback([&] { self.Credit(id, length); }, NGHTTP3_ERR_CALLBACK_FAILURE);
        };
        callbacks.stop_sending = [](nghttp3_conn*, int64_t id, uint64_t code, void* data, void*) {
            auto& self = *static_cast<Peer*>(data);
            return self.Callback([&] {
                self.CheckQuic(ngtcp2_conn_shutdown_stream_read(self.quic_.get(), 0, id, code), "HTTP stop sending");
            }, NGHTTP3_ERR_CALLBACK_FAILURE);
        };
        callbacks.reset_stream = [](nghttp3_conn*, int64_t id, uint64_t code, void* data, void*) {
            auto& self = *static_cast<Peer*>(data);
            return self.Callback([&] {
                self.CheckQuic(ngtcp2_conn_shutdown_stream_write(self.quic_.get(), 0, id, code), "HTTP reset stream");
            }, NGHTTP3_ERR_CALLBACK_FAILURE);
        };
        callbacks.rand = [](uint8_t* bytes, size_t length) {
            if (RAND_bytes(bytes, length) != 1) std::terminate();
        };
        nghttp3_settings settings;
        nghttp3_settings_default(&settings);
        settings.max_field_section_size = 8192;
        settings.qpack_max_dtable_capacity = 0;
        settings.qpack_encoder_max_dtable_capacity = 0;
        settings.qpack_blocked_streams = 0;
        nghttp3_conn* connection = nullptr;
        CheckHttp(nghttp3_conn_client_new(&connection, &callbacks, &settings, nullptr, this), "HTTP client new");
        http_.reset(connection);
        int64_t control = -1, encoder = -1, decoder = -1;
        CheckQuic(ngtcp2_conn_open_uni_stream(quic_.get(), &control, nullptr), "open HTTP control");
        CheckHttp(nghttp3_conn_bind_control_stream(http_.get(), control), "bind HTTP control");
        CheckQuic(ngtcp2_conn_open_uni_stream(quic_.get(), &encoder, nullptr), "open QPACK encoder");
        CheckQuic(ngtcp2_conn_open_uni_stream(quic_.get(), &decoder, nullptr), "open QPACK decoder");
        CheckHttp(nghttp3_conn_bind_qpack_streams(http_.get(), encoder, decoder), "bind QPACK");
    }

    void Receive(int64_t id, uint32_t flags, uint64_t offset, const uint8_t* bytes, size_t length) {
        if (auto it = streams_.find(id); it != streams_.end()) {
            auto& stream = it->second;
            if (offset != stream.received.size()) Fail("noncontiguous TCP receive offset");
            if (length > MaxReceiveBytes - receive_bytes_) Fail("TCP receive storage limit");
            stream.received.append(reinterpret_cast<const char*>(bytes), length);
            receive_bytes_ += length;
            stream.fin_received |= (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
            if (stream.hold_receive_credit) {
                stream.withheld_receive_credit += length;
                // Only the selected stream is blocked; ACKs and connection-wide
                // credit continue so another TCP stream can prove liveness.
                ngtcp2_conn_extend_max_offset(quic_.get(), length);
            } else {
                Credit(id, length);
            }
            return;
        }
        if (!http_ || (id != auth_stream_ && (id & 2) == 0)) Fail("unexpected incoming stream");
        const auto consumed = nghttp3_conn_read_stream2(http_.get(), id, bytes, length,
            (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0, Timestamp());
        if (consumed < 0) CheckHttp(static_cast<int>(consumed), "HTTP receive");
        Credit(id, static_cast<size_t>(consumed));
    }

    void Ack(int64_t id, uint64_t offset, uint64_t length) {
        auto it = streams_.find(id);
        if (it == streams_.end()) {
            if (http_) CheckHttp(nghttp3_conn_add_ack_offset(http_.get(), id, length), "HTTP ACK offset");
            return;
        }
        auto& stream = it->second;
        if (offset > stream.submitted || length > stream.submitted - offset) Fail("invalid TCP ACK range");
        if (length == 0) return;
        uint64_t start = offset, end = offset + length;
        auto range = stream.ack_ranges.lower_bound(start);
        if (range != stream.ack_ranges.begin() && std::prev(range)->second >= start) --range;
        while (range != stream.ack_ranges.end() && range->first <= end) {
            start = std::min(start, range->first);
            end = std::max(end, range->second);
            range = stream.ack_ranges.erase(range);
        }
        if (stream.ack_ranges.size() >= MaxChunks) Fail("TCP ACK range limit");
        stream.ack_ranges.emplace(start, end);
        while (!stream.ack_ranges.empty() && stream.ack_ranges.begin()->first <= stream.acknowledged) {
            stream.acknowledged = std::max(stream.acknowledged, stream.ack_ranges.begin()->second);
            stream.ack_ranges.erase(stream.ack_ranges.begin());
        }
        while (!stream.output.empty()) {
            const auto& chunk = stream.output.front();
            if (chunk.offset + chunk.bytes.size() > stream.acknowledged) break;
            send_bytes_ -= chunk.bytes.size();
            --chunks_;
            stream.output.pop_front();
        }
    }

    void HandleExpiry() {
        if (ngtcp2_conn_get_expiry2(quic_.get()) > Timestamp()) return;
        const int result = ngtcp2_conn_handle_expiry(quic_.get(), Timestamp());
        if (result == NGTCP2_ERR_IDLE_CLOSE || result == NGTCP2_ERR_DRAINING) {
            closed_ = true;
            return;
        }
        CheckQuic(result, "QUIC expiry");
    }
    bool SendPacket() {
        if (pending_size_ == 0) return true;
        const auto length = ::send(socket_.Fd(), packet_.data(), pending_size_, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (length < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return false;
            SocketError("QUIC send");
        }
        if (static_cast<size_t>(length) != pending_size_) Fail("short QUIC UDP send");
        pending_size_ = 0;
        return true;
    }
    void Flush() {
        RequireOpen();
        if (!SendPacket()) return;
        struct UpdateTxTime {
            ngtcp2_conn* connection;
            ~UpdateTxTime() { ngtcp2_conn_update_pkt_tx_time(connection, Timestamp()); }
        } update{quic_.get()};
        const size_t attempts = std::clamp<size_t>(
            ngtcp2_conn_get_send_quantum2(quic_.get()) / packet_.size(), 1, 64);
        std::map<int64_t, bool> skipped;
        for (size_t attempt = 0; attempt < attempts; ++attempt) {
            int64_t id = -1;
            int fin = 0;
            bool http = false;
            std::array<ngtcp2_vec, 16> vectors{};
            size_t count = 0;
            if (http_) {
                std::array<nghttp3_vec, 16> http_vectors{};
                const auto result = nghttp3_conn_writev_stream(http_.get(), &id, &fin,
                    http_vectors.data(), http_vectors.size());
                if (result < 0) CheckHttp(static_cast<int>(result), "HTTP write vectors");
                count = static_cast<size_t>(result);
                for (size_t index = 0; index < count; ++index)
                    vectors[index] = {http_vectors[index].base, http_vectors[index].len};
                http = id >= 0;
            }
            Stream* stream = nullptr;
            size_t offered = 0;
            if (!http) {
                for (auto& [candidate, state] : streams_) {
                    if (state.closed || state.reset || state.write_stopped || skipped.contains(candidate)) continue;
                    if (state.submitted == state.queued && (!state.fin_requested || state.fin_submitted)) continue;
                    id = candidate;
                    stream = &state;
                    for (const auto& chunk : state.output) {
                        if (chunk.offset + chunk.bytes.size() <= state.submitted) continue;
                        const size_t skip = state.submitted > chunk.offset ?
                            static_cast<size_t>(state.submitted - chunk.offset) : 0;
                        const size_t size = chunk.bytes.size() - skip;
                        vectors[count++] = {reinterpret_cast<uint8_t*>(const_cast<char*>(chunk.bytes.data() + skip)), size};
                        offered += size;
                        if (count == vectors.size()) break;
                    }
                    fin = state.fin_requested && state.submitted + offered == state.queued;
                    break;
                }
            }
            ngtcp2_path_storage output_path;
            ngtcp2_path_storage_zero(&output_path);
            ngtcp2_pkt_info info{};
            ngtcp2_ssize accepted = -1;
            const auto result = ngtcp2_conn_writev_stream(quic_.get(), &output_path.path, &info,
                packet_.data(), packet_.size(), &accepted,
                fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : NGTCP2_WRITE_STREAM_FLAG_NONE,
                id, vectors.data(), count, Timestamp());
            if (result == NGTCP2_ERR_STREAM_DATA_BLOCKED || result == NGTCP2_ERR_STREAM_SHUT_WR ||
                result == NGTCP2_ERR_STREAM_NOT_FOUND) {
                if (http) {
                    if (result == NGTCP2_ERR_STREAM_DATA_BLOCKED) nghttp3_conn_block_stream(http_.get(), id);
                    else nghttp3_conn_shutdown_stream_write(http_.get(), id);
                } else if (stream) {
                    skipped.emplace(id, true);
                    if (result != NGTCP2_ERR_STREAM_DATA_BLOCKED) stream->write_stopped = true;
                }
                continue;
            }
            if (result < 0) CheckQuic(static_cast<int>(result), "write packet");
            if (accepted >= 0) {
                if (http) CheckHttp(nghttp3_conn_add_write_offset(http_.get(), id,
                    static_cast<size_t>(accepted)), "HTTP write offset");
                else if (stream) {
                    stream->submitted += static_cast<uint64_t>(accepted);
                    if (fin && static_cast<size_t>(accepted) == offered) stream->fin_submitted = true;
                }
            }
            if (result == 0) return;
            pending_size_ = static_cast<size_t>(result);
            if (!SendPacket()) return;
        }
    }

    Socket socket_;
    sockaddr_in local_{};
    sockaddr_in remote_{};
    std::map<int64_t, Stream> streams_;
    std::deque<std::string> datagrams_;
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context_;
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl_;
    std::unique_ptr<nghttp3_conn, decltype(&nghttp3_conn_del)> http_;
    ngtcp2_crypto_conn_ref conn_ref_{};
    std::unique_ptr<ngtcp2_conn, decltype(&ngtcp2_conn_del)> quic_;
    std::exception_ptr callback_failure_;
    std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> packet_{};
    size_t pending_size_ = 0;
    size_t send_bytes_ = 0;
    size_t receive_bytes_ = 0;
    size_t chunks_ = 0;
    size_t header_bytes_ = 0;
    size_t http_body_bytes_ = 0;
    int64_t auth_stream_ = -1;
    std::string auth_status_;
    bool handshake_complete_ = false;
    bool auth_headers_complete_ = false;
    bool closed_ = false;
};

inline Json HysteriaInbound(uint16_t port) {
    return {{"protocol", "hysteria2"}, {"listen", "127.0.0.1"}, {"port", port},
        {"settings", {{"upMbps", 100}, {"downMbps", 100},
            {"clients", Json::array({{{"password", "smoke-secret"}}})}}},
        {"sniffing", {{"enabled", false}}}, {"streamSettings", TlsSettings(true)}};
}

// A query observed here proves dispatch is waiting for DNS rather than
// forwarding this request's later traffic to its outbound.
class DnsBlackhole final {
public:
    Socket socket = Socket::BindUdp(0, "127.77.0.2");
    explicit DnsBlackhole(bool retain_queries = false) : retain_queries_(retain_queries) {}

    bool Observed(std::string_view expected) {
        bool found = false;
        for (size_t packet = 0; packet < 64; ++packet) {
            std::array<uint8_t, 4096> bytes{};
            sockaddr_in source{};
            socklen_t source_length = sizeof(source);
            const auto received = recvfrom(socket.Fd(), bytes.data(), bytes.size(), MSG_DONTWAIT,
                reinterpret_cast<sockaddr*>(&source), &source_length);
            if (received < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                throw std::system_error(errno, std::generic_category(), "receive DNS query");
            }
            const size_t length = static_cast<size_t>(received);
            if (length < 13 || (bytes[2] & 0x80) != 0) continue;
            std::string name;
            size_t offset = 12;
            while (offset < length) {
                const size_t count = bytes[offset++];
                if (count == 0) {
                    found |= name == expected;
                    if (retain_queries_ && name == expected) {
                        if (offset + 4 > length || queries_.size() >= 32)
                            throw std::runtime_error("retained DNS question limit");
                        queries_.push_back({std::string(reinterpret_cast<const char*>(bytes.data()),
                            offset + 4), source});
                    }
                    break;
                }
                if (count > 63 || count > length - offset)
                    throw std::runtime_error("invalid DNS query name");
                if (!name.empty()) name += '.';
                name.append(reinterpret_cast<const char*>(bytes.data() + offset), count);
                offset += count;
            }
        }
        if (released_ && !queries_.empty()) Release();
        return found;
    }

    void Hold() {
        if (!queries_.empty()) throw std::runtime_error("unreleased DNS question");
        released_ = false;
    }

    // Release just the observed questions on the real resolver socket. A gets
    // loopback; AAAA gets a successful empty answer, avoiding an external DNS.
    void Release() {
        released_ = true;
        if (queries_.empty()) throw std::runtime_error("no retained DNS question");
        for (auto& query : queries_) {
            auto& reply = query.wire;
            const bool address = static_cast<uint8_t>(reply[reply.size() - 4]) == 0 &&
                static_cast<uint8_t>(reply[reply.size() - 3]) == 1;
            reply[2] = static_cast<char>(0x81);
            reply[3] = static_cast<char>(0x80);
            reply[4] = 0;
            reply[5] = 1;
            reply[6] = 0;
            reply[7] = address ? 1 : 0;
            for (size_t i = 8; i < 12; ++i) reply[i] = 0;
            if (address) {
                constexpr std::array<uint8_t, 16> answer{
                    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1};
                reply.append(reinterpret_cast<const char*>(answer.data()), answer.size());
            }
            const auto sent = sendto(socket.Fd(), reply.data(), reply.size(), 0,
                reinterpret_cast<const sockaddr*>(&query.source), sizeof(query.source));
            if (sent < 0)
                throw std::system_error(errno, std::generic_category(), "release DNS question");
            if (static_cast<size_t>(sent) != reply.size())
                throw std::runtime_error("partial DNS response");
        }
        queries_.clear();
    }

private:
    struct Query {
        std::string wire;
        sockaddr_in source;
    };
    bool retain_queries_ = false;
    bool released_ = false;
    std::vector<Query> queries_;

};
} // namespace cnode::e2e::quic
