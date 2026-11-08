#include "transport/internet/ws_stream.hpp"
#include "http1_handshake.hpp"
#include "http_path_match.hpp"
#include "common/binary_text_codec.hpp"
#include "common/unsafe.hpp"
#include "common/buffer_util.hpp"
#include "infra/log.hpp"

#include <openssl/base64.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <algorithm>
#include <limits>
#include <string_view>
#include <stdexcept>


namespace ws {

std::array<char, 28> EncodeWsAccept(std::string_view ws_key) noexcept {
    constexpr std::string_view kWsGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t sha1[SHA_DIGEST_LENGTH];
    SHA_CTX context;
    SHA1_Init(&context);
    SHA1_Update(&context, ws_key.data(), ws_key.size());
    SHA1_Update(&context, kWsGuid.data(), kWsGuid.size());
    SHA1_Final(sha1, &context);
    OPENSSL_cleanse(&context, sizeof(context));
    std::array<uint8_t, 29> encoded{};
    EVP_EncodeBlock(encoded.data(), sha1, sizeof(sha1));
    OPENSSL_cleanse(sha1, sizeof(sha1));
    std::array<char, 28> out{};
    std::memcpy(out.data(), encoded.data(), out.size());
    OPENSSL_cleanse(encoded.data(), encoded.size());
    return out;
}

std::string ComputeWsAccept(std::string_view ws_key) {
    const auto accept = EncodeWsAccept(ws_key);
    return std::string(accept.data(), accept.size());
}

}  // namespace ws

namespace {
using transport::internet::TrimAscii;
using transport::internet::detail::EffectiveHttpPath;

class WriteGateWait final : private transport::CancellationSubscription {
public:
    WriteGateWait(transport::CancellationSource& source, net::cancellation_slot parent)
        : parent_(parent) {
        if (parent_.is_connected()) {
            parent_.assign([this](net::cancellation_type type) {
                cancelled_ = true;
                signal_.emit(type);
            });
        }
        Resubscribe(source);
    }

    ~WriteGateWait() {
        if (parent_.is_connected()) parent_.clear();
    }

    net::cancellation_slot Slot() noexcept { return signal_.slot(); }
    bool Cancelled() const noexcept { return cancelled_; }

private:
    void OnCancellation(transport::Cancellation) noexcept override {
        cancelled_ = true;
        signal_.emit(net::cancellation_type::all);
    }

    net::cancellation_slot parent_;
    net::cancellation_signal signal_;
    bool cancelled_ = false;
};

void AddPayloadSize(size_t& total, size_t size) {
    if (size > BaseWsStream::kMaxFrameSize - total)
        throw IoSystemError(io_error::message_size, "WebSocket frame exceeds payload budget");
    total += size;
}

}  // namespace

BaseWsStream::BaseWsStream(
    std::unique_ptr<AsyncStream> inner, uint64_t conn_id, bool is_client)
    : inner_(std::move(inner)), conn_id_(conn_id), is_client_(is_client) {}

BaseWsStream::~BaseWsStream() noexcept {
    Close();
}

void BaseWsStream::SetPendingData(const uint8_t* data, size_t len) {
    if (!buf::AppendSpanToMultiBuffer(std::span<const uint8_t>(data, len), pending_data_)) {
        throw std::bad_alloc();
    }
}

bool BaseWsStream::Utf8State::Consume(std::span<const uint8_t> bytes) noexcept {
    for (const uint8_t byte : bytes) {
        if (remaining != 0) {
            if (byte < minimum || byte > maximum) return false;
            --remaining;
            minimum = 0x80;
            maximum = 0xbf;
        } else if (byte <= 0x7f) {
            continue;
        } else if (byte >= 0xc2 && byte <= 0xdf) {
            remaining = 1;
        } else if (byte >= 0xe0 && byte <= 0xef) {
            remaining = 2;
            if (byte == 0xe0) minimum = 0xa0;
            if (byte == 0xed) maximum = 0x9f;
        } else if (byte >= 0xf0 && byte <= 0xf4) {
            remaining = 3;
            if (byte == 0xf0) minimum = 0x90;
            if (byte == 0xf4) maximum = 0x8f;
        } else {
            return false;
        }
    }
    return true;
}

[[noreturn]] void BaseWsStream::ProtocolFailure(const char* reason) {
    CloseAbortive();
    throw IoSystemError(io_error::connection_reset, reason);
}

net::awaitable<bool> BaseWsStream::EnsurePendingData() {
    if (closed_ || read_closed_) co_return false;
    while (!pending_data_.empty()) {
        if (const buf::Buffer* front = *pending_data_.begin();
            front && !front->IsEmpty()) {
            co_return true;
        }
        pending_data_.drop_front(1);
    }
    buf::MultiBuffer next;
    try {
        next = co_await inner_->ReadMultiBuffer();
    } catch (const IoSystemError& error) {
        if (error.code() != io_error::eof) throw;
        if (!closed_ && !read_closed_) ProtocolFailure("WebSocket truncated without Close");
        co_return false;
    }
    if (next.empty()) {
        if (!closed_ && !read_closed_)
            ProtocolFailure("WebSocket truncated without Close");
        co_return false;
    }
    pending_data_.AppendAndCoalesce(std::move(next));
    co_return !pending_data_.empty();
}

net::awaitable<size_t> BaseWsStream::ReadSome(uint8_t* data, size_t size) {
    if (!co_await EnsurePendingData()) co_return 0;
    const size_t n = pending_data_.ConsumePrefixTo(std::span<uint8_t>(data, size));
    pending_data_.ReleaseIfIdle();
    co_return n;
}

net::awaitable<bool> BaseWsStream::FillHeader() {
    while (header_used_ < header_required_) {
        const size_t n = co_await ReadSome(
            header_.data() + header_used_, header_required_ - header_used_);
        if (n == 0) co_return false;
        header_used_ += n;
    }
    co_return true;
}

void BaseWsStream::FinishDataFrame() {
    if (frame_fin_ && text_message_ && text_utf8_.remaining != 0)
        ProtocolFailure("WebSocket incomplete UTF-8 text message");
    read_stage_ = ReadStage::Header;
}

void BaseWsStream::ValidateClose() {
    // RFC 6455 §§5.5.1, 7.4, 8.1: a Close is empty or status + UTF-8 reason.
    if (control_used_ == 1) ProtocolFailure("WebSocket invalid Close payload length");
    if (control_used_ < 2) return;
    const unsigned status = (static_cast<unsigned>(control_payload_[0]) << 8) |
                            control_payload_[1];
    const bool standard = status >= 1000 && status <= 1014 &&
                          status != 1004 && status != 1005 && status != 1006;
    if (!standard && !(status >= 3000 && status <= 4999))
        ProtocolFailure("WebSocket invalid Close status");
    Utf8State reason;
    if (!reason.Consume(std::span<const uint8_t>(control_payload_.data() + 2,
                                               control_used_ - 2)) ||
        reason.remaining != 0)
        ProtocolFailure("WebSocket invalid Close reason");
}

net::awaitable<bool> BaseWsStream::PrepareNextDataFrame() {
    while (!closed_ && !read_closed_ && !peer_closed_cleanly_) {
        switch (read_stage_) {
            case ReadStage::Header: {
                if (!co_await FillHeader()) co_return false;
                // No extensions are negotiated. RFC 6455 §§5.2–5.5 require
                // rejecting reserved bits/opcodes, wrong mask direction and
                // fragmented or oversized control frames before their body.
                if ((header_[0] & 0x70) != 0)
                    ProtocolFailure("WebSocket unexpected RSV bits");
                frame_opcode_ = static_cast<ws::Opcode>(header_[0] & 0x0f);
                switch (frame_opcode_) {
                    case ws::Opcode::CONTINUATION:
                    case ws::Opcode::TEXT:
                    case ws::Opcode::BINARY:
                    case ws::Opcode::CLOSE:
                    case ws::Opcode::PING:
                    case ws::Opcode::PONG:
                        break;
                    default:
                        ProtocolFailure("WebSocket reserved opcode");
                }
                frame_fin_ = (header_[0] & 0x80) != 0;
                frame_masked_ = (header_[1] & 0x80) != 0;
                if (frame_masked_ == is_client_)
                    ProtocolFailure("WebSocket invalid mask direction");
                const uint8_t length = header_[1] & 0x7f;
                const bool control = (header_[0] & 0x08) != 0;
                if (control && (!frame_fin_ || length > 125))
                    ProtocolFailure("WebSocket invalid control frame");
                if (length >= 126) {
                    header_required_ = length == 126 ? 4 : 10;
                    read_stage_ = ReadStage::Length;
                } else {
                    frame_payload_remaining_ = length;
                    header_required_ = 2 + (frame_masked_ ? 4 : 0);
                    read_stage_ = ReadStage::Mask;
                }
                break;
            }
            case ReadStage::Length: {
                if (!co_await FillHeader()) co_return false;
                uint64_t length = 0;
                for (size_t i = 2; i < header_required_; ++i)
                    length = (length << 8) | header_[i];
                if ((header_required_ == 4 && length < 126) ||
                    (header_required_ == 10 && (length < 65536 || (header_[2] & 0x80))))
                    ProtocolFailure("WebSocket noncanonical payload length");
                if (length > kMaxFrameSize)
                    ProtocolFailure("WebSocket frame exceeds payload budget");
                frame_payload_remaining_ = length;
                header_required_ += frame_masked_ ? 4 : 0;
                read_stage_ = ReadStage::Mask;
                break;
            }
            case ReadStage::Mask: {
                if (!co_await FillHeader()) co_return false;
                if (frame_masked_)
                    std::memcpy(frame_mask_key_.data(),
                                header_.data() + header_required_ - 4, 4);
                frame_mask_offset_ = 0;
                header_used_ = 0;
                header_required_ = 2;
                if ((static_cast<uint8_t>(frame_opcode_) & 0x08) != 0) {
                    control_used_ = 0;
                    read_stage_ = ReadStage::Control;
                    break;
                }
                if (frame_opcode_ == ws::Opcode::CONTINUATION) {
                    if (!fragmented_)
                        ProtocolFailure("WebSocket unexpected continuation");
                } else {
                    if (fragmented_)
                        ProtocolFailure("WebSocket interrupted fragmented message");
                    text_message_ = frame_opcode_ == ws::Opcode::TEXT;
                    text_utf8_ = {};
                }
                fragmented_ = !frame_fin_;
                read_stage_ = ReadStage::Payload;
                break;
            }
            case ReadStage::Payload:
                if (frame_payload_remaining_ != 0) co_return true;
                FinishDataFrame();
                break;
            case ReadStage::Control: {
                while (frame_payload_remaining_ != 0) {
                    const size_t n = co_await ReadSome(
                        control_payload_.data() + control_used_,
                        static_cast<size_t>(frame_payload_remaining_));
                    if (n == 0) co_return false;
                    if (frame_masked_)
                        ws::MaskData(control_payload_.data() + control_used_, n,
                                     frame_mask_key_.data(), control_used_);
                    control_used_ += n;
                    frame_payload_remaining_ -= n;
                }
                const auto payload = std::span<const uint8_t>(
                    control_payload_.data(), control_used_);
                if (frame_opcode_ == ws::Opcode::CLOSE) {
                    ValidateClose();
                    if (fragmented_)
                        ProtocolFailure("WebSocket Close during fragmented message");
                    peer_closed_cleanly_ = true;
                    try {
                        co_await WriteControlFrame(ws::Opcode::CLOSE, payload);
                    } catch (const IoSystemError& e) {
                        if (e.code() == io_error::operation_aborted) throw;
                        Close();
                    }
                    co_return false;
                }
                if (frame_opcode_ == ws::Opcode::PING)
                    co_await WriteControlFrame(ws::Opcode::PONG, payload);
                read_stage_ = ReadStage::Header;
                break;
            }
        }
    }
    co_return false;
}

net::awaitable<size_t> BaseWsStream::ReadPayload(net::mutable_buffer buffer) {
    const size_t size = static_cast<size_t>(std::min<uint64_t>(
        buffer.size(), frame_payload_remaining_));
    auto* data = static_cast<uint8_t*>(buffer.data());
    // A single read-some commits its bytes immediately. Filling the requested
    // buffer would both delay small messages and lose an unreported prefix if
    // a later lower-layer read were cancelled.
    const size_t n = co_await ReadSome(data, size);
    if (n == 0) co_return 0;
    if (frame_masked_)
        ws::MaskData(data, n, frame_mask_key_.data(), frame_mask_offset_);
    frame_mask_offset_ += n;
    frame_payload_remaining_ -= n;
    if (text_message_ && !text_utf8_.Consume(std::span<const uint8_t>(data, n)))
        ProtocolFailure("WebSocket invalid UTF-8 text message");
    if (frame_payload_remaining_ == 0) FinishDataFrame();
    co_return n;
}

net::awaitable<size_t> BaseWsStream::AsyncRead(net::mutable_buffer buffer) {
    if (buffer.size() == 0 || !co_await PrepareNextDataFrame()) co_return 0;
    co_return co_await ReadPayload(buffer);
}

net::awaitable<buf::MultiBuffer> BaseWsStream::ReadMultiBuffer() {
    if (!co_await PrepareNextDataFrame()) co_return buf::MultiBuffer{};
    if (!co_await EnsurePendingData()) co_return buf::MultiBuffer{};
    if (buf::Buffer* front = *pending_data_.begin();
        front && front->Len() <= frame_payload_remaining_) {
        buf::BufferGuard output = pending_data_.pop_front();
        pending_data_.ReleaseIfIdle();
        auto bytes = output->Bytes();
        if (frame_masked_)
            ws::MaskData(bytes.data(), bytes.size(), frame_mask_key_.data(), frame_mask_offset_);
        frame_mask_offset_ += bytes.size();
        frame_payload_remaining_ -= bytes.size();
        if (text_message_ && !text_utf8_.Consume(bytes))
            ProtocolFailure("WebSocket invalid UTF-8 text message");
        if (frame_payload_remaining_ == 0) FinishDataFrame();
        co_return buf::MultiBuffer{std::move(output)};
    }
    buf::BufferGuard output{buf::Buffer::New()};
    if (!output) throw std::bad_alloc();
    const size_t n = co_await ReadPayload(net::buffer(output->Tail().data(), output->Available()));
    if (n == 0) co_return buf::MultiBuffer{};
    output->Produce(static_cast<uint32_t>(n));
    co_return buf::MultiBuffer{std::move(output)};
}

void BaseWsStream::CheckWritable() const {
    if (closed_ || close_requested_ || write_closed_)
        throw IoSystemError(io_error::broken_pipe, "WebSocket write after Close");
}

net::awaitable<BaseWsStream::WriteGate::Lease> BaseWsStream::AcquireWrite(
    net::cancellation_slot caller_slot) {
    if (auto lease = write_gate_.TryAcquire()) co_return lease;
    const auto executor = co_await net::this_coro::executor;
    // Cancel() is reusable, so only this acquisition is cancelled. Closing the
    // shared gate is reserved for terminal shutdown, not a sniff deadline.
    WriteGateWait wait(Cancellation(), caller_slot);
    if (wait.Cancelled()) throw IoSystemError(io_error::operation_aborted);
    auto lease = co_await net::co_spawn(
        executor, write_gate_.Acquire(),
        net::bind_cancellation_slot(wait.Slot(), net::use_awaitable));
    if (!lease || wait.Cancelled()) throw IoSystemError(io_error::operation_aborted);
    co_return lease;
}

net::awaitable<void> BaseWsStream::WriteDataFrame(
    std::span<const net::const_buffer> buffers, size_t size) {
    const auto state = co_await net::this_coro::cancellation_state;
    if (closed_ || state.cancelled() != net::cancellation_type::none)
        throw IoSystemError(io_error::operation_aborted);
    WriteGate::Lease lease = write_gate_.TryAcquire();
    if (!lease) lease = co_await AcquireWrite(state.slot());
    CheckWritable();
    uint8_t mask[4]{};
    if (is_client_ && RAND_bytes(mask, sizeof(mask)) != 1)
        throw IoSystemError(io_error::fault, "WebSocket mask generation failed");
    const auto header = ws::EncodeFrameHeader(size, ws::Opcode::BINARY, is_client_, mask);
    try {
        if (!is_client_) {
            ConstBufferSpanBuilder<16> output;
            output.Append(net::buffer(header.bytes.data(), header.size));
            output.AppendBuffers(buffers);
            co_await inner_->WriteBuffers(output.Span());
        } else {
            buf::BufferGuard scratch{buf::Buffer::New()};
            if (!scratch) throw std::bad_alloc();
            std::memcpy(scratch->Tail().data(), header.bytes.data(), header.size);
            scratch->Produce(static_cast<uint32_t>(header.size));
            size_t offset = 0;
            for (const auto& buffer : buffers) {
                const auto* data = static_cast<const uint8_t*>(buffer.data());
                size_t remaining = buffer.size();
                while (remaining != 0) {
                    if (scratch->Available() == 0) {
                        const auto bytes = scratch->Bytes();
                        const net::const_buffer output(bytes.data(), bytes.size());
                        co_await inner_->WriteBuffers({&output, 1});
                        scratch->Reset();
                    }
                    const size_t chunk = std::min(remaining, static_cast<size_t>(scratch->Available()));
                    uint8_t* dst = scratch->Tail().data();
                    std::memcpy(dst, data, chunk);
                    ws::MaskData(dst, chunk, mask, offset);
                    scratch->Produce(static_cast<uint32_t>(chunk));
                    data += chunk;
                    remaining -= chunk;
                    offset += chunk;
                }
            }
            if (!scratch->IsEmpty()) {
                const auto bytes = scratch->Bytes();
                const net::const_buffer output(bytes.data(), bytes.size());
                co_await inner_->WriteBuffers({&output, 1});
            }
        }
    } catch (...) {
        // A cancelled or failed physical write may already have sent a prefix.
        // It cannot be retried or followed by another frame on this connection.
        CloseAbortive();
        throw;
    }
}

net::awaitable<void> BaseWsStream::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    CheckWritable();
    size_t size = 0;
    for (const auto& buffer : buffers) AddPayloadSize(size, buffer.size());
    if (size != 0) co_await WriteDataFrame(buffers, size);
}

net::awaitable<size_t> BaseWsStream::AsyncWrite(net::const_buffer buffer) {
    CheckWritable();
    if (buffer.size() > kMaxFrameSize)
        throw IoSystemError(io_error::message_size, "WebSocket frame exceeds payload budget");
    if (buffer.size() != 0) co_await WriteDataFrame({&buffer, 1}, buffer.size());
    co_return buffer.size();
}

net::awaitable<void> BaseWsStream::WriteMultiBuffer(buf::MultiBuffer buffers) {
    struct ClearOnExit {
        buf::MultiBuffer& mb;
        ~ClearOnExit() { mb.clear(); }
    } clear_guard{buffers};
    CheckWritable();
    size_t size = 0;
    for (const auto* buffer : buffers) {
        if (!buffer || buffer->IsEmpty()) continue;
        AddPayloadSize(size, buffer->Len());
    }
    if (size == 0) co_return;
    const auto state = co_await net::this_coro::cancellation_state;
    if (closed_ || state.cancelled() != net::cancellation_type::none)
        throw IoSystemError(io_error::operation_aborted);
    WriteGate::Lease lease = write_gate_.TryAcquire();
    if (!lease) lease = co_await AcquireWrite(state.slot());
    CheckWritable();
    uint8_t mask[4]{};
    if (is_client_ && RAND_bytes(mask, sizeof(mask)) != 1)
        throw IoSystemError(io_error::fault, "WebSocket mask generation failed");
    const auto header = ws::EncodeFrameHeader(size, ws::Opcode::BINARY, is_client_, mask);
    try {
        ConstBufferSpanBuilder<16> output;
        output.Append(net::buffer(header.bytes.data(), header.size));
        size_t offset = 0;
        for (auto* buffer : buffers) {
            if (!buffer || buffer->IsEmpty()) continue;
            auto bytes = buffer->Bytes();
            if (is_client_) {
                ws::MaskData(bytes.data(), bytes.size(), mask, offset);
                offset += bytes.size();
            }
            output.Append(net::buffer(bytes.data(), bytes.size()));
        }
        co_await inner_->WriteBuffers(output.Span());
    } catch (...) {
        CloseAbortive();
        throw;
    }
}
net::awaitable<void> BaseWsStream::WriteControlFrame(
    ws::Opcode opcode, std::span<const uint8_t> payload) {
    const bool closing = opcode == ws::Opcode::CLOSE;
    const auto state = co_await net::this_coro::cancellation_state;
    if (closed_ || state.cancelled() != net::cancellation_type::none)
        throw IoSystemError(io_error::operation_aborted);
    WriteGate::Lease lease = write_gate_.TryAcquire();
    if (!lease) lease = co_await AcquireWrite(state.slot());
    if (write_closed_ || (!closing && close_requested_)) co_return;
    if (closing) close_requested_ = true;
    uint8_t mask[4]{};
    if (is_client_ && RAND_bytes(mask, sizeof(mask)) != 1)
        throw IoSystemError(io_error::fault, "WebSocket mask generation failed");
    const auto header = ws::EncodeFrameHeader(payload.size(), opcode, is_client_, mask);
    std::array<uint8_t, 14 + 125> frame;
    std::memcpy(frame.data(), header.bytes.data(), header.size);
    if (!payload.empty()) std::memcpy(frame.data() + header.size, payload.data(), payload.size());
    if (is_client_) ws::MaskData(frame.data() + header.size, payload.size(), mask);
    const net::const_buffer output(frame.data(), header.size + payload.size());
    try {
        co_await inner_->WriteBuffers({&output, 1});
        if (closing) {
            write_closed_ = true;
            co_await inner_->AsyncShutdownWrite();
        }
    } catch (...) {
        CloseAbortive();
        throw;
    }
}

net::awaitable<void> BaseWsStream::AsyncShutdownWrite() {
    if (closed_ || write_closed_) co_return;
    constexpr std::array<uint8_t, 2> normal_close{0x03, 0xe8};
    co_await WriteControlFrame(ws::Opcode::CLOSE, normal_close);
}

void BaseWsStream::ShutdownWrite() {
    if (closed_ || write_closed_) return;
    // Synchronous shutdown cannot wait behind an in-flight frame or complete
    // the closing handshake; it must not splice a TCP FIN into that frame.
    CloseAbortive();
}

void BaseWsStream::ShutdownRead() {
    if (read_closed_) return;
    read_closed_ = true;
    pending_data_.clear();
    inner_->ShutdownRead();
}

void BaseWsStream::Close() {
    NotifyClosed();
    write_gate_.Cancel();
    if (closed_) return;
    closed_ = true;
    close_requested_ = true;
    pending_data_.clear();
    inner_->Close();
}

void BaseWsStream::CloseAbortive() {
    NotifyClosed();
    write_gate_.Cancel();
    if (closed_) return;
    closed_ = true;
    close_requested_ = true;
    pending_data_.clear();
    inner_->CloseAbortive();
}

void BaseWsStream::Cancel() noexcept {
    NotifyCancellation();
    inner_->Cancel();
}

bool BaseWsStream::IsOpen() const { return !closed_ && inner_->IsOpen(); }
int BaseWsStream::NativeHandle() const { return inner_->NativeHandle(); }
TcpStream* BaseWsStream::BaseTcpStream() { return BaseTcpStreamOf(*inner_); }
const TcpStream* BaseWsStream::BaseTcpStream() const {
    return BaseTcpStreamOf(std::as_const(*inner_));
}

net::awaitable<WsHandshakeResult> WsClientStream::Handshake(
    std::string_view host,
    std::string_view path,
    const transport::internet::HttpHeaders* headers) {
    // RFC 6455 §4.1: 密钥必须是随机生成的 16 字节 base64 编码
    uint8_t raw_key[16];
    if (RAND_bytes(raw_key, sizeof(raw_key)) != 1) [[unlikely]] {
        LOG_CONN_DEBUG(conn_id_, "WebSocket client failed to generate handshake nonce");
        co_return tl::unexpected(ErrorCode::INTERNAL);
    }
    std::array<uint8_t, 25> ws_key_buf{};
    EVP_EncodeBlock(ws_key_buf.data(), raw_key, sizeof(raw_key));
    OPENSSL_cleanse(raw_key, sizeof(raw_key));
    struct WsKeyCleanseGuard {
        std::array<uint8_t, 25>& buf;
        ~WsKeyCleanseGuard() noexcept { OPENSSL_cleanse(buf.data(), buf.size()); }
    } cleanse_ws_key{ws_key_buf};
    const std::string_view ws_key(reinterpret_cast<const char*>(ws_key_buf.data()), 24);
    const std::string_view req_path = EffectiveHttpPath(path);
    host = transport::internet::ResolveHttpUpgradeHost(host, {}, headers);
    auto head = co_await transport::internet::ExecuteHttp1UpgradeClientHandshake(
        *inner_, "WebSocket", conn_id_, host, req_path, headers, ws_key);
    if (!head) {
        co_return tl::unexpected(head.error());
    }

    const std::string_view accept = TrimAscii(
        transport::internet::ExtractHeaderValueCI(head->Text(), "Sec-WebSocket-Accept"));
    if (accept.empty()) {
        LOG_CONN_DEBUG(conn_id_, "WebSocket client missing Sec-WebSocket-Accept");
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const auto expected_accept = ws::EncodeWsAccept(ws_key);
    if (accept != std::string_view(expected_accept.data(), expected_accept.size())) {
        LOG_CONN_DEBUG(conn_id_, "WebSocket client received invalid Sec-WebSocket-Accept");
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (const auto read_ahead = head->ReadAhead(); !read_ahead.empty()) {
        SetPendingData(read_ahead.data(), read_ahead.size());
    }

    LOG_CONN_DEBUG(conn_id_, "WebSocket client handshake completed (host={} path={})",
                   transport::internet::PublicHttpTargetForLog(host),
                   transport::internet::PublicHttpTargetForLog(req_path));
    co_return WsHandshakeResult{};
}

