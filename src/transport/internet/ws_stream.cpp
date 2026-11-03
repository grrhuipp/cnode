#include "acppnode/transport/internet/ws_stream.hpp"
#include "acppnode/common/base64.hpp"
#include "acppnode/common/unsafe.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/infra/log.hpp"

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <algorithm>
#include <limits>
#include <cctype>
#include <string_view>
#include <stdexcept>

namespace acpp {

namespace ws {

std::string ComputeWsAccept(std::string_view ws_key) {
    constexpr std::string_view kWsGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::array<char, 256> inline_buf;
    uint8_t sha1[20];
    if (ws_key.size() + kWsGuid.size() <= inline_buf.size()) {
        std::memcpy(inline_buf.data(), ws_key.data(), ws_key.size());
        std::memcpy(inline_buf.data() + ws_key.size(), kWsGuid.data(), kWsGuid.size());
        SHA1(unsafe::ptr_cast<const uint8_t>(inline_buf.data()),
             ws_key.size() + kWsGuid.size(),
             sha1);
    } else {
        std::string accept_src;
        accept_src.reserve(ws_key.size() + kWsGuid.size());
        accept_src.append(ws_key);
        accept_src.append(kWsGuid);
        SHA1(unsafe::ptr_cast<const uint8_t>(accept_src.data()), accept_src.size(), sha1);
    }
    return Base64Encode(sha1, sizeof(sha1));
}

}  // namespace ws

namespace {
[[nodiscard]] char LowerAsciiChar(char ch) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
}

[[nodiscard]] bool EqualsAsciiCI(std::string_view lhs, std::string_view rhs) {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (LowerAsciiChar(lhs[i]) != LowerAsciiChar(rhs[i])) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::string_view TrimAscii(std::string_view value) {
    while (!value.empty() &&
           (value.front() == ' ' || value.front() == '\t' ||
            value.front() == '\r' || value.front() == '\n')) {
        value.remove_prefix(1);
    }
    while (!value.empty() &&
           (value.back() == ' ' || value.back() == '\t' ||
            value.back() == '\r' || value.back() == '\n')) {
        value.remove_suffix(1);
    }
    return value;
}

[[nodiscard]] std::string_view ExtractHttpHeaderCI(
    std::string_view response,
    std::string_view name) {
    size_t line_start = 0;
    while (line_start < response.size()) {
        const size_t line_end = response.find("\r\n", line_start);
        if (line_end == std::string_view::npos) {
            break;
        }
        if (line_end == line_start) {
            break;
        }

        const std::string_view line = response.substr(line_start, line_end - line_start);
        if (const size_t colon = line.find(':'); colon != std::string_view::npos) {
            if (EqualsAsciiCI(line.substr(0, colon), name)) {
                size_t value_start = colon + 1;
                while (value_start < line.size() &&
                       (line[value_start] == ' ' || line[value_start] == '\t')) {
                    ++value_start;
                }
                return TrimAscii(line.substr(value_start));
            }
        }
        line_start = line_end + 2;
    }
    return {};
}

[[nodiscard]] std::string_view ExtractStatusLine(std::string_view response) {
    const size_t crlf = response.find("\r\n");
    return crlf == std::string_view::npos ? response : response.substr(0, crlf);
}

[[nodiscard]] bool IsSwitchingProtocolsStatus(std::string_view status_line) {
    if (!status_line.starts_with("HTTP/")) {
        return false;
    }
    size_t pos = status_line.find(' ');
    if (pos == std::string_view::npos) {
        return false;
    }
    while (pos < status_line.size() && status_line[pos] == ' ') {
        ++pos;
    }
    if (pos + 3 > status_line.size() ||
        status_line[pos] != '1' ||
        status_line[pos + 1] != '0' ||
        status_line[pos + 2] != '1') {
        return false;
    }
    return pos + 3 == status_line.size() || status_line[pos + 3] == ' ';
}

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

void AddPayloadSize(size_t& total, size_t additional) {
    // RFC 6455 §5.2: the most significant bit of a 64-bit length is zero.
    constexpr uint64_t maximum = std::numeric_limits<uint64_t>::max() >> 1;
    if (additional > maximum - total) throw std::length_error("WebSocket payload too large");
    total += additional;
}

}  // namespace

BaseWsStream::BaseWsStream(
    std::unique_ptr<AsyncStream> inner, uint64_t conn_id, bool is_client)
    : inner_(std::move(inner)), conn_id_(conn_id), is_client_(is_client) {}

BaseWsStream::~BaseWsStream() noexcept {
    Close();
}

void BaseWsStream::SetPendingData(const uint8_t* data, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) throw std::bad_alloc();
        const size_t n = std::min(len - offset, static_cast<size_t>(buffer->Available()));
        std::memcpy(buffer->Tail().data(), data + offset, n);
        buffer->Produce(static_cast<uint32_t>(n));
        pending_data_.push_back(std::move(buffer));
        offset += n;
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

net::awaitable<size_t> BaseWsStream::ReadSome(uint8_t* data, size_t size) {
    if (closed_ || read_closed_) co_return 0;
    const size_t pending = pending_data_.ConsumePrefixTo(std::span<uint8_t>(data, size));
    if (pending != 0) co_return pending;
    size_t n = 0;
    try {
        n = co_await inner_->AsyncRead(net::buffer(data, size));
    } catch (const IoSystemError& error) {
        if (error.code() != io_error::eof) throw;
        if (!closed_ && !read_closed_) ProtocolFailure("WebSocket truncated without Close");
        co_return 0;
    }
    if (n == 0 && !closed_ && !read_closed_)
        ProtocolFailure("WebSocket truncated without Close");
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
                    co_await WriteControlFrame(ws::Opcode::CLOSE, payload);
                    peer_closed_cleanly_ = true;
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
    if (closing) close_requested_ = true;
    const auto state = co_await net::this_coro::cancellation_state;
    if (closed_ || state.cancelled() != net::cancellation_type::none)
        throw IoSystemError(io_error::operation_aborted);
    WriteGate::Lease lease = write_gate_.TryAcquire();
    if (!lease) lease = co_await AcquireWrite(state.slot());
    if (write_closed_ || (!closing && close_requested_)) co_return;
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
        LOG_NET_DEBUG("[conn={}] WS client: RAND_bytes failed", conn_id_);
        co_return tl::unexpected(ErrorCode::INTERNAL);
    }
    std::string ws_key = Base64Encode(raw_key, sizeof(raw_key));

    const std::string_view req_path = path.empty() ? "/" : std::string_view(path);
    auto is_host_header = [](std::string_view key) {
        if (key.size() != 4) return false;
        return std::tolower(static_cast<unsigned char>(key[0])) == 'h' &&
               std::tolower(static_cast<unsigned char>(key[1])) == 'o' &&
               std::tolower(static_cast<unsigned char>(key[2])) == 's' &&
               std::tolower(static_cast<unsigned char>(key[3])) == 't';
    };

    size_t reserve_size = 256 + req_path.size() + host.size() + ws_key.size();
    if (headers) {
        for (const auto& [k, v] : *headers) {
            if (!is_host_header(k)) {
                reserve_size += k.size() + v.size() + 4; // ": " + "\r\n"
            }
        }
    }

    std::array<std::byte, 512> arena_buf{};
    memory::request_memory arena(memory::ThreadPool(), arena_buf);
    memory::ThreadLocalString request(arena.resource());
    request.reserve(reserve_size);
    request.append("GET ");
    request.append(req_path);
    request.append(" HTTP/1.1\r\n");
    request.append("Host: ");
    request.append(host);
    request.append("\r\n");
    request.append("Upgrade: websocket\r\n");
    request.append("Connection: Upgrade\r\n");
    request.append("Sec-WebSocket-Key: ");
    request.append(ws_key);
    request.append("\r\n");
    request.append("Sec-WebSocket-Version: 13\r\n");
    if (headers) {
        for (const auto& [k, v] : *headers) {
            if (is_host_header(k)) continue;
            request.append(k);
            request.append(": ");
            request.append(v);
            request.append("\r\n");
        }
    }
    request.append("\r\n");

    const net::const_buffer request_buffer(request.data(), request.size());
    co_await inner_->WriteBuffers({&request_buffer, 1});

    buf::BufferGuard response_buf{buf::Buffer::New()};
    if (!response_buf) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    char* response_data = unsafe::ptr_cast<char>(response_buf->Tail().data());
    const size_t response_capacity = response_buf->Available();
    size_t response_len = 0;
    bool found_end = false;
    size_t header_end = 0;

    while (!found_end && response_len < response_capacity) {
        size_t n = co_await inner_->AsyncRead(
            net::buffer(response_data + response_len, response_capacity - response_len));
        if (n == 0) {
            LOG_NET_DEBUG("[conn={}] WS client: peer closed during upgrade response read", conn_id_);
            co_return tl::unexpected(ErrorCode::SOCKET_EOF);
        }

        response_len += n;
        std::string_view response(response_data, response_len);
        size_t pos = response.find("\r\n\r\n");
        if (pos != std::string_view::npos) {
            found_end = true;
            header_end = pos + 4;
        }
    }

    if (!found_end) {
        LOG_NET_DEBUG("[conn={}] WS client: incomplete upgrade response", conn_id_);
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const std::string_view response(response_data, response_len);
    const std::string_view first_line = ExtractStatusLine(response);
    if (!IsSwitchingProtocolsStatus(first_line)) {
        LOG_NET_DEBUG("[conn={}] WS client: server rejected upgrade: {}",
                  conn_id_,
                  first_line);
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const std::string_view accept = ExtractHttpHeaderCI(response, "Sec-WebSocket-Accept");
    if (accept.empty()) {
        LOG_NET_DEBUG("[conn={}] WS client: missing Sec-WebSocket-Accept", conn_id_);
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const std::string expected_accept = ws::ComputeWsAccept(ws_key);
    if (accept != expected_accept) {
        LOG_NET_DEBUG("[conn={}] WS client: invalid Sec-WebSocket-Accept", conn_id_);
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (header_end < response_len) {
        SetPendingData(unsafe::ptr_cast<const uint8_t>(response_data + header_end),
                       response_len - header_end);
    }

    LOG_NET_DEBUG("[conn={}] WS client: handshake ok (host={} path={})", conn_id_, host, path);
    co_return WsHandshakeResult{};
}

}  // namespace acpp
