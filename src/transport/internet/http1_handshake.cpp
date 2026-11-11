#include "transport/internet/http1_handshake.hpp"
#include "common/binary_text_codec.hpp"

#include "common/allocator.hpp"
#include "common/const_buffer_span.hpp"
#include "infra/log.hpp"
#include "transport/internet/http_headers.hpp"
#include "common/unsafe.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "transport/internet/ws_stream.hpp"

#include <openssl/base64.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstring>
#include <limits>
#include <optional>

namespace transport::internet {
namespace {

using detail::EffectiveHttpPath;

class Http1BodyStream final : public AsyncStream {
public:
    Http1BodyStream(std::unique_ptr<AsyncStream> inner,
                    const Http1ReadFraming& read_framing,
                    bool write_chunked, Http1BodyReadOptions read_options)
        : inner_(std::move(inner))
        , read_budget_(read_options.max_body_bytes)
        , max_line_bytes_(read_options.max_line_bytes)
        , max_trailer_lines_(read_options.max_trailer_lines)
        , max_trailer_bytes_(read_options.max_trailer_bytes)
        , count_trailer_terminator_(read_options.count_trailer_terminator)
        , read_chunked_(std::holds_alternative<Http1BodyChunked>(read_framing))
        , write_chunked_(write_chunked)
        , reject_trailing_read_ahead_(read_options.reject_trailing_read_ahead) {
        if (const auto* length = std::get_if<Http1BodyContentLength>(&read_framing)) {
            if (length->bytes > read_budget_) FailBodyRead("HTTP body too large");
            content_remaining_ = length->bytes;
        }
    }

    ~Http1BodyStream() noexcept override {
        Close();
    }

    void SetPendingMultiBuffer(buf::MultiBuffer&& mb) {
        if (closed_ || read_closed_) {
            mb.clear();
            return;
        }
        if (content_remaining_) {
            const auto max_bytes = static_cast<size_t>(
                std::min<uint64_t>(mb.byte_size(), *content_remaining_));
            if (max_bytes < mb.byte_size()) {
                if (reject_trailing_read_ahead_)
                    FailBodyRead("trailing bytes after HTTP/1 Content-Length body");
                buf::MultiBuffer trimmed;
                if (!mb.MovePrefixTo(trimmed, max_bytes)) {
                    throw std::bad_alloc();
                }
                mb.clear();
                mb = std::move(trimmed);
            }
        }
        if (mb.byte_size() == 0) {
            mb.clear();
            return;
        }
        pending_.MoveTo(mb);
        pending_ = std::move(mb);
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        if (read_chunked_) {
            return ReadChunked(buffer);
        }
        if (content_remaining_) {
            return ReadContentLength(buffer);
        }
        return ReadRaw(buffer);
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (closed_ || write_closed_) {
            throw IoSystemError(io_error::operation_aborted, "http1 body write closed");
        }
        if (buffer.size() == 0) {
            co_return 0;
        }
        co_await WriteBuffers({&buffer, 1});
        co_return buffer.size();
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (closed_ || read_closed_) {
            co_return buf::MultiBuffer{};
        }
        if (content_remaining_) {
            co_return co_await ReadContentLengthMultiBuffer();
        }
        if (!read_chunked_) {
            if (pending_.byte_size() != 0) {
                ChargeBodyRead(pending_.byte_size());
                co_return std::move(pending_);
            }
            auto payload = co_await inner_->ReadMultiBuffer();
            ChargeBodyRead(payload.byte_size());
            co_return payload;
        }
        if (chunk_remaining_ == 0 && !co_await EnsureChunkPayload()) {
            co_return buf::MultiBuffer{};
        }
        if (pending_.byte_size() == 0) {
            pending_ = co_await inner_->ReadMultiBuffer();
        }
        if (pending_.byte_size() == 0) {
            if (closed_ || read_closed_) co_return buf::MultiBuffer{};
            FailBodyRead("truncated HTTP/1 chunk payload");
        }
        if (pending_.byte_size() <= chunk_remaining_) {
            ChargeBodyRead(pending_.byte_size());
            chunk_remaining_ -= pending_.byte_size();
            if (chunk_remaining_ == 0) chunk_terminator_pending_ = true;
            co_return std::move(pending_);
        }
        const size_t n = std::min(pending_.byte_size(), chunk_remaining_);
        buf::MultiBuffer payload;
        if (!pending_.MovePrefixTo(payload, n)) throw std::bad_alloc();
        ChargeBodyRead(n);
        chunk_remaining_ -= n;
        if (chunk_remaining_ == 0) chunk_terminator_pending_ = true;
        co_return payload;
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (closed_ || write_closed_) {
            mb.clear();
            throw IoSystemError(io_error::operation_aborted, "http1 body write closed");
        }
        return AsyncStream::WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        if (closed_ || write_closed_) {
            throw IoSystemError(io_error::operation_aborted, "http1 body write closed");
        }
        size_t len = 0;
        for (const auto& buffer : buffers) {
            if (buffer.size() > std::numeric_limits<size_t>::max() - len) {
                throw IoSystemError(io_error::message_size, "http1 chunk size overflow");
            }
            len += buffer.size();
        }
        if (len == 0) {
            co_return;
        }
        if (!write_chunked_) {
            try {
                co_await inner_->WriteBuffers(buffers);
            } catch (...) {
                CloseAbortive();
                throw;
            }
            co_return;
        }
        Http1ChunkPrefixBuffer prefix{};
        ConstBufferSpanBuilder<16> chunk_buffers;
        if (!AppendHttp1Chunk(chunk_buffers, prefix, buffers, len)) {
            throw IoSystemError(io_error::fault, "http1 chunk size encode failed");
        }
        try {
            co_await inner_->WriteBuffers(chunk_buffers.Span());
        } catch (...) {
            CloseAbortive();
            throw;
        }
    }

    void ShutdownRead() override {
        read_closed_ = true;
        pending_.clear();
        ResetLine();
        inner_->ShutdownRead();
    }

    void ShutdownWrite() override {
        if (closed_ || write_closed_) {
            return;
        }
        if (write_chunked_) {
            CloseAbortive();
            return;
        }
        write_closed_ = true;
        inner_->ShutdownWrite();
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (closed_ || write_closed_) {
            co_return;
        }
        write_closed_ = true;
        try {
            if (write_chunked_) {
                constexpr std::string_view kTerminator = "0\r\n\r\n";
                const net::const_buffer buffer{kTerminator.data(), kTerminator.size()};
                co_await inner_->WriteBuffers({&buffer, 1});
            }
            co_await inner_->AsyncShutdownWrite();
        } catch (...) {
            CloseAbortive();
            throw;
        }
    }

    void Cancel() noexcept override {
        NotifyCancellation();
        inner_->Cancel();
    }

    transport::CancellationSource& Cancellation() noexcept override {
        return inner_->Cancellation();
    }

    void Close() override {
        NotifyClosed();
        if (closed_) {
            return;
        }
        closed_ = true;
        pending_.clear();
        inner_->Close();
    }

    void CloseAbortive() override {
        NotifyClosed();
        if (closed_) {
            return;
        }
        closed_ = true;
        pending_.clear();
        inner_->CloseAbortive();
    }

    int NativeHandle() const override {
        return inner_->NativeHandle();
    }

    bool IsOpen() const override {
        return !closed_ && inner_->IsOpen();
    }

protected:
    TcpStream* BaseTcpStream() override {
        return BaseTcpStreamOf(*inner_);
    }

    const TcpStream* BaseTcpStream() const override {
        return BaseTcpStreamOf(*inner_);
    }

private:
    void ChargeTrailerLine(size_t bytes) {
        if (bytes > max_trailer_bytes_ - trailer_bytes_)
            FailBodyRead("HTTP/1 chunk trailers exceed limit");
        trailer_bytes_ += bytes;
    }

    net::awaitable<size_t> ReadRaw(net::mutable_buffer buffer) {
        if (closed_ || read_closed_) {
            co_return 0;
        }
        auto* out = static_cast<uint8_t*>(buffer.data());
        const size_t capacity = buffer.size();
        if (capacity == 0) {
            co_return 0;
        }
        if (pending_.byte_size() != 0) {
            const size_t n = pending_.ConsumePrefixTo(std::span<uint8_t>(out, capacity));
            pending_.ReleaseIfIdle();
            ChargeBodyRead(n);
            co_return n;
        }
        const auto n = co_await inner_->AsyncRead(buffer);
        ChargeBodyRead(n);
        co_return n;
    }

    // RFC 9112 6.3: a Content-Length body ends after exactly that many bytes;
    // whatever follows on the connection is not body. EOF before the end is a
    // truncated message, not a clean close.
    net::awaitable<size_t> ReadContentLength(net::mutable_buffer buffer) {
        if (closed_ || read_closed_ || *content_remaining_ == 0 || buffer.size() == 0) {
            if (content_remaining_ && *content_remaining_ == 0) {
                pending_.clear();
            }
            co_return 0;
        }
        const auto want = static_cast<size_t>(
            std::min<uint64_t>(buffer.size(), *content_remaining_));
        const size_t n = co_await ReadRaw(net::buffer(buffer.data(), want));
        if (n == 0) {
            if (closed_ || read_closed_) co_return 0;
            FailBodyRead("truncated HTTP/1 Content-Length body");
        }
        *content_remaining_ -= n;
        if (*content_remaining_ == 0) {
            pending_.clear();
        }
        co_return n;
    }

    net::awaitable<buf::MultiBuffer> ReadContentLengthMultiBuffer() {
        if (closed_ || read_closed_ || *content_remaining_ == 0) {
            if (content_remaining_ && *content_remaining_ == 0) {
                pending_.clear();
            }
            co_return buf::MultiBuffer{};
        }
        if (pending_.byte_size() == 0) {
            pending_ = co_await inner_->ReadMultiBuffer();
            if (pending_.byte_size() == 0) {
                if (closed_ || read_closed_) co_return buf::MultiBuffer{};
                FailBodyRead("truncated HTTP/1 Content-Length body");
            }
        }
        if (pending_.byte_size() <= *content_remaining_) {
            ChargeBodyRead(pending_.byte_size());
            *content_remaining_ -= pending_.byte_size();
            co_return std::move(pending_);
        }
        buf::MultiBuffer payload;
        if (reject_trailing_read_ahead_)
            FailBodyRead("trailing bytes after HTTP/1 Content-Length body");
        if (!pending_.MovePrefixTo(payload, static_cast<size_t>(*content_remaining_))) {
            throw std::bad_alloc();
        }
        ChargeBodyRead(payload.byte_size());
        *content_remaining_ = 0;
        pending_.clear();
        co_return payload;
    }

    // Parser state belongs to the stream, not a suspended read. A sniff read
    // can be cancelled after consuming part of a size line or chunk terminator.
    net::awaitable<bool> ReadLine() {
        const size_t wire_limit = max_line_bytes_ + 2;
        while (line_.size() < wire_limit) {
            if (pending_.byte_size() == 0) {
                pending_ = co_await inner_->ReadMultiBuffer();
                if (pending_.byte_size() == 0) co_return false;
            }
            const auto bytes = pending_.FrontSpan();
            const auto end = std::find(bytes.begin(), bytes.end(), uint8_t{'\n'});
            const bool finished = end != bytes.end();
            const size_t count = end == bytes.end() ? bytes.size()
                : static_cast<size_t>(end - bytes.begin()) + 1;
            if (count > wire_limit - line_.size()) co_return false;
            line_.append(reinterpret_cast<const char*>(bytes.data()), count);
            pending_.DropPrefixBytes(count);
            pending_.ReleaseIfIdle();
            if (finished) {
                if (line_.size() < 2 || line_[line_.size() - 2] != '\r')
                    co_return false;
                line_.resize(line_.size() - 2);
                if (line_.size() > max_line_bytes_) co_return false;
                co_return true;
            }
        }
        co_return false;
    }

    void ResetLine() noexcept {
        memory::String{}.swap(line_);
    }

    void ChargeBodyRead(size_t bytes) {
        if (bytes > read_budget_) FailBodyRead("HTTP body too large");
        read_budget_ -= bytes;
    }

    [[noreturn]] void FailBodyRead(const char* what) {
        read_closed_ = true;
        ResetLine();
        inner_->SetAbortiveClose(true);
        throw IoSystemError(io_error::invalid_argument, what);
    }

    net::awaitable<bool> EnsureChunkPayload() {
        if (closed_ || read_closed_) {
            co_return false;
        }
        while (chunk_remaining_ == 0) {
            if (chunk_terminator_pending_) {
                constexpr std::array<uint8_t, 2> terminator{'\r', '\n'};
                while (chunk_terminator_bytes_ != terminator.size()) {
                    if (pending_.byte_size() == 0) {
                        pending_ = co_await inner_->ReadMultiBuffer();
                        if (pending_.byte_size() == 0) {
                            if (closed_ || read_closed_) co_return false;
                            FailBodyRead("incomplete HTTP/1 chunk terminator");
                        }
                    }
                    const auto bytes = pending_.FrontSpan();
                    const size_t count = std::min(bytes.size(),
                        terminator.size() - chunk_terminator_bytes_);
                    for (size_t i = 0; i < count; ++i) {
                        if (bytes[i] != terminator[chunk_terminator_bytes_ + i])
                            FailBodyRead("invalid HTTP/1 chunk terminator");
                    }
                    pending_.DropPrefixBytes(count);
                    pending_.ReleaseIfIdle();
                    chunk_terminator_bytes_ += count;
                }
                chunk_terminator_bytes_ = 0;
                chunk_terminator_pending_ = false;
            }
            if (!co_await ReadLine()) {
                if (closed_ || read_closed_) co_return false;
                FailBodyRead("incomplete HTTP/1 chunk-size or trailer line");
            }
            if (reading_trailers_) {
                if (line_.empty()) {
                    if (count_trailer_terminator_) ChargeTrailerLine(2);
                    if (reject_trailing_read_ahead_ && pending_.byte_size() != 0)
                        FailBodyRead("trailing bytes after HTTP/1 chunked body");
                    ResetLine();
                    read_closed_ = true;
                    pending_.clear();
                    co_return false;
                }
                std::string_view trailer_name;
                std::string_view trailer_value;
                if (!SplitAndValidateHttpHeaderLine(
                        line_, trailer_name, trailer_value)) {
                    FailBodyRead("invalid HTTP/1 chunk trailer line");
                }
                const size_t line_bytes = line_.size() + 2;
                ResetLine();
                ++trailer_lines_;
                if (trailer_lines_ > max_trailer_lines_)
                    FailBodyRead("HTTP/1 chunk trailers exceed limit");
                ChargeTrailerLine(line_bytes);
                continue;
            }
            const auto chunk_size = ParseHttpChunkSize(line_);
            ResetLine();
            if (!chunk_size) FailBodyRead("invalid HTTP/1 chunk-size line");
            if (*chunk_size == 0) {
                reading_trailers_ = true;
                continue;
            }
            if (*chunk_size > read_budget_) FailBodyRead("HTTP body too large");
            chunk_remaining_ = *chunk_size;
        }
        co_return true;
    }

    net::awaitable<size_t> ReadChunked(net::mutable_buffer buffer) {
        if (closed_ || read_closed_) {
            co_return 0;
        }
        auto* out = static_cast<uint8_t*>(buffer.data());
        const size_t capacity = buffer.size();
        if (capacity == 0) {
            co_return 0;
        }

        if (chunk_remaining_ == 0 && !co_await EnsureChunkPayload()) co_return 0;
        const size_t want = std::min(capacity, chunk_remaining_);
        const size_t n = co_await ReadRaw(net::buffer(out, want));
        if (n == 0) {
            if (closed_ || read_closed_) co_return 0;
            FailBodyRead("truncated HTTP/1 chunk payload");
        }
        chunk_remaining_ -= n;
        if (chunk_remaining_ == 0) chunk_terminator_pending_ = true;
        co_return n;
    }

    std::unique_ptr<AsyncStream> inner_;
    buf::MultiBuffer pending_;
    size_t chunk_remaining_ = 0;
    // Unread Content-Length body bytes; empty unless the body is so framed.
    std::optional<uint64_t> content_remaining_;
    uint64_t read_budget_;
    size_t max_line_bytes_;
    size_t max_trailer_lines_;
    size_t max_trailer_bytes_;
    bool count_trailer_terminator_;
    memory::String line_;
    size_t chunk_terminator_bytes_ = 0;
    size_t trailer_lines_ = 0;
    size_t trailer_bytes_ = 0;
    bool chunk_terminator_pending_ = false;
    bool reading_trailers_ = false;
    bool read_chunked_ = false;
    bool write_chunked_ = false;
    bool reject_trailing_read_ahead_ = false;
    bool read_closed_ = false;
    bool write_closed_ = false;
    bool closed_ = false;
};

[[nodiscard]] bool IsReservedUpgradeHeader(std::string_view key) noexcept {
    return EqualsAsciiCI(key, "Host") ||
           EqualsAsciiCI(key, "Upgrade") ||
           EqualsAsciiCI(key, "Connection") ||
           EqualsAsciiCI(key, "Sec-WebSocket-Key") ||
           EqualsAsciiCI(key, "Sec-WebSocket-Version");
}

[[nodiscard]] bool HasWebSocketUpgradeHeaders(std::string_view head) {
    return EqualsAsciiCI(TrimAscii(ExtractHeaderValueCI(head, "Upgrade")), "websocket") &&
           HeaderListContainsTokenCI(head, "Connection", "upgrade");
}

void LogHeadReadFailure(std::string_view scope, uint64_t conn_id, ErrorCode error) {
    if (error == ErrorCode::SOCKET_EOF) {
        LOG_CONN_DEBUG(conn_id, "{} peer closed while reading HTTP/1 message head", scope);
    } else if (error == ErrorCode::PROTOCOL_DECODE_FAILED) {
        LOG_CONN_DEBUG(conn_id, "{} HTTP/1 message head too large or incomplete", scope);
    }
}

// HTTPUpgrade 与 WebSocket（RFC 6455 4.2.2）共用的 101 响应；WebSocket 在结束
// 空行之前追加 Sec-WebSocket-Accept。
constexpr std::string_view kSwitchingProtocolsResponse =
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "\r\n";
constexpr std::string_view kSwitchingProtocolsFields =
    kSwitchingProtocolsResponse.substr(0, kSwitchingProtocolsResponse.size() - 2);

// Reads the response head of a client handshake and requires `status_code`.
// Read-ahead belongs to the established byte stream.
net::awaitable<tl::expected<void, ErrorCode>> ReadClientResponse(
    AsyncStream& stream,
    std::string_view scope,
    uint64_t conn_id,
    std::string_view status_code) {
    auto head = co_await ReadHttp1MessageHead(stream);
    if (!head) {
        LogHeadReadFailure(scope, conn_id, head.error());
        co_return tl::unexpected(head.error());
    }
    const std::string_view status_line = ExtractStartLine(head->Text());
    if (!HasStatusCode(status_line, status_code)) {
        LOG_CONN_DEBUG(conn_id, "{} client request rejected", scope);
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    MoveReadAhead(stream, *head);
    co_return tl::expected<void, ErrorCode>{};
}

}  // namespace

net::awaitable<tl::expected<Http1ResponseHead, ErrorCode>>
ReadHttp1ResponseHead(AsyncStream& stream, Http1HeadReadLimits limits) {
    Http1ResponseHead response;
    size_t total_head_bytes = 0;
    for (;;) {
        auto remaining_limits = limits;
        if (limits.max_head_bytes != 0) {
            if (total_head_bytes >= limits.max_head_bytes)
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            remaining_limits.max_head_bytes -= total_head_bytes;
        }
        auto read = co_await ReadHttp1MessageHead(stream, response.head, {}, remaining_limits);
        if (!read) co_return tl::unexpected(read.error());
        total_head_bytes += response.head.header_end;
        if (limits.max_head_bytes == 0 && total_head_bytes > 256 * 1024)
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        const auto text = response.head.Text();
        const auto line = ExtractStartLine(text);
        const size_t space = line.find(' ');
        if (space == std::string_view::npos)
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        const auto version = line.substr(0, space);
        const auto rest = line.substr(space + 1);
        const auto token = rest.substr(0, rest.find(' '));
        int status = 0;
        const auto [end, ec] = std::from_chars(
            token.data(), token.data() + token.size(), status);
        if ((version != "HTTP/1.0" && version != "HTTP/1.1") ||
            token.size() != 3 || ec != std::errc{} ||
            end != token.data() + token.size() || status < 100 || status > 599 ||
            !IsValidHttpHeaderValue(rest))
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);

        std::optional<uint64_t> length;
        bool transfer_encoding = false;
        size_t coding_count = 0;
        bool only_chunked = true;
        size_t offset = line.size() + 2;
        while (offset < text.size() - 2) {
            const size_t end_line = text.find("\r\n", offset);
            if (end_line == std::string_view::npos)
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            std::string_view name, value;
            if (!SplitAndValidateHttpHeaderLine(
                    text.substr(offset, end_line - offset), name, value))
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            offset = end_line + 2;
            if (EqualsAsciiCI(name, "Content-Length")) {
                uint64_t parsed = 0;
                const auto [last, error] = std::from_chars(
                    value.data(), value.data() + value.size(), parsed);
                if (value.empty() || error != std::errc{} ||
                    last != value.data() + value.size() || (length && *length != parsed))
                    co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
                length = parsed;
            } else if (EqualsAsciiCI(name, "Transfer-Encoding")) {
                transfer_encoding = true;
                while (!value.empty()) {
                    const size_t comma = value.find(',');
                    const auto coding = TrimHttpOws(value.substr(0, comma));
                    value = comma == std::string_view::npos ? std::string_view{}
                        : value.substr(comma + 1);
                    if (coding.empty()) continue;
                    ++coding_count;
                    only_chunked &= EqualsAsciiCI(coding, "chunked");
                }
            }
        }
        if (status < 200) {
            if (status == 101)
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            continue;
        }
        response.status = status;
        response.header_bytes = total_head_bytes;
        // RFC 9112 6.3 rule 1: representation metadata on 304 is not a body.
        if (status == 204 || status == 304) {
            response.framing = Http1BodyContentLength{0};
        } else if (transfer_encoding) {
            if (version == "HTTP/1.0" || length || coding_count != 1 || !only_chunked)
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            response.framing = Http1BodyChunked{};
        } else if (length) {
            response.framing = Http1BodyContentLength{*length};
        }
        co_return response;
    }
}

net::awaitable<tl::expected<void, ErrorCode>> ReadHttp1MessageHead(
    AsyncStream& stream, Http1MessageHead& head, std::span<const uint8_t> initial,
    Http1HeadReadLimits limits) {
    if (!head.extended_storage.empty() && head.header_end != 0) {
        head.extended_storage.erase(0, head.header_end);
        head.size = head.extended_storage.size();
        head.header_end = 0;
        head.bytes = unsafe::ptr_cast<const uint8_t>(head.extended_storage.data());
        if (head.extended_storage.empty()) memory::String{}.swap(head.extended_storage);
    }
    if (head.storage) {
        if (head.header_end != 0) {
            const size_t remaining = head.size - head.header_end;
            if (remaining != 0) {
                uint8_t* data = head.storage->Tail().data();
                std::memmove(data, data + head.header_end, remaining);
                head.bytes = data;
                head.size = remaining;
                head.header_end = 0;
            } else if (initial.empty()) {
                head.storage.reset();
                head.bytes = nullptr;
                head.size = 0;
                head.header_end = 0;
            } else {
                head.bytes = head.storage->Tail().data();
                head.size = 0;
                head.header_end = 0;
            }
        } else if (head.size == 0 && initial.empty()) {
            head.storage.reset();
            head.bytes = nullptr;
        }
    }
    if (!head.storage) {
        if (initial.empty()) {
            buf::MultiBuffer mb = co_await stream.ReadMultiBuffer();
            buf::BufferGuard first;
            while (!mb.empty()) {
                first = mb.pop_front();
                if (first && !first->IsEmpty()) break;
                first.reset();
            }
            if (!first) {
                co_return tl::unexpected(ErrorCode::SOCKET_EOF);
            }
            first->CompactToFront();
            const size_t first_len = first->Len();
            first->Reset();
            head.storage = std::move(first);
            uint8_t* data = head.storage->Tail().data();
            const size_t capacity = head.storage->Available();
            head.bytes = data;
            head.header_end = 0;
            head.size = first_len;
            if (!mb.empty()) {
                head.size += mb.ConsumePrefixTo(
                    std::span<uint8_t>(data + head.size, capacity - head.size));
                stream.PrependReadMultiBuffer(std::move(mb));
            }
        } else {
            head.storage = buf::BufferGuard{buf::Buffer::New()};
            if (!head.storage) {
                co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
            }
            head.bytes = head.storage->Tail().data();
            head.header_end = 0;
            head.size = 0;
        }
    }
    uint8_t* data = head.storage->Tail().data();
    const size_t capacity = head.storage->Available();
    const size_t head_limit = limits.max_head_bytes ? limits.max_head_bytes : capacity;
    if (head.extended_storage.empty()) head.bytes = data;
    if (!initial.empty()) {
        if (initial.size() > head_limit || head.size > head_limit - initial.size())
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        if (head.extended_storage.empty() && initial.size() <= capacity - head.size) {
            std::memcpy(data + head.size, initial.data(), initial.size());
        } else {
            if (head.extended_storage.empty())
                head.extended_storage.assign(unsafe::ptr_cast<const char>(data), head.size);
            head.extended_storage.append(
                unsafe::ptr_cast<const char>(initial.data()), initial.size());
            head.bytes = unsafe::ptr_cast<const uint8_t>(head.extended_storage.data());
        }
        head.size += initial.size();
    }

    constexpr std::string_view kTerminator = "\r\n\r\n";
    size_t scanned = 0;
    size_t line_start = 0;
    size_t line_scanned = 0;
    for (;;) {
        const std::string_view received(unsafe::ptr_cast<const char>(head.bytes), head.size);
        const size_t from = scanned < kTerminator.size() - 1
            ? 0 : scanned - (kTerminator.size() - 1);
        const size_t end = received.find(kTerminator, from);
        const size_t checked_size = end == std::string_view::npos
            ? received.size() : end + kTerminator.size();
        if (checked_size > head_limit)
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        if (limits.max_line_bytes != 0) {
            while (line_start < checked_size) {
                const size_t scan_from = line_scanned > line_start ? line_scanned - 1 : line_start;
                const size_t crlf = received.find("\r\n", scan_from);
                if (crlf != std::string_view::npos && crlf + 2 <= checked_size) {
                    if (crlf - line_start > limits.max_line_bytes)
                        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
                    line_start = line_scanned = crlf + 2;
                } else {
                    const size_t partial = checked_size - line_start;
                    if (partial > limits.max_line_bytes &&
                        (partial - limits.max_line_bytes != 1 || received[checked_size - 1] != '\r'))
                        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
                    line_scanned = checked_size;
                    break;
                }
            }
        }
        if (end != std::string_view::npos) {
            head.header_end = checked_size;
            co_return tl::expected<void, ErrorCode>{};
        }
        scanned = head.size;
        if (head.size >= head_limit)
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        if (head.extended_storage.empty() && head.size < capacity) {
            const size_t want = std::min(capacity - head.size, head_limit - head.size);
            const size_t n = co_await stream.AsyncRead(net::buffer(data + head.size, want));
            if (n == 0) co_return tl::unexpected(ErrorCode::SOCKET_EOF);
            head.size += n;
        } else {
            if (head.extended_storage.empty())
                head.extended_storage.assign(unsafe::ptr_cast<const char>(data), head.size);
            const size_t want = std::min(capacity, head_limit - head.size);
            const size_t n = co_await stream.AsyncRead(net::buffer(data, want));
            if (n == 0) co_return tl::unexpected(ErrorCode::SOCKET_EOF);
            head.extended_storage.append(unsafe::ptr_cast<const char>(data), n);
            head.size += n;
            head.bytes = unsafe::ptr_cast<const uint8_t>(head.extended_storage.data());
        }
    }
}

net::awaitable<tl::expected<Http1MessageHead, ErrorCode>> ReadHttp1MessageHead(
    AsyncStream& stream, std::span<const uint8_t> initial, Http1HeadReadLimits limits) {
    Http1MessageHead head;
    if (auto res = co_await ReadHttp1MessageHead(stream, head, initial, limits); !res) {
        co_return tl::unexpected(res.error());
    }
    co_return std::move(head);
}

std::string_view ExtractStartLine(std::string_view head) {
    return head.substr(0, head.find("\r\n"));
}

Http1RequestLine ParseHttp1RequestLine(std::string_view request_line) {
    Http1RequestLine line;
    const size_t first_space = request_line.find(' ');
    if (first_space == std::string_view::npos) {
        return line;
    }
    line.method = request_line.substr(0, first_space);
    const size_t start = request_line.find_first_not_of(' ', first_space + 1);
    if (start == std::string_view::npos) {
        return line;
    }
    const size_t end = request_line.find(' ', start);
    if (end == std::string_view::npos) {
        return line;
    }
    line.target = request_line.substr(start, end - start);
    const size_t version_start = request_line.find_first_not_of(' ', end + 1);
    if (version_start != std::string_view::npos) {
        const size_t version_end = request_line.find(' ', version_start);
        line.version = request_line.substr(version_start, version_end - version_start);
    }
    return line;
}

namespace {

// Visits the value (leading whitespace removed) of each `name` field line in
// order until `visit` returns true; returns whether it did.
template <class Visit>
bool VisitHeaderValuesCI(std::string_view head, std::string_view name, Visit&& visit) {
    size_t line_start = 0;
    while (line_start < head.size()) {
        const size_t line_end = head.find("\r\n", line_start);
        if (line_end == std::string_view::npos || line_end == line_start) {
            break;
        }
        const std::string_view line = head.substr(line_start, line_end - line_start);
        if (const size_t colon = line.find(':');
            colon != std::string_view::npos &&
            EqualsAsciiCI(line.substr(0, colon), name)) {
            size_t value_start = colon + 1;
            while (value_start < line.size() &&
                   (line[value_start] == ' ' || line[value_start] == '\t')) {
                ++value_start;
            }
            if (visit(line.substr(value_start))) {
                return true;
            }
        }
        line_start = line_end + 2;
    }
    return false;
}

}  // namespace

std::string_view ExtractHeaderValueCI(std::string_view head, std::string_view name) {
    std::string_view first;
    (void)VisitHeaderValuesCI(head, name, [&first](std::string_view value) {
        first = value;
        return true;
    });
    return first;
}

size_t CountHeadersCI(std::string_view head, std::string_view name) {
    size_t count = 0;
    (void)VisitHeaderValuesCI(head, name, [&count](std::string_view) {
        ++count;
        return false;
    });
    return count;
}

bool HeaderContainsTokenCI(std::string_view value, std::string_view token) {
    while (!value.empty()) {
        const size_t comma = value.find(',');
        if (EqualsAsciiCI(TrimAscii(value.substr(0, comma)), token)) {
            return true;
        }
        if (comma == std::string_view::npos) {
            break;
        }
        value.remove_prefix(comma + 1);
    }
    return false;
}

bool HeaderListContainsTokenCI(std::string_view head,
                               std::string_view name,
                               std::string_view token) {
    return VisitHeaderValuesCI(head, name, [token](std::string_view value) {
        return HeaderContainsTokenCI(value, token);
    });
}

bool HasStatusCode(std::string_view status_line, std::string_view code) {
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
    const std::string_view rest = status_line.substr(pos);
    return rest.starts_with(code) &&
           (rest.size() == code.size() || rest[code.size()] == ' ');
}

void RecordExtractedRealIp(std::string_view head,
                           std::string_view header_name,
                           InboundTransportMetadata* metadata) {
    if (!metadata || header_name.empty()) {
        return;
    }
    std::string_view val = ExtractHeaderValueCI(head, header_name);
    val = TrimAscii(val.substr(0, val.find(',')));
    if (!val.empty()) {
        metadata->real_ip.assign(val);
    }
}

std::string_view PublicHttpTargetForLog(std::string_view value) {
    constexpr std::string_view invalid = "[invalid HTTP target]";
    value = TrimAscii(value);
    value = value.substr(0, value.find_first_of("?#"));
    if (value.empty()) return "-";
    for (unsigned char ch : value) {
        if (ch <= ' ' || ch >= 0x7f || ch == '\\') return invalid;
    }
    // A single leading slash is an origin path, not an authority. In
    // particular, '@' in that path is not URL userinfo.
    if (value.starts_with('/') && !value.starts_with("//")) return value;
    if (value == "*") return value;

    size_t authority_start = 0;
    const auto scheme_end = value.find("://");
    if (scheme_end != std::string_view::npos) {
        const auto scheme = value.substr(0, scheme_end);
        const auto alpha = [](char ch) {
            return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
        };
        if (scheme.empty() || !alpha(scheme.front())) return invalid;
        for (char ch : scheme) {
            if (!alpha(ch) && !(ch >= '0' && ch <= '9') &&
                ch != '+' && ch != '-' && ch != '.') return invalid;
        }
        authority_start = scheme_end + 3;
    } else if (value.starts_with("//")) {
        authority_start = 2;
    }
    const auto authority_end = value.find('/', authority_start);
    auto authority = value.substr(authority_start, authority_end - authority_start);
    if (authority.empty()) return invalid;
    const auto at = authority.find('@');
    if (at != std::string_view::npos) {
        authority.remove_prefix(at + 1);
        if (authority.find('@') != std::string_view::npos) return invalid;
    }
    if (authority.empty()) return invalid;
    // Validate host/port boundaries before exposing any authority. This is
    // deliberately log-only: malformed URL spellings retain no raw bytes.
    std::string_view port;
    if (authority.starts_with('[')) {
        const auto close = authority.find(']');
        if (close == std::string_view::npos || close == 1) return invalid;
        for (char ch : authority.substr(1, close - 1)) {
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                  (ch >= 'A' && ch <= 'F') || ch == ':' || ch == '.')) return invalid;
        }
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') return invalid;
            port = authority.substr(close + 2);
            if (port.empty()) return invalid;
        }
    } else {
        const auto colon = authority.find(':');
        const auto host = authority.substr(0, colon);
        if (host.empty()) return invalid;
        for (char ch : host) {
            if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                  (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' ||
                  ch == '_')) return invalid;
        }
        if (colon != std::string_view::npos) {
            port = authority.substr(colon + 1);
            if (port.empty()) return invalid;
        }
    }
    for (char ch : port) {
        if (ch < '0' || ch > '9') return invalid;
    }
    if (at != std::string_view::npos) value.remove_prefix(authority_start + at + 1);
    return value;
}

std::string_view PublicHttpMethodForLog(std::string_view value) {
    if (value.empty()) return "[invalid method]";
    for (char ch : value) {
        // RFC 9110 token grammar. Do not echo arbitrary request-line tokens.
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') ||
              std::string_view("!#$%&'*+-.^_`|~").find(ch) != std::string_view::npos)) {
            return "[invalid method]";
        }
    }
    return value;
}

std::string SanitizeHttpRequestLineForLog(const Http1RequestLine& line) {
    const auto method = PublicHttpMethodForLog(line.method);
    const auto target = PublicHttpTargetForLog(line.target);
    // RFC 9112 HTTP-version is HTTP-name "/" DIGIT "." DIGIT. Neither
    // invalid versions nor ignored trailing tokens are safe diagnostic text.
    const auto version = line.version.size() == 8 && line.version.starts_with("HTTP/") &&
                         line.version[5] >= '0' && line.version[5] <= '9' &&
                         line.version[6] == '.' &&
                         line.version[7] >= '0' && line.version[7] <= '9'
        ? line.version : std::string_view("[invalid version]");
    constexpr size_t kLimit = 160;
    const size_t public_size = method.size() + target.size() + version.size() + 2;
    std::string out;
    out.reserve(std::min(public_size, kLimit) + 3);
    const auto append = [&out](std::string_view part) {
        for (unsigned char ch : part) {
            if (out.size() == kLimit) break;
            if (ch == '\r' || ch == '\n' || ch == '\t') {
                out.push_back(' ');
            } else {
                out.push_back(std::isprint(ch) ? static_cast<char>(ch) : '?');
            }
        }
    };
    append(method);
    append(" ");
    append(target);
    append(" ");
    append(version);
    if (public_size > kLimit) out.append("...");
    return out;
}

void AppendRequestStart(memory::String& request,
                        std::string_view method,
                        std::string_view path,
                        std::string_view host) {
    request.append(method);
    request.push_back(' ');
    request.append(path);
    request.append(" HTTP/1.1\r\n");
    request.append("Host: ");
    request.append(host);
    request.append("\r\n");
}

void AppendHeaderLine(memory::String& out,
                      std::string_view name,
                      std::string_view value) {
    out.append(name);
    out.append(": ");
    out.append(value);
    out.append("\r\n");
}

net::awaitable<tl::expected<Http1Request, ErrorCode>> ReadHttp1Request(
    AsyncStream& stream,
    std::string_view scope,
    uint64_t conn_id,
    std::span<const uint8_t> initial) {
    Http1Request request;
    if (auto read = co_await ReadHttp1MessageHead(stream, request.head, initial); !read) {
        LogHeadReadFailure(scope, conn_id, read.error());
        co_return tl::unexpected(read.error());
    }
    const std::string_view text = request.head.Text();
    request.start_line = ExtractStartLine(text);
    request.line = ParseHttp1RequestLine(request.start_line);
    request.host = TrimAscii(ExtractHeaderValueCI(text, "Host"));
    LOG_CONN_TRACE(conn_id,
        "{} request line='{}' method='{}' path='{}' host='{}' bytes={}",
        scope,
        SanitizeHttpRequestLineForLog(request.line),
        PublicHttpMethodForLog(request.line.method),
        PublicHttpTargetForLog(request.line.target),
        PublicHttpTargetForLog(request.host),
        request.head.size);
    co_return std::move(request);
}

bool RejectHostMismatch(std::string_view scope,
                        uint64_t conn_id,
                        std::string_view expected_host,
                        std::string_view host) {
    if (expected_host.empty() || EqualsAsciiCI(host, expected_host)) {
        return false;
    }
    LOG_CONN_DEBUG(conn_id,
        "{} host mismatch expected='{}' actual='{}'",
        scope,
        PublicHttpTargetForLog(expected_host),
        PublicHttpTargetForLog(host));
    return true;
}

void MoveReadAhead(AsyncStream& stream, Http1MessageHead& head) {
    if (auto read_ahead = head.TakeReadAheadMultiBuffer(); !read_ahead.empty()) {
        stream.PrependReadMultiBuffer(std::move(read_ahead));
    }
}

net::awaitable<tl::expected<Http1MessageHead, ErrorCode>>
ExecuteHttp1UpgradeClientHandshake(
    AsyncStream& stream,
    std::string_view scope,
    uint64_t conn_id,
    std::string_view host,
    std::string_view path,
    const HttpHeaders* headers,
    std::string_view ws_key) {
    const std::string_view req_path = EffectiveHttpPath(path);
    size_t reserve_size =
        (ws_key.empty() ? 192 : 256) + req_path.size() + host.size() + ws_key.size();
    if (headers) {
        for (const auto& [key, value] : *headers) {
            if (!key.empty() && !IsReservedUpgradeHeader(key)) {
                reserve_size += key.size() + value.size() + 4;
            }
        }
    }

    memory::String request;
    request.reserve(reserve_size);
    AppendRequestStart(request, "GET", req_path, host);
    request.append("Upgrade: websocket\r\n");
    request.append("Connection: Upgrade\r\n");
    if (!ws_key.empty()) {
        AppendHeaderLine(request, "Sec-WebSocket-Key", ws_key);
        request.append("Sec-WebSocket-Version: 13\r\n");
    }
    if (headers) {
        for (const auto& [key, value] : *headers) {
            if (!key.empty() && !IsReservedUpgradeHeader(key)) {
                AppendHeaderLine(request, key, value);
            }
        }
    }
    request.append("\r\n");

    const bool write_ok = co_await WriteFullToStream(stream, request);
    memory::String{}.swap(request);
    if (!write_ok) {
        LOG_CONN_DEBUG(conn_id, "{} client failed to send upgrade request", scope);
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    auto head = co_await ReadHttp1MessageHead(stream);
    if (!head) {
        LogHeadReadFailure(scope, conn_id, head.error());
        co_return tl::unexpected(head.error());
    }
    const std::string_view response = head->Text();
    const std::string_view status_line = ExtractStartLine(response);
    if (!HasStatusCode(status_line, "101")) {
        LOG_CONN_DEBUG(conn_id, "{} client upgrade rejected", scope);
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (!HasWebSocketUpgradeHeaders(response)) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    co_return std::move(*head);
}

net::awaitable<bool> WriteFullToStream(AsyncStream& stream, std::string_view bytes) {
    if (bytes.empty()) {
        co_return true;
    }
    const net::const_buffer buffer{bytes.data(), bytes.size()};
    try {
        co_await stream.WriteBuffers(std::span<const net::const_buffer>{&buffer, 1});
    } catch (...) {
        co_return false;
    }
    co_return true;
}

net::awaitable<bool> ReadFullFromStream(AsyncStream& stream, std::span<uint8_t> out) {
    size_t done = 0;
    while (done < out.size()) {
        const size_t n = co_await stream.AsyncRead(
            net::buffer(out.data() + done, out.size() - done));
        if (n == 0) {
            co_return false;
        }
        done += n;
    }
    co_return true;
}

std::unique_ptr<AsyncStream> MakeHttp1BodyStream(
    std::unique_ptr<AsyncStream> inner,
    Http1ReadFraming read_framing,
    bool write_chunked,
    buf::MultiBuffer&& read_ahead,
    Http1BodyReadOptions read_options) {
    auto body = std::make_unique<Http1BodyStream>(
        std::move(inner), read_framing, write_chunked, read_options);
    body->SetPendingMultiBuffer(std::move(read_ahead));
    return body;
}

namespace {

void LogPathMismatch(std::string_view scope,
                     uint64_t conn_id,
                     std::string_view configured_path,
                     std::string_view target) {
    LOG_CONN_DEBUG(conn_id,
        "{} path mismatch expected='{}' actual='{}'",
        scope,
        PublicHttpTargetForLog(EffectiveHttpPath(configured_path)),
        PublicHttpTargetForLog(target));
}

}  // namespace

net::awaitable<TransportBuildResult> DoHttp1ServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    uint64_t conn_id,
    InboundTransportMetadata* transport_metadata,
    std::span<const uint8_t> initial) {
    constexpr std::string_view kScope = "HTTP server";
    auto request = co_await ReadHttp1Request(*stream, kScope, conn_id, initial);
    if (!request) {
        co_return tl::unexpected(request.error());
    }
    const Http1RequestLine& line = request->line;
    if (line.method.empty() || !detail::PathPrefixMatchesSegment(cfg.path, line.target)) {
        LogPathMismatch(kScope, conn_id, cfg.path, line.target);
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (!cfg.method.empty() && !EqualsAsciiCI(line.method, cfg.method)) {
        LOG_CONN_DEBUG(conn_id,
            "HTTP server method mismatch expected='{}' actual='{}'",
            PublicHttpMethodForLog(cfg.method),
            PublicHttpMethodForLog(line.method));
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (RejectHostMismatch(kScope, conn_id,
                           ResolveConfiguredHttpHost(cfg.host, &cfg.headers),
                           request->host)) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    RecordExtractedRealIp(request->head.Text(), cfg.real_ip_header, transport_metadata);

    memory::String response;
    response.reserve(96 + cfg.headers.size() * 32);
    response.append("HTTP/1.1 200 OK\r\n");
    response.append("Cache-Control: no-store\r\n");
    for (const auto& [key, value] : cfg.headers) {
        if (!key.empty()) {
            AppendHeaderLine(response, key, value);
        }
    }
    response.append("\r\n");

    if (!co_await WriteFullToStream(*stream, response)) {
        LOG_CONN_DEBUG(conn_id, "HTTP server failed to send 200 response");
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    MoveReadAhead(*stream, request->head);
    LOG_CONN_DEBUG(conn_id, "HTTP server handshake completed (path={})",
                   PublicHttpTargetForLog(EffectiveHttpPath(cfg.path)));
    co_return std::move(stream);
}

net::awaitable<TransportBuildResult> DoHttp1ClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    std::string_view host,
    uint64_t conn_id) {
    const std::string_view req_path = EffectiveHttpPath(cfg.path);
    const std::string_view method = cfg.method.empty()
        ? std::string_view("PUT") : std::string_view(cfg.method);
    size_t reserve_size = 192 + method.size() + req_path.size() + host.size();
    for (const auto& [key, value] : cfg.headers) {
        if (!key.empty() && !EqualsAsciiCI(key, "Host")) {
            reserve_size += key.size() + value.size() + 4;
        }
    }

    memory::String request;
    request.reserve(reserve_size);
    AppendRequestStart(request, method, req_path, host);
    for (const auto& [key, value] : cfg.headers) {
        if (!key.empty() && !EqualsAsciiCI(key, "Host")) {
            AppendHeaderLine(request, key, value);
        }
    }
    request.append("\r\n");

    if (!co_await WriteFullToStream(*stream, request)) {
        LOG_CONN_DEBUG(conn_id, "HTTP client failed to send request");
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }
    memory::String{}.swap(request);
    if (auto response = co_await ReadClientResponse(*stream, "HTTP", conn_id, "200");
        !response) {
        co_return tl::unexpected(response.error());
    }
    LOG_CONN_DEBUG(conn_id, "HTTP client handshake completed (host={} path={})",
                   PublicHttpTargetForLog(host), PublicHttpTargetForLog(req_path));
    co_return std::move(stream);
}

net::awaitable<TransportBuildResult> DoHttpUpgradeServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpUpgradeConfig& cfg,
    uint64_t conn_id,
    InboundTransportMetadata* transport_metadata) {
    constexpr std::string_view kScope = "HTTPUpgrade server";
    auto request = co_await ReadHttp1Request(*stream, kScope, conn_id);
    if (!request) {
        co_return tl::unexpected(request.error());
    }
    if (!request->start_line.starts_with("GET ") ||
        !detail::PathMatchesExactly(cfg.path, request->line.target)) {
        LogPathMismatch(kScope, conn_id, cfg.path, request->line.target);
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (!HasWebSocketUpgradeHeaders(request->head.Text())) {
        LOG_CONN_DEBUG(conn_id, "HTTPUpgrade server received invalid upgrade headers");
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (RejectHostMismatch(kScope, conn_id,
                           ResolveConfiguredHttpHost(cfg.host, &cfg.headers),
                           request->host)) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    RecordExtractedRealIp(request->head.Text(), cfg.real_ip_header, transport_metadata);

    if (!co_await WriteFullToStream(*stream, kSwitchingProtocolsResponse)) {
        LOG_CONN_DEBUG(conn_id, "HTTPUpgrade server failed to send 101 response");
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    MoveReadAhead(*stream, request->head);
    LOG_CONN_DEBUG(conn_id, "HTTPUpgrade server handshake completed (path={})",
                   PublicHttpTargetForLog(EffectiveHttpPath(cfg.path)));
    co_return std::move(stream);
}

net::awaitable<TransportBuildResult> DoHttpUpgradeClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpUpgradeConfig& cfg,
    std::string_view host,
    uint64_t conn_id) {
    const std::string_view req_path = EffectiveHttpPath(cfg.path);
    const std::string_view effective_host =
        ResolveConfiguredHttpHost(cfg.host, &cfg.headers, host);
    auto head = co_await ExecuteHttp1UpgradeClientHandshake(
        *stream, "HTTPUpgrade", conn_id, effective_host, req_path, &cfg.headers);
    if (!head) {
        co_return tl::unexpected(head.error());
    }
    MoveReadAhead(*stream, *head);
    LOG_CONN_DEBUG(conn_id, "HTTPUpgrade client handshake completed (host={} path={})",
                   PublicHttpTargetForLog(effective_host), PublicHttpTargetForLog(req_path));
    co_return std::move(stream);
}

// 路径语义与 HTTPUpgrade 及 Xray websocket hub 一致：忽略 query 后与配置路径
// （未配置即 "/"）严格相等，根路径不放行其他路径。
net::awaitable<TransportBuildResult> DoWsServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const WsConfig& ws_cfg,
    uint64_t conn_id,
    InboundTransportMetadata* transport_metadata) {
    constexpr std::string_view kScope = "WebSocket server";
    auto request = co_await ReadHttp1Request(*stream, kScope, conn_id);
    if (!request) {
        co_return tl::unexpected(request.error());
    }
    const std::string_view text = request->head.Text();
    if (!HasWebSocketUpgradeHeaders(text)) {
        LOG_CONN_DEBUG(conn_id, "WebSocket server missing 'Upgrade: websocket' header");
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (!request->start_line.starts_with("GET ") ||
        !request->start_line.ends_with(" HTTP/1.1") ||
        TrimAscii(ExtractHeaderValueCI(text, "Sec-WebSocket-Version")) != "13") {
        LOG_CONN_DEBUG(conn_id, "WebSocket server received invalid upgrade request");
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (!detail::PathMatchesExactly(ws_cfg.path, request->line.target)) {
        LogPathMismatch(kScope, conn_id, ws_cfg.path, request->line.target);
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    // RFC 6455 4.2.1: the key is a base64-encoded 16-byte nonce.
    const std::string_view ws_key = TrimAscii(ExtractHeaderValueCI(text, "Sec-WebSocket-Key"));
    std::array<uint8_t, 18> decoded_key;
    if (ws_key.size() != 24 || ws_key[22] != '=' || ws_key[23] != '=' ||
        EVP_DecodeBlock(decoded_key.data(),
            reinterpret_cast<const uint8_t*>(ws_key.data()), 24) != 18) {
        LOG_CONN_DEBUG(conn_id, "WebSocket server received invalid Sec-WebSocket-Key header");
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    RecordExtractedRealIp(text, ws_cfg.real_ip_header, transport_metadata);

    const auto ws_accept = ws::EncodeWsAccept(ws_key);
    memory::String response;
    response.reserve(kSwitchingProtocolsResponse.size() + 32 + ws_accept.size());
    response.append(kSwitchingProtocolsFields);
    response.append("Sec-WebSocket-Accept: ");
    response.append(ws_accept.data(), ws_accept.size());
    response.append("\r\n\r\n");
    if (!co_await WriteFullToStream(*stream, response)) {
        LOG_CONN_DEBUG(conn_id, "WebSocket server failed to send 101 response");
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    // Bytes read past the request head belong to the WebSocket frame stream.
    auto ws = std::make_unique<BaseWsStream>(std::move(stream), false);
    const size_t pending_bytes = request->head.ReadAhead().size();
    if (auto read_ahead = request->head.TakeReadAheadMultiBuffer(); !read_ahead.empty()) {
        ws->SetPendingMultiBuffer(std::move(read_ahead));
    }
    LOG_CONN_DEBUG(conn_id, "WebSocket server handshake completed (path={} pending={})",
                   PublicHttpTargetForLog(EffectiveHttpPath(ws_cfg.path)),
                   pending_bytes);
    co_return std::unique_ptr<AsyncStream>(std::move(ws));
}

}  // namespace transport::internet
