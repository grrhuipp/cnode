#include "http1_handshake.hpp"
#include "common/binary_text_codec.hpp"

#include "http_path_match.hpp"
#include "common/allocator.hpp"
#include "common/buffer_util.hpp"
#include "infra/log.hpp"
#include "transport/internet/http_headers.hpp"
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
                    bool write_chunked)
        : inner_(std::move(inner))
        , read_chunked_(std::holds_alternative<Http1BodyChunked>(read_framing))
        , write_chunked_(write_chunked) {
        if (const auto* length = std::get_if<Http1BodyContentLength>(&read_framing)) {
            content_remaining_ = length->bytes;
        }
    }

    ~Http1BodyStream() noexcept override {
        Close();
    }

    void SetPendingData(std::span<const uint8_t> data) {
        if (content_remaining_) {
            data = data.first(
                static_cast<size_t>(std::min<uint64_t>(data.size(), *content_remaining_)));
        }
        if (data.empty() || closed_ || read_closed_) {
            return;
        }
        if (!buf::AppendSpanToMultiBuffer(data, pending_)) {
            throw std::bad_alloc();
        }
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        if (read_chunked_) {
            co_return co_await ReadChunked(buffer);
        }
        if (content_remaining_) {
            co_return co_await ReadContentLength(buffer);
        }
        co_return co_await ReadRaw(buffer);
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
                co_return std::move(pending_);
            }
            co_return co_await inner_->ReadMultiBuffer();
        }
        if (!co_await EnsureChunkPayload()) {
            co_return buf::MultiBuffer{};
        }
        if (pending_.byte_size() == 0) {
            pending_ = co_await inner_->ReadMultiBuffer();
        }
        if (pending_.byte_size() == 0) {
            if (closed_ || read_closed_) co_return buf::MultiBuffer{};
            FailBodyRead("truncated HTTP/1 chunk payload");
        }
        const size_t n = std::min(pending_.byte_size(), chunk_remaining_);
        buf::MultiBuffer payload;
        if (!pending_.MovePrefixTo(payload, n)) throw std::bad_alloc();
        chunk_remaining_ -= n;
        if (chunk_remaining_ == 0) chunk_terminator_pending_ = true;
        co_return payload;
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (closed_ || write_closed_) {
            mb.clear();
            throw IoSystemError(io_error::operation_aborted, "http1 body write closed");
        }
        co_await AsyncStream::WriteMultiBuffer(std::move(mb));
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
        std::array<char, sizeof(size_t) * 2 + 2> prefix{};
        auto [ptr, ec] = std::to_chars(
            prefix.data(),
            prefix.data() + prefix.size() - 2,
            len,
            16);
        if (ec != std::errc{}) {
            throw IoSystemError(io_error::fault, "http1 chunk size encode failed");
        }
        *ptr++ = '\r';
        *ptr++ = '\n';

        constexpr std::array<char, 2> kChunkTail{'\r', '\n'};
        ConstBufferSpanBuilder<16> chunk_buffers;
        chunk_buffers.Append(
            net::buffer(prefix.data(), static_cast<size_t>(ptr - prefix.data())));
        chunk_buffers.AppendBuffers(buffers);
        chunk_buffers.Append(net::buffer(kChunkTail.data(), kChunkTail.size()));
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
    static constexpr size_t kMaxChunkLine = 8192;
    static constexpr size_t kMaxTrailerLines = 128;
    static constexpr size_t kMaxTrailerBytes = 64 * 1024;

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
            co_return n;
        }
        co_return co_await inner_->AsyncRead(buffer);
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
            *content_remaining_ -= pending_.byte_size();
            co_return std::move(pending_);
        }
        buf::MultiBuffer payload;
        if (!pending_.MovePrefixTo(payload, static_cast<size_t>(*content_remaining_))) {
            throw std::bad_alloc();
        }
        *content_remaining_ = 0;
        pending_.clear();
        co_return payload;
    }

    // Parser state belongs to the stream, not a suspended read. A sniff read
    // can be cancelled after consuming part of a size line or chunk terminator.
    net::awaitable<bool> ReadLine() {
        while (line_.size() < kMaxChunkLine) {
            if (pending_.byte_size() == 0) {
                pending_ = co_await inner_->ReadMultiBuffer();
                if (pending_.byte_size() == 0) co_return false;
            }
            const auto bytes = pending_.FrontSpan();
            const auto end = std::find(bytes.begin(), bytes.end(), uint8_t{'\n'});
            const bool finished = end != bytes.end();
            const size_t count = end == bytes.end() ? bytes.size()
                : static_cast<size_t>(end - bytes.begin()) + 1;
            if (count > kMaxChunkLine - line_.size()) co_return false;
            line_.append(reinterpret_cast<const char*>(bytes.data()), count);
            pending_.DropPrefixBytes(count);
            pending_.ReleaseIfIdle();
            if (finished) {
                if (line_.size() < 2 || line_[line_.size() - 2] != '\r')
                    co_return false;
                line_.resize(line_.size() - 2);
                co_return true;
            }
        }
        co_return false;
    }

    void ResetLine() noexcept {
        memory::ThreadLocalString{}.swap(line_);
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
                    ResetLine();
                    read_closed_ = true;
                    pending_.clear();
                    co_return false;
                }
                const size_t colon = line_.find(':');
                if (colon == std::string::npos || colon == 0 ||
                    !IsValidHttpHeaderName(std::string_view(line_).substr(0, colon)) ||
                    !IsValidHttpHeaderValue(
                        TrimHttpOws(std::string_view(line_).substr(colon + 1)))) {
                    FailBodyRead("invalid HTTP/1 chunk trailer line");
                }
                const size_t line_bytes = line_.size() + 2;
                ResetLine();
                ++trailer_lines_;
                if (trailer_lines_ > kMaxTrailerLines ||
                    line_bytes > kMaxTrailerBytes - trailer_bytes_) {
                    FailBodyRead("HTTP/1 chunk trailers exceed limit");
                }
                trailer_bytes_ += line_bytes;
                continue;
            }
            const auto chunk_size = ParseHttpChunkSize(line_);
            ResetLine();
            if (!chunk_size) FailBodyRead("invalid HTTP/1 chunk-size line");
            if (*chunk_size == 0) {
                reading_trailers_ = true;
                continue;
            }
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

        if (!co_await EnsureChunkPayload()) co_return 0;
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
    memory::ThreadLocalString line_;
    size_t chunk_terminator_bytes_ = 0;
    size_t trailer_lines_ = 0;
    size_t trailer_bytes_ = 0;
    bool chunk_terminator_pending_ = false;
    bool reading_trailers_ = false;
    bool read_chunked_ = false;
    bool write_chunked_ = false;
    bool read_closed_ = false;
    bool write_closed_ = false;
    bool closed_ = false;
};

[[nodiscard]] bool IsHostHeader(std::string_view key) {
    return EqualsAsciiCI(key, "Host");
}

[[nodiscard]] std::string_view ConfiguredHostHeader(const HttpHeaders& headers) noexcept {
    const std::string* host = FindHttpHeader(headers, "Host");
    return host ? std::string_view(*host) : std::string_view{};
}

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

// Request line, CRLF and fields; transport-specific framing headers are added
// by the caller before the configured fields.
void AppendRequestStart(memory::ThreadLocalString& request,
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

void AppendHeaderLine(memory::ThreadLocalString& out,
                      std::string_view name,
                      std::string_view value) {
    out.append(name);
    out.append(": ");
    out.append(value);
    out.append("\r\n");
}

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
    // HTTP handshakes run directly on TCP or TLS. Read-ahead returns to that
    // exact byte layer: TLS plaintext never enters the TCP ciphertext queue.
    if (const auto read_ahead = head->ReadAhead(); !read_ahead.empty()) {
        stream.PrependReadData(read_ahead);
    }
    co_return tl::expected<void, ErrorCode>{};
}

}  // namespace

net::awaitable<tl::expected<void, ErrorCode>> ReadHttp1MessageHead(
    AsyncStream& stream, Http1MessageHead& head, std::span<const uint8_t> initial) {
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
                for (size_t i = mb.size(); i > 0; --i) {
                    if (const buf::Buffer* b = *(mb.begin() + (i - 1)); b && !b->IsEmpty()) {
                        stream.PrependReadData(b->Bytes());
                    }
                }
                mb.clear();
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
    head.bytes = data;
    if (!initial.empty()) {
        if (initial.size() > capacity - head.size) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        std::memcpy(data + head.size, initial.data(), initial.size());
        head.size += initial.size();
    }

    constexpr std::string_view kTerminator = "\r\n\r\n";
    size_t scanned = 0;
    while (true) {
        // Resume behind the last scanned byte; a terminator may straddle reads.
        const std::string_view received(unsafe::ptr_cast<const char>(data), head.size);
        const size_t from = scanned < kTerminator.size() - 1
            ? 0 : scanned - (kTerminator.size() - 1);
        if (const size_t end = received.find(kTerminator, from);
            end != std::string_view::npos) {
            head.header_end = end + kTerminator.size();
            co_return tl::expected<void, ErrorCode>{};
        }
        scanned = head.size;
        if (head.size == capacity) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        const size_t n = co_await stream.AsyncRead(
            net::buffer(data + head.size, capacity - head.size));
        if (n == 0) {
            co_return tl::unexpected(ErrorCode::SOCKET_EOF);
        }
        head.size += n;
    }
}

net::awaitable<tl::expected<Http1MessageHead, ErrorCode>> ReadHttp1MessageHead(
    AsyncStream& stream, std::span<const uint8_t> initial) {
    Http1MessageHead head;
    if (auto res = co_await ReadHttp1MessageHead(stream, head, initial); !res) {
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
        metadata->real_ip_header.assign(header_name);
    }
}

std::string SanitizeForLog(std::string_view value, size_t max_len) {
    value = TrimAscii(value);
    if (value.empty()) {
        return "-";
    }

    const size_t limit = std::min(value.size(), max_len);
    std::string out;
    out.reserve(limit + 4);

    for (size_t i = 0; i < limit; ++i) {
        const auto ch = static_cast<unsigned char>(value[i]);
        if (ch == '\r' || ch == '\n' || ch == '\t') {
            out.push_back(' ');
        } else if (std::isprint(ch)) {
            out.push_back(static_cast<char>(ch));
        } else {
            out.push_back('?');
        }
    }

    if (value.size() > limit) {
        out.append("...");
    }
    return out;
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

std::string_view ExpectedHttpHost(const HttpConfig& cfg) {
    return cfg.host.empty() ? ConfiguredHostHeader(cfg.headers)
                            : std::string_view(cfg.host);
}

std::string_view ResolveHttpUpgradeHost(std::string_view fallback_host,
                                        std::string_view configured_host,
                                        const HttpHeaders* headers) noexcept {
    const std::string_view raw_host = !configured_host.empty()
        ? configured_host
        : (headers ? ConfiguredHostHeader(*headers) : std::string_view{});
    const std::string_view trimmed = TrimAscii(raw_host);
    return trimmed.empty() ? fallback_host : trimmed;
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

    memory::ThreadLocalString request;
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
    memory::ThreadLocalString{}.swap(request);
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

std::unique_ptr<AsyncStream> MakeHttp1BodyStream(
    std::unique_ptr<AsyncStream> inner,
    Http1ReadFraming read_framing,
    bool write_chunked,
    std::span<const uint8_t> read_ahead) {
    auto body = std::make_unique<Http1BodyStream>(
        std::move(inner), read_framing, write_chunked);
    body->SetPendingData(read_ahead);
    return body;
}

net::awaitable<TransportBuildResult> DoHttp1ServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    uint64_t conn_id,
    InboundTransportMetadata* transport_metadata,
    std::span<const uint8_t> initial) {
    auto head = co_await ReadHttp1MessageHead(*stream, initial);
    if (!head) {
        LogHeadReadFailure("HTTP", conn_id, head.error());
        co_return tl::unexpected(head.error());
    }

    const std::string_view request = head->Text();
    const std::string_view request_line = ExtractStartLine(request);
    const auto parsed_line = ParseHttp1RequestLine(request_line);
    const auto method = parsed_line.method;
    const auto request_path = parsed_line.target;
    const std::string_view host = TrimAscii(ExtractHeaderValueCI(request, "Host"));

    LOG_CONN_TRACE(conn_id,
        "HTTP server request line='{}' method='{}' path='{}' host='{}' bytes={}",
        SanitizeHttpRequestLineForLog(parsed_line),
        PublicHttpMethodForLog(method),
        PublicHttpTargetForLog(request_path),
        PublicHttpTargetForLog(host),
        head->size);

    if (method.empty() || !detail::PathPrefixMatchesSegment(cfg.path, request_path)) {
        LOG_CONN_DEBUG(conn_id,
            "HTTP server path mismatch expected='{}' actual='{}'",
            PublicHttpTargetForLog(EffectiveHttpPath(cfg.path)),
            PublicHttpTargetForLog(request_path));
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (!cfg.method.empty() && !EqualsAsciiCI(method, cfg.method)) {
        LOG_CONN_DEBUG(conn_id,
            "HTTP server method mismatch expected='{}' actual='{}'",
            PublicHttpMethodForLog(cfg.method),
            PublicHttpMethodForLog(method));
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (const std::string_view expected_host = TrimAscii(ExpectedHttpHost(cfg));
        !expected_host.empty() && !EqualsAsciiCI(host, expected_host)) {
        LOG_CONN_DEBUG(conn_id,
            "HTTP server host mismatch expected='{}' actual='{}'",
            PublicHttpTargetForLog(expected_host),
            PublicHttpTargetForLog(host));
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    RecordExtractedRealIp(request, cfg.real_ip_header, transport_metadata);

    memory::ThreadLocalString response;
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

    if (const auto read_ahead = head->ReadAhead(); !read_ahead.empty()) {
        stream->PrependReadData(read_ahead);
    }
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
        if (!key.empty() && !IsHostHeader(key)) {
            reserve_size += key.size() + value.size() + 4;
        }
    }

    memory::ThreadLocalString request;
    request.reserve(reserve_size);
    AppendRequestStart(request, method, req_path, host);
    for (const auto& [key, value] : cfg.headers) {
        if (!key.empty() && !IsHostHeader(key)) {
            AppendHeaderLine(request, key, value);
        }
    }
    request.append("\r\n");

    if (!co_await WriteFullToStream(*stream, request)) {
        LOG_CONN_DEBUG(conn_id, "HTTP client failed to send request");
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }
    memory::ThreadLocalString{}.swap(request);
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
    auto head = co_await ReadHttp1MessageHead(*stream);
    if (!head) {
        LogHeadReadFailure("HTTPUpgrade", conn_id, head.error());
        co_return tl::unexpected(head.error());
    }

    const std::string_view request = head->Text();
    const std::string_view request_line = ExtractStartLine(request);
    const auto parsed_line = ParseHttp1RequestLine(request_line);
    const auto request_path = parsed_line.target;
    const std::string_view host = TrimAscii(ExtractHeaderValueCI(request, "Host"));

    LOG_CONN_TRACE(conn_id,
        "HTTPUpgrade server request line='{}' path='{}' host='{}' bytes={}",
        SanitizeHttpRequestLineForLog(parsed_line),
        PublicHttpTargetForLog(request_path),
        PublicHttpTargetForLog(host),
        head->size);

    if (!request_line.starts_with("GET ") ||
        !detail::PathMatchesExactly(cfg.path, request_path)) {
        LOG_CONN_DEBUG(conn_id,
            "HTTPUpgrade server path mismatch expected='{}' actual='{}'",
            PublicHttpTargetForLog(EffectiveHttpPath(cfg.path)),
            PublicHttpTargetForLog(request_path));
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (!HasWebSocketUpgradeHeaders(request)) {
        LOG_CONN_DEBUG(conn_id, "HTTPUpgrade server received invalid upgrade headers");
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (const std::string_view expected_host =
            ResolveHttpUpgradeHost({}, cfg.host, &cfg.headers);
        !expected_host.empty() && !EqualsAsciiCI(host, expected_host)) {
        LOG_CONN_DEBUG(conn_id,
            "HTTPUpgrade server host mismatch expected='{}' actual='{}'",
            PublicHttpTargetForLog(expected_host),
            PublicHttpTargetForLog(host));
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    RecordExtractedRealIp(request, cfg.real_ip_header, transport_metadata);

    constexpr std::string_view kResponse =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "\r\n";
    if (!co_await WriteFullToStream(*stream, kResponse)) {
        LOG_CONN_DEBUG(conn_id, "HTTPUpgrade server failed to send 101 response");
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    if (const auto read_ahead = head->ReadAhead(); !read_ahead.empty()) {
        stream->PrependReadData(read_ahead);
    }
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
        ResolveHttpUpgradeHost(host, cfg.host, &cfg.headers);
    auto head = co_await ExecuteHttp1UpgradeClientHandshake(
        *stream, "HTTPUpgrade", conn_id, effective_host, req_path, &cfg.headers);
    if (!head) {
        co_return tl::unexpected(head.error());
    }
    if (const auto read_ahead = head->ReadAhead(); !read_ahead.empty()) {
        stream->PrependReadData(read_ahead);
    }
    LOG_CONN_DEBUG(conn_id, "HTTPUpgrade client handshake completed (host={} path={})",
                   PublicHttpTargetForLog(effective_host), PublicHttpTargetForLog(req_path));
    co_return std::move(stream);
}

net::awaitable<TransportBuildResult> DoWsServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const WsConfig& ws_cfg,
    uint64_t conn_id,
    InboundTransportMetadata* transport_metadata) {
    auto head = co_await ReadHttp1MessageHead(*stream);
    if (!head) {
        LogHeadReadFailure("WS", conn_id, head.error());
        co_return tl::unexpected(head.error());
    }

    const std::string_view request = head->Text();
    const std::string_view request_line = ExtractStartLine(request);
    const auto parsed_line = ParseHttp1RequestLine(request_line);
    const auto request_path = parsed_line.target;
    const std::string_view host = ExtractHeaderValueCI(request, "Host");
    const std::string_view version = ExtractHeaderValueCI(request, "Sec-WebSocket-Version");

    LOG_CONN_TRACE(conn_id, "WebSocket server received HTTP upgrade bytes={}", head->size);

    if (!HasWebSocketUpgradeHeaders(request)) {
        LOG_CONN_DEBUG(conn_id, "WebSocket server missing 'Upgrade: websocket' header");
        LOG_CONN_TRACE(conn_id, "WebSocket server rejected missing upgrade line='{}' host='{}'",
                      SanitizeHttpRequestLineForLog(parsed_line),
                      PublicHttpTargetForLog(host));
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (!request_line.starts_with("GET ") || !request_line.ends_with(" HTTP/1.1") ||
        TrimAscii(version) != "13") {
        LOG_CONN_DEBUG(conn_id, "WebSocket server received invalid upgrade request");
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    // 仅在配置了非根路径时校验路径
    const std::string_view expected_path = EffectiveHttpPath(ws_cfg.path);
    if (expected_path != "/" && request_path != expected_path) {
        LOG_CONN_DEBUG(conn_id, "WebSocket server path mismatch expected='{}'",
                       PublicHttpTargetForLog(expected_path));
        LOG_CONN_TRACE(conn_id, "WebSocket server rejected path mismatch expected='{}' actual='{}' line='{}'",
                      PublicHttpTargetForLog(expected_path),
                      PublicHttpTargetForLog(request_path),
                      SanitizeHttpRequestLineForLog(parsed_line));
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    // RFC 6455 4.2.1: the key is a base64-encoded 16-byte nonce.
    const std::string_view ws_key = TrimAscii(
        ExtractHeaderValueCI(request, "Sec-WebSocket-Key"));
    std::array<uint8_t, 18> decoded_key;
    if (ws_key.size() != 24 || ws_key[22] != '=' || ws_key[23] != '=' ||
        EVP_DecodeBlock(decoded_key.data(),
            reinterpret_cast<const uint8_t*>(ws_key.data()), 24) != 18) {
        LOG_CONN_DEBUG(conn_id, "WebSocket server received invalid Sec-WebSocket-Key header");
        LOG_CONN_TRACE(conn_id, "WebSocket server rejected invalid key line='{}' host='{}' version='{}'",
                      SanitizeHttpRequestLineForLog(parsed_line),
                      PublicHttpTargetForLog(host),
                      SanitizeForLog(version));
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    // 提取真实客户端 IP（CDN 透传头）
    RecordExtractedRealIp(request, ws_cfg.real_ip_header, transport_metadata);

    memory::ThreadLocalString response;
    response.reserve(128);
    response.append("HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Accept: ");
    const auto ws_accept = ws::EncodeWsAccept(ws_key);
    response.append(ws_accept.data(), ws_accept.size());
    response.append("\r\n\r\n");
    if (!co_await WriteFullToStream(*stream, response)) {
        LOG_CONN_DEBUG(conn_id, "WebSocket server failed to send 101 response");
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    // HTTP 头之后已读到的字节属于 WebSocket 帧流
    auto ws = std::make_unique<WsServerStream>(std::move(stream), conn_id);
    const auto read_ahead = head->ReadAhead();
    if (!read_ahead.empty()) {
        ws->SetPendingData(read_ahead.data(), read_ahead.size());
    }
    LOG_CONN_TRACE(conn_id,
        "WebSocket server handshake accepted path='{}' host='{}' pending={}",
        PublicHttpTargetForLog(expected_path),
        PublicHttpTargetForLog(host),
        read_ahead.size());
    LOG_CONN_DEBUG(conn_id, "WebSocket server handshake completed (path={})",
                   PublicHttpTargetForLog(expected_path));
    co_return std::unique_ptr<AsyncStream>(std::move(ws));
}

}  // namespace transport::internet
