#include "http1_handshake.hpp"
#include "acppnode/common/binary_text_codec.hpp"

#include "http_path_match.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/internet/http_headers.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/transport/internet/ws_stream.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstring>
#include <limits>
#include <optional>

namespace acpp::transport::internet {
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
        if (data.empty()) {
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
        if (write_closed_) {
            throw IoSystemError(io_error::operation_aborted, "http1 body write closed");
        }
        if (!write_chunked_) {
            co_return co_await inner_->AsyncWrite(buffer);
        }
        const auto* data = static_cast<const uint8_t*>(buffer.data());
        const size_t len = buffer.size();
        if (len == 0) {
            co_return 0;
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
        const std::array<net::const_buffer, 3> buffers{
            net::buffer(prefix.data(), static_cast<size_t>(ptr - prefix.data())),
            net::buffer(data, len),
            net::buffer(kChunkTail.data(), kChunkTail.size())
        };
        try {
            co_await inner_->WriteBuffers(buffers);
        } catch (...) {
            throw IoSystemError(io_error::broken_pipe, "http1 chunk write failed");
        }
        co_return len;
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
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
        if (write_closed_) {
            mb.clear();
            throw IoSystemError(io_error::operation_aborted, "http1 body write closed");
        }
        if (!write_chunked_) {
            co_await inner_->WriteMultiBuffer(std::move(mb));
            co_return;
        }
        for (buf::Buffer*& buffer : mb) {
            if (buffer && !buffer->IsEmpty()) {
                const auto bytes = buffer->Bytes();
                (void)co_await AsyncWrite(net::buffer(bytes.data(), bytes.size()));
            }
            mb.FreeSlot(buffer);
        }
        mb.clear();
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        if (write_closed_) {
            throw IoSystemError(io_error::operation_aborted, "http1 body write closed");
        }
        if (!write_chunked_) {
            co_await inner_->WriteBuffers(buffers);
            co_return;
        }
        for (const auto& buffer : buffers) {
            if (buffer.size() == 0) {
                continue;
            }
            (void)co_await AsyncWrite(buffer);
        }
    }

    void ShutdownRead() override {
        read_closed_ = true;
        pending_.clear();
        inner_->ShutdownRead();
    }

    void ShutdownWrite() override {
        if (write_closed_) {
            return;
        }
        write_closed_ = true;
        inner_->ShutdownWrite();
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (write_closed_) {
            co_return;
        }
        write_closed_ = true;
        if (write_chunked_) {
            (void)co_await WriteFullToStream(*inner_, "0\r\n\r\n");
        }
        co_await inner_->AsyncShutdownWrite();
    }

    void Cancel() noexcept override {
        NotifyCancellation();
        inner_->Cancel();
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

    net::awaitable<size_t> ReadRaw(net::mutable_buffer buffer) {
        auto* out = static_cast<uint8_t*>(buffer.data());
        const size_t capacity = buffer.size();
        if (capacity == 0) {
            co_return 0;
        }
        if (pending_.byte_size() != 0) {
            co_return pending_.ConsumePrefixTo(std::span<uint8_t>(out, capacity));
        }
        co_return co_await inner_->AsyncRead(buffer);
    }

    // RFC 9112 6.3: a Content-Length body ends after exactly that many bytes;
    // whatever follows on the connection is not body. EOF before the end is a
    // truncated message, not a clean close.
    net::awaitable<size_t> ReadContentLength(net::mutable_buffer buffer) {
        if (*content_remaining_ == 0 || buffer.size() == 0) {
            co_return 0;
        }
        const auto want = static_cast<size_t>(
            std::min<uint64_t>(buffer.size(), *content_remaining_));
        const size_t n = co_await ReadRaw(net::buffer(buffer.data(), want));
        if (n == 0) FailBodyRead("truncated HTTP/1 Content-Length body");
        *content_remaining_ -= n;
        co_return n;
    }

    net::awaitable<buf::MultiBuffer> ReadContentLengthMultiBuffer() {
        if (*content_remaining_ == 0) {
            co_return buf::MultiBuffer{};
        }
        if (pending_.byte_size() == 0) {
            pending_ = co_await inner_->ReadMultiBuffer();
            if (pending_.byte_size() == 0) FailBodyRead("truncated HTTP/1 Content-Length body");
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
        throw IoSystemError(io_error::invalid_argument, what);
    }

    net::awaitable<bool> EnsureChunkPayload() {
        if (read_closed_) {
            co_return false;
        }
        while (chunk_remaining_ == 0) {
            if (chunk_terminator_pending_) {
                constexpr std::array<uint8_t, 2> terminator{'\r', '\n'};
                while (chunk_terminator_bytes_ != terminator.size()) {
                    if (pending_.byte_size() == 0) {
                        pending_ = co_await inner_->ReadMultiBuffer();
                        if (pending_.byte_size() == 0)
                            FailBodyRead("incomplete HTTP/1 chunk terminator");
                    }
                    const auto bytes = pending_.FrontSpan();
                    const size_t count = std::min(bytes.size(),
                        terminator.size() - chunk_terminator_bytes_);
                    for (size_t i = 0; i < count; ++i) {
                        if (bytes[i] != terminator[chunk_terminator_bytes_ + i])
                            FailBodyRead("invalid HTTP/1 chunk terminator");
                    }
                    pending_.DropPrefixBytes(count);
                    chunk_terminator_bytes_ += count;
                }
                chunk_terminator_bytes_ = 0;
                chunk_terminator_pending_ = false;
            }
            if (!co_await ReadLine())
                FailBodyRead("incomplete HTTP/1 chunk-size or trailer line");
            if (reading_trailers_) {
                const bool finished = line_.empty();
                ResetLine();
                if (finished) {
                    read_closed_ = true;
                    co_return false;
                }
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
        if (read_closed_) {
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
        if (n == 0) FailBodyRead("truncated HTTP/1 chunk payload");
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

[[nodiscard]] std::string_view ConfiguredHostHeader(const HttpHeaders& headers) {
    const std::string* host = FindHttpHeader(headers, "Host");
    return host ? std::string_view(*host) : std::string_view{};
}

[[nodiscard]] std::string_view ExpectedHttpUpgradeHost(const HttpUpgradeConfig& cfg) {
    return cfg.host.empty() ? ConfiguredHostHeader(cfg.headers)
                            : std::string_view(cfg.host);
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
        LOG_CONN_DEBUG(conn_id, "{} client request rejected > {}",
                       scope, SanitizeForLog(status_line));
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (status_code == "101" &&
        (!EqualsAsciiCI(TrimAscii(ExtractHeaderValueCI(head->Text(), "Upgrade")), "websocket") ||
         !HeaderListContainsTokenCI(head->Text(), "Connection", "upgrade"))) {
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

net::awaitable<tl::expected<Http1MessageHead, ErrorCode>> ReadHttp1MessageHead(
    AsyncStream& stream, std::span<const uint8_t> initial) {
    Http1MessageHead head;
    head.storage = buf::BufferGuard{buf::Buffer::New()};
    if (!head.storage) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    uint8_t* data = head.storage->Tail().data();
    const size_t capacity = head.storage->Available();
    if (initial.size() > capacity) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (!initial.empty()) {
        std::memcpy(data, initial.data(), initial.size());
    }
    head.bytes = data;
    head.size = initial.size();

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
            co_return std::move(head);
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

std::string_view ExtractStartLine(std::string_view head) {
    return head.substr(0, head.find("\r\n"));
}

std::string_view ExtractRequestMethod(std::string_view request_line) {
    const size_t end = request_line.find(' ');
    if (end == std::string_view::npos) {
        return {};
    }
    return request_line.substr(0, end);
}

std::string_view ExtractRequestTarget(std::string_view request_line) {
    const size_t first_space = request_line.find(' ');
    if (first_space == std::string_view::npos) {
        return {};
    }
    size_t start = first_space + 1;
    while (start < request_line.size() && request_line[start] == ' ') {
        ++start;
    }
    const size_t end = request_line.find(' ', start);
    if (end == std::string_view::npos || end <= start) {
        return {};
    }
    return request_line.substr(start, end - start);
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
    value = TrimAscii(value);
    value = value.substr(0, value.find_first_of("?#"));
    const auto scheme = value.find("://");
    const size_t authority_start = scheme != std::string_view::npos
        ? scheme + 3 : value.starts_with("//") ? 2 : 0;
    const auto authority_end = value.find('/', authority_start);
    const auto at = value.substr(0, authority_end).rfind('@');
    if (at != std::string_view::npos) {
        value.remove_prefix(at + 1);
    }
    return value;
}

std::string SanitizeHttpRequestLineForLog(std::string_view value) {
    const auto method_end = value.find(' ');
    const auto target_end = value.rfind(' ');
    if (method_end == std::string_view::npos || target_end <= method_end) {
        return "invalid request line";
    }
    const auto method = value.substr(0, method_end);
    const auto target = PublicHttpTargetForLog(
        value.substr(method_end + 1, target_end - method_end - 1));
    const auto version = value.substr(target_end + 1);
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
    const std::string_view method = ExtractRequestMethod(request_line);
    const std::string_view request_path = ExtractRequestTarget(request_line);
    const std::string_view host = TrimAscii(ExtractHeaderValueCI(request, "Host"));
    const std::string_view user_agent = ExtractHeaderValueCI(request, "User-Agent");

    LOG_CONN_TRACE(conn_id,
        "HTTP server request line='{}' method='{}' path='{}' host='{}' ua='{}' bytes={}",
        SanitizeHttpRequestLineForLog(request_line),
        SanitizeForLog(method),
        PublicHttpTargetForLog(request_path),
        PublicHttpTargetForLog(host),
        SanitizeForLog(user_agent),
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
            cfg.method,
            SanitizeForLog(method));
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
        if (!IsHostHeader(key)) {
            reserve_size += key.size() + value.size() + 4;
        }
    }

    memory::ThreadLocalString request;
    request.reserve(reserve_size);
    AppendRequestStart(request, method, req_path, host);
    for (const auto& [key, value] : cfg.headers) {
        if (!IsHostHeader(key)) {
            AppendHeaderLine(request, key, value);
        }
    }
    request.append("\r\n");

    if (!co_await WriteFullToStream(*stream, request)) {
        LOG_CONN_DEBUG(conn_id, "HTTP client failed to send request");
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }
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
    const std::string_view request_path = ExtractRequestTarget(request_line);
    const std::string_view host = TrimAscii(ExtractHeaderValueCI(request, "Host"));
    const std::string_view upgrade = TrimAscii(ExtractHeaderValueCI(request, "Upgrade"));
    const std::string_view connection = ExtractHeaderValueCI(request, "Connection");
    const std::string_view user_agent = ExtractHeaderValueCI(request, "User-Agent");

    LOG_CONN_TRACE(conn_id,
        "HTTPUpgrade server request line='{}' path='{}' host='{}' upgrade='{}' connection='{}' ua='{}' bytes={}",
        SanitizeHttpRequestLineForLog(request_line),
        PublicHttpTargetForLog(request_path),
        PublicHttpTargetForLog(host),
        SanitizeForLog(upgrade),
        SanitizeForLog(connection),
        SanitizeForLog(user_agent),
        head->size);

    if (!request_line.starts_with("GET ") ||
        !detail::PathMatchesExactly(cfg.path, request_path)) {
        LOG_CONN_DEBUG(conn_id,
            "HTTPUpgrade server path mismatch expected='{}' actual='{}'",
            PublicHttpTargetForLog(EffectiveHttpPath(cfg.path)),
            PublicHttpTargetForLog(request_path));
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (!EqualsAsciiCI(upgrade, "websocket") ||
        !HeaderListContainsTokenCI(request, "Connection", "upgrade")) {
        LOG_CONN_DEBUG(conn_id, "HTTPUpgrade server received invalid upgrade headers");
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (const std::string_view expected_host = TrimAscii(ExpectedHttpUpgradeHost(cfg));
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
    size_t reserve_size = 192 + req_path.size() + host.size();
    for (const auto& [key, value] : cfg.headers) {
        if (!IsHostHeader(key)) {
            reserve_size += key.size() + value.size() + 4;
        }
    }

    memory::ThreadLocalString request;
    request.reserve(reserve_size);
    AppendRequestStart(request, "GET", req_path, host);
    request.append("Upgrade: websocket\r\n");
    request.append("Connection: Upgrade\r\n");
    for (const auto& [key, value] : cfg.headers) {
        if (!IsHostHeader(key)) {
            AppendHeaderLine(request, key, value);
        }
    }
    request.append("\r\n");

    if (!co_await WriteFullToStream(*stream, request)) {
        LOG_CONN_DEBUG(conn_id, "HTTPUpgrade client failed to send request");
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }
    if (auto response = co_await ReadClientResponse(*stream, "HTTPUpgrade", conn_id, "101");
        !response) {
        co_return tl::unexpected(response.error());
    }
    LOG_CONN_DEBUG(conn_id, "HTTPUpgrade client handshake completed (host={} path={})",
                   PublicHttpTargetForLog(host), PublicHttpTargetForLog(req_path));
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
    const std::string_view request_path = ExtractRequestTarget(request_line);
    const std::string_view host = ExtractHeaderValueCI(request, "Host");
    const std::string_view upgrade = ExtractHeaderValueCI(request, "Upgrade");
    const std::string_view connection = ExtractHeaderValueCI(request, "Connection");
    const std::string_view version = ExtractHeaderValueCI(request, "Sec-WebSocket-Version");

    LOG_CONN_TRACE(conn_id, "WebSocket server received HTTP upgrade bytes={}", head->size);

    if (!EqualsAsciiCI(TrimAscii(upgrade), "websocket")) {
        LOG_CONN_DEBUG(conn_id, "WebSocket server missing 'Upgrade: websocket' header");
        LOG_CONN_TRACE(conn_id, "WebSocket server rejected missing upgrade line='{}' host='{}' upgrade='{}' connection='{}'",
                      SanitizeHttpRequestLineForLog(request_line),
                      PublicHttpTargetForLog(host),
                      SanitizeForLog(upgrade),
                      SanitizeForLog(connection));
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (!request_line.starts_with("GET ") || !request_line.ends_with(" HTTP/1.1") ||
        !HeaderListContainsTokenCI(request, "Connection", "upgrade") || TrimAscii(version) != "13") {
        LOG_CONN_DEBUG(conn_id, "WebSocket server received invalid upgrade request");
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    // 仅在配置了非根路径时校验路径
    if (ws_cfg.path != "/" && !ws_cfg.path.empty() && request_path != ws_cfg.path) {
        LOG_CONN_DEBUG(conn_id, "WebSocket server path mismatch expected='{}'", PublicHttpTargetForLog(ws_cfg.path));
        LOG_CONN_TRACE(conn_id, "WebSocket server rejected path mismatch expected='{}' actual='{}' line='{}'",
                      PublicHttpTargetForLog(ws_cfg.path),
                      PublicHttpTargetForLog(request_path),
                      SanitizeHttpRequestLineForLog(request_line));
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
                      SanitizeHttpRequestLineForLog(request_line),
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
    response.append(ws::ComputeWsAccept(ws_key));
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
        "WebSocket server handshake accepted path='{}' host='{}' pending={} real_ip_header='{}' real_ip='{}'",
        PublicHttpTargetForLog(EffectiveHttpPath(ws_cfg.path)),
        PublicHttpTargetForLog(host),
        read_ahead.size(),
        ws_cfg.real_ip_header.empty() ? "-" : ws_cfg.real_ip_header,
        (transport_metadata && !transport_metadata->real_ip.empty())
            ? std::string_view(transport_metadata->real_ip)
            : std::string_view("-"));
    LOG_CONN_DEBUG(conn_id, "WebSocket server handshake completed (path={})", PublicHttpTargetForLog(ws_cfg.path));
    co_return std::unique_ptr<AsyncStream>(std::move(ws));
}

}  // namespace acpp::transport::internet
