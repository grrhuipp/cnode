#include "acppnode/transport/internet/transport_stack.hpp"
#include "async_write_gate.hpp"
#include "http2_settings.hpp"
#include "tls_context_cache.hpp"
#include "tls_context_cache_key.hpp"
#include "xhttp_packet_queue.hpp"
#include "xhttp_packet_session_key.hpp"
#include "xhttp_upload_stream_slot.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/transport/internet/tls_stream.hpp"
#include "acppnode/transport/internet/ws_stream.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/base64.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/unsafe.hpp"

#include <openssl/sha.h>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/channel.hpp>
#include <array>
#include <charconv>
#include <cctype>
#include <cstring>
#include <format>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace acpp {

namespace {

constexpr size_t kTlsContextCacheMaxEntries = 16;
constexpr size_t kXHttpMaxPacketSessions = 1024;
constexpr size_t kGrpcServerH2QueueShrinkItems = 64;

using TlsContextMap =
    memory::ThreadLocalUnorderedMap<std::string, std::unique_ptr<SslContext>>;
using TlsContextCache = transport::internet::BoundedTlsContextCache<
    SslContext, TlsContextMap>;

[[nodiscard]] std::string ComputeWsAccept(std::string_view ws_key) {
    constexpr std::string_view kWsGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string accept_src;
    accept_src.reserve(ws_key.size() + kWsGuid.size());
    accept_src.append(ws_key);
    accept_src.append(kWsGuid);

    uint8_t sha1[20];
    SHA1(unsafe::ptr_cast<const uint8_t>(accept_src.data()), accept_src.size(), sha1);
    return Base64Encode(sha1, sizeof(sha1));
}

SslContext* AcquireServerTlsContext(const TlsConfig& config) {
    thread_local TlsContextCache cache(kTlsContextCacheMaxEntries);

    const bool has_certificate = config.HasCertificatePair();
    std::string key = has_certificate
        ? transport::internet::MakeTlsContextCacheKey("server", config)
        : transport::internet::MakeTlsContextCacheKey("server-auto-sign", config);

    if (auto* cached = cache.Find(key)) return cached;

    std::unique_ptr<SslContext> ctx;
    if (has_certificate) {
        ctx = SslContext::CreateServer(config);
    } else {
        ctx = SslContext::CreateServerAutoSign(config);
    }

    if (ctx) {
        return cache.Insert(std::move(key), std::move(ctx));
    }
    return nullptr;
}

SslContext* AcquireServerRealityContext(const RealityConfig& reality,
                                        const TlsConfig& tls_config) {
    thread_local TlsContextCache cache(kTlsContextCacheMaxEntries);

    std::string key = transport::internet::MakeRealityServerContextCacheKey(
        reality, tls_config);
    if (auto* cached = cache.Find(key)) return cached;

    auto ctx = SslContext::CreateServerReality(reality, tls_config);
    if (!ctx) {
        return nullptr;
    }

    return cache.Insert(std::move(key), std::move(ctx));
}

SslContext* AcquireClientTlsContext(const TlsConfig& config) {
    thread_local TlsContextCache cache(kTlsContextCacheMaxEntries);

    std::string key =
        transport::internet::MakeTlsContextCacheKey("client", config);

    if (auto* cached = cache.Find(key)) return cached;

    std::unique_ptr<SslContext> ctx = SslContext::CreateClient(config);
    if (ctx) {
        return cache.Insert(std::move(key), std::move(ctx));
    }
    return nullptr;
}

SslContext* AcquireClientRealityContext(const RealityConfig& reality,
                                        const TlsConfig& tls_config) {
    thread_local TlsContextCache cache(kTlsContextCacheMaxEntries);

    std::string key = transport::internet::MakeRealityClientContextCacheKey(
        reality, tls_config);
    if (auto* cached = cache.Find(key)) return cached;

    auto ctx = SslContext::CreateClientReality(reality, tls_config);
    if (!ctx) {
        return nullptr;
    }

    return cache.Insert(std::move(key), std::move(ctx));
}

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

[[nodiscard]] std::string_view ExtractHeaderValueCI(
    std::string_view request,
    std::string_view name) {
    size_t line_start = 0;
    while (line_start < request.size()) {
        const size_t line_end = request.find("\r\n", line_start);
        if (line_end == std::string_view::npos) {
            break;
        }
        if (line_end == line_start) {
            break;
        }

        const std::string_view line = request.substr(line_start, line_end - line_start);
        if (const size_t colon = line.find(':'); colon != std::string_view::npos) {
            if (EqualsAsciiCI(line.substr(0, colon), name)) {
                size_t value_start = colon + 1;
                while (value_start < line.size() &&
                       (line[value_start] == ' ' || line[value_start] == '\t')) {
                    ++value_start;
                }
                return line.substr(value_start);
            }
        }
        line_start = line_end + 2;
    }
    return {};
}

[[nodiscard]] std::string_view ExtractRequestLine(std::string_view request) {
    const size_t end = request.find("\r\n");
    if (end == std::string_view::npos) {
        return request;
    }
    return request.substr(0, end);
}

[[nodiscard]] std::string_view ExtractRequestMethod(std::string_view request_line) {
    const size_t end = request_line.find(' ');
    if (end == std::string_view::npos) {
        return {};
    }
    return request_line.substr(0, end);
}

[[nodiscard]] std::string_view ExtractRequestPathAny(std::string_view request_line) {
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

[[nodiscard]] std::string_view ExtractRequestPath(std::string_view request_line) {
    constexpr std::string_view kGet = "GET ";
    if (!request_line.starts_with(kGet)) {
        return {};
    }

    const size_t start = kGet.size();
    const size_t end = request_line.find(' ', start);
    if (end == std::string_view::npos || end <= start) {
        return {};
    }
    return request_line.substr(start, end - start);
}

[[nodiscard]] std::string_view PathWithoutQuery(std::string_view path) {
    const size_t query = path.find('?');
    if (query == std::string_view::npos) {
        return path;
    }
    return path.substr(0, query);
}

[[nodiscard]] std::string_view EffectivePath(std::string_view configured) {
    return configured.empty() ? std::string_view("/") : configured;
}

[[nodiscard]] bool RequestPathMatches(std::string_view configured,
                                      std::string_view actual) {
    return PathWithoutQuery(actual) == EffectivePath(configured);
}

[[nodiscard]] bool IsHostHeader(std::string_view key) {
    return EqualsAsciiCI(key, "Host");
}

[[nodiscard]] std::string_view FindConfiguredHost(
    const transport::internet::HttpHeaders& headers) {
    for (const auto& [key, value] : headers) {
        if (IsHostHeader(key)) {
            return value;
        }
    }
    return {};
}

[[nodiscard]] std::string_view ExpectedHttpUpgradeHost(
    const HttpUpgradeConfig& cfg) {
    if (!cfg.host.empty()) {
        return cfg.host;
    }
    return FindConfiguredHost(cfg.headers);
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

[[nodiscard]] bool HeaderContainsTokenCI(std::string_view value,
                                         std::string_view token) {
    while (!value.empty()) {
        size_t comma = value.find(',');
        std::string_view part = comma == std::string_view::npos
            ? value
            : value.substr(0, comma);
        part = TrimAscii(part);
        if (EqualsAsciiCI(part, token)) {
            return true;
        }
        if (comma == std::string_view::npos) {
            break;
        }
        value.remove_prefix(comma + 1);
    }
    return false;
}

[[nodiscard]] std::string SanitizeForLog(std::string_view value, size_t max_len = 160) {
    value = TrimAscii(value);
    if (value.empty()) {
        return "-";
    }

    const size_t limit = std::min(value.size(), max_len);
    std::string out;
    out.reserve(limit + 4);

    for (size_t i = 0; i < limit; ++i) {
        unsigned char ch = static_cast<unsigned char>(value[i]);
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

net::awaitable<bool> WriteFullToStream(AsyncStream& stream,
                                       const uint8_t* data,
                                       size_t len) {
    if (len == 0) {
        co_return true;
    }
    const net::const_buffer buffer{data, len};
    try {
        co_await stream.WriteBuffers(
            std::span<const net::const_buffer>{&buffer, 1});
    } catch (...) {
        co_return false;
    }
    co_return true;
}

net::awaitable<size_t> ReadToMultiBufferTail(AsyncStream& stream,
                                             buf::MultiBuffer& out,
                                             size_t max_read) {
    if (max_read == 0) {
        co_return 0;
    }
    buf::BufferGuard buffer{buf::Buffer::New()};
    if (!buffer) {
        throw std::bad_alloc();
    }
    try {
        const size_t capacity = std::min(
            max_read,
            static_cast<size_t>(buffer->Available()));
        const size_t n = co_await stream.AsyncRead(
            net::buffer(buffer->Tail().data(), capacity));
        if (n > 0) {
            buffer->Produce(static_cast<uint32_t>(n));
            out.push_back(buffer.release());
        }
        co_return n;
    } catch (...) {
        throw;
    }
}

}  // namespace

class HttpUpgradeStream final : public AsyncStream {
public:
    explicit HttpUpgradeStream(std::unique_ptr<AsyncStream> inner)
        : inner_(std::move(inner)) {}

    ~HttpUpgradeStream() noexcept override {
        Close();
    }

    void SetPendingData(const uint8_t* data, size_t len) {
        size_t offset = 0;
        while (offset < len) {
            buf::BufferGuard buffer{buf::Buffer::New()};
            if (!buffer) {
                throw std::bad_alloc();
            }
            const size_t n = std::min(
                len - offset,
                static_cast<size_t>(buffer->Available()));
            std::memcpy(buffer->Tail().data(), data + offset, n);
            buffer->Produce(static_cast<uint32_t>(n));
            pending_.push_back(buffer.release());
            offset += n;
        }
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        if (buf::HasData(pending_)) {
            co_return PopPendingData(buffer);
        }
        co_return co_await inner_->AsyncRead(buffer);
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        co_return co_await inner_->AsyncWrite(buffer);
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (buf::HasData(pending_)) {
            co_return std::move(pending_);
        }
        co_return co_await inner_->ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        co_await inner_->WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        co_await inner_->WriteBuffers(buffers);
    }

    void ShutdownRead() override {
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
        co_await inner_->AsyncShutdownWrite();
    }

    void Cancel() noexcept override {
        inner_->Cancel();
    }

    void Close() override {
        if (closed_) {
            return;
        }
        closed_ = true;
        pending_.clear();
        inner_->Close();
    }

    void CloseAbortive() override {
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
    size_t PopPendingData(net::mutable_buffer target) noexcept {
        return pending_.ConsumePrefixTo(
            std::span<uint8_t>(
                static_cast<uint8_t*>(target.data()),
                target.size()));
    }

    std::unique_ptr<AsyncStream> inner_;
    buf::MultiBuffer pending_;
    bool closed_ = false;
    bool write_closed_ = false;
};

class Http1BodyStream final : public AsyncStream {
public:
    Http1BodyStream(std::unique_ptr<AsyncStream> inner,
                    bool read_chunked,
                    bool write_chunked)
        : inner_(std::move(inner))
        , read_chunked_(read_chunked)
        , write_chunked_(write_chunked) {}

    ~Http1BodyStream() noexcept override {
        Close();
    }

    void SetPendingData(const uint8_t* data, size_t len) {
        if (len == 0) {
            return;
        }
        if (!buf::AppendSpanToMultiBuffer(
                std::span<const uint8_t>(data, len),
                pending_)) {
            throw std::bad_alloc();
        }
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        if (!read_chunked_) {
            co_return co_await ReadRaw(buffer);
        }
        co_return co_await ReadChunked(buffer);
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
        if (!read_chunked_) {
            if (buf::HasData(pending_)) {
                co_return std::move(pending_);
            }
            co_return co_await inner_->ReadMultiBuffer();
        }
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) {
            throw std::bad_alloc();
        }
        const size_t n = co_await AsyncRead(
            net::buffer(buffer->Tail().data(), buffer->Available()));
        if (n == 0) {
            co_return buf::MultiBuffer{};
        }
        buffer->Produce(static_cast<uint32_t>(n));
        buf::MultiBuffer mb;
        mb.push_back(buffer.release());
        co_return mb;
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
            (void)co_await WriteFullToStream(
                *inner_,
                unsafe::ptr_cast<const uint8_t>("0\r\n\r\n"),
                5);
        }
        co_await inner_->AsyncShutdownWrite();
    }

    void Cancel() noexcept override {
        inner_->Cancel();
    }

    void Close() override {
        if (closed_) {
            return;
        }
        closed_ = true;
        pending_.clear();
        inner_->Close();
    }

    void CloseAbortive() override {
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
    static int HexValue(uint8_t ch) noexcept {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return 10 + ch - 'a';
        if (ch >= 'A' && ch <= 'F') return 10 + ch - 'A';
        return -1;
    }

    static std::optional<size_t> ParseChunkSize(std::string_view line) noexcept {
        size_t value = 0;
        bool any = false;
        for (char ch : line) {
            if (ch == ';') {
                break;
            }
            if (ch == ' ' || ch == '\t') {
                if (any) {
                    continue;
                }
                continue;
            }
            const int hex = HexValue(static_cast<uint8_t>(ch));
            if (hex < 0) {
                return std::nullopt;
            }
            if (value > (std::numeric_limits<size_t>::max() >> 4)) {
                return std::nullopt;
            }
            value = (value << 4) | static_cast<size_t>(hex);
            any = true;
        }
        if (!any) {
            return std::nullopt;
        }
        return value;
    }

    net::awaitable<size_t> ReadRaw(net::mutable_buffer buffer) {
        auto* out = static_cast<uint8_t*>(buffer.data());
        const size_t capacity = buffer.size();
        if (capacity == 0) {
            co_return 0;
        }
        if (buf::HasData(pending_)) {
            const size_t n = pending_.ConsumePrefixTo(
                std::span<uint8_t>(out, capacity));
            co_return n;
        }
        co_return co_await inner_->AsyncRead(buffer);
    }

    net::awaitable<size_t> ReadRawByte(uint8_t& out) {
        if (buf::HasData(pending_)) {
            co_return pending_.ConsumePrefixTo(std::span<uint8_t>(&out, 1));
        }
        const size_t n = co_await inner_->AsyncRead(net::buffer(&out, 1));
        co_return n;
    }

    net::awaitable<bool> ReadLine(std::string& out) {
        out.clear();
        uint8_t prev = 0;
        while (out.size() < 8192) {
            uint8_t ch = 0;
            const size_t n = co_await ReadRawByte(ch);
            if (n == 0) {
                co_return false;
            }
            out.push_back(static_cast<char>(ch));
            if (prev == '\r' && ch == '\n') {
                out.resize(out.size() - 2);
                co_return true;
            }
            prev = ch;
        }
        co_return false;
    }

    net::awaitable<bool> ReadExact(uint8_t* out, size_t len) {
        size_t copied = 0;
        while (copied < len) {
            const size_t n = co_await ReadRaw(
                net::buffer(out + copied, len - copied));
            if (n == 0) {
                co_return false;
            }
            copied += n;
        }
        co_return true;
    }

    net::awaitable<bool> ConsumeTrailers() {
        std::string line;
        while (co_await ReadLine(line)) {
            if (line.empty()) {
                co_return true;
            }
        }
        co_return false;
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

        size_t copied = 0;
        while (copied < capacity) {
            if (chunk_remaining_ == 0) {
                if (copied > 0) {
                    co_return copied;
                }
                std::string line;
                if (!co_await ReadLine(line)) {
                    read_closed_ = true;
                    co_return copied;
                }
                auto chunk_size = ParseChunkSize(line);
                if (!chunk_size) {
                    read_closed_ = true;
                    co_return copied;
                }
                if (*chunk_size == 0) {
                    (void)co_await ConsumeTrailers();
                    read_closed_ = true;
                    co_return copied;
                }
                chunk_remaining_ = *chunk_size;
            }

            const size_t want = std::min(capacity - copied, chunk_remaining_);
            const size_t n = co_await ReadRaw(net::buffer(out + copied, want));
            if (n == 0) {
                read_closed_ = true;
                co_return copied;
            }
            copied += n;
            chunk_remaining_ -= n;

            if (chunk_remaining_ == 0) {
                std::array<uint8_t, 2> crlf{};
                if (!co_await ReadExact(crlf.data(), crlf.size()) ||
                    crlf[0] != '\r' || crlf[1] != '\n') {
                    read_closed_ = true;
                    co_return copied;
                }
                if (copied > 0) {
                    co_return copied;
                }
            }
        }
        co_return copied;
    }

    std::unique_ptr<AsyncStream> inner_;
    buf::MultiBuffer pending_;
    size_t chunk_remaining_ = 0;
    bool read_chunked_ = false;
    bool write_chunked_ = false;
    bool read_closed_ = false;
    bool write_closed_ = false;
    bool closed_ = false;
};

class XHttpPacketUpSession final {
public:
    explicit XHttpPacketUpSession(net::io_context& io_context)
        : io_context_(io_context)
        , input_signal_(io_context) {}

    [[nodiscard]] bool AttachStream(std::unique_ptr<AsyncStream> stream) {
        if (closed_ || input_closed_ || !stream) {
            return false;
        }
        if (!stream_input_.Attach(std::move(stream))) {
            return false;
        }
        Wake();
        return true;
    }

    [[nodiscard]] bool Push(uint64_t seq, buf::MultiBuffer payload) {
        if (closed_ || input_closed_) {
            payload.clear();
            return false;
        }
        if (!packet_queue_.Push(seq, std::move(payload))) {
            Close();
            return false;
        }
        Wake();
        return true;
    }

    void CloseInput() noexcept {
        if (input_closed_) {
            return;
        }
        input_closed_ = true;
        Wake();
    }

    void Close() noexcept {
        if (closed_) {
            return;
        }
        closed_ = true;
        input_closed_ = true;
        packet_queue_.Clear();
        if (auto stream = stream_input_.Take()) {
            stream->Close();
        }
        Wake();
    }

    void CancelPendingOperations() noexcept {
        if (closed_) {
            return;
        }
        read_cancelled_ = true;
        if (auto stream = stream_input_.Snapshot()) {
            stream->Cancel();
        }
        Wake();
    }

    [[nodiscard]] bool AcceptingInput() const noexcept {
        return !closed_ && !input_closed_;
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) {
        auto* out = static_cast<uint8_t*>(buffer.data());
        const size_t capacity = buffer.size();
        if (capacity == 0) {
            co_return 0;
        }

        while (true) {
            ThrowIfReadCancelled();
            if (packet_queue_.HasReady()) {
                const size_t n = packet_queue_.ConsumePrefixTo(
                    std::span<uint8_t>(out, capacity));
                co_return n;
            }
            if (auto stream = stream_input_.Snapshot()) {
                size_t n = 0;
                try {
                    n = co_await stream->AsyncRead(buffer);
                } catch (...) {
                    ThrowIfReadCancelled();
                    throw;
                }
                ThrowIfReadCancelled();
                if (n > 0) {
                    co_return n;
                }
                (void)stream_input_.ReleaseIfCurrent(stream);
                CloseInput();
                co_return 0;
            }
            if (closed_ || input_closed_) {
                co_return 0;
            }
            IoErrorCode ec;
            co_await input_signal_.async_receive(net::redirect_error(net::use_awaitable, ec));
            if (ec && ec != io_error::operation_aborted) {
                co_return 0;
            }
        }
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() {
        while (true) {
            ThrowIfReadCancelled();
            if (packet_queue_.HasReady()) {
                co_return packet_queue_.Pop();
            }
            if (auto stream = stream_input_.Snapshot()) {
                buf::MultiBuffer mb;
                try {
                    mb = co_await stream->ReadMultiBuffer();
                } catch (...) {
                    ThrowIfReadCancelled();
                    throw;
                }
                ThrowIfReadCancelled();
                if (buf::HasData(mb)) {
                    co_return mb;
                }
                (void)stream_input_.ReleaseIfCurrent(stream);
                CloseInput();
                co_return buf::MultiBuffer{};
            }
            if (closed_ || input_closed_) {
                co_return buf::MultiBuffer{};
            }
            IoErrorCode ec;
            co_await input_signal_.async_receive(net::redirect_error(net::use_awaitable, ec));
            if (ec && ec != io_error::operation_aborted) {
                co_return buf::MultiBuffer{};
            }
        }
    }

private:
    void ThrowIfReadCancelled() {
        if (!read_cancelled_) {
            return;
        }
        read_cancelled_ = false;
        throw IoSystemError(
            io_error::operation_aborted,
            "xhttp packet-up read cancelled");
    }

    void Wake() noexcept {
        if (io_context_.stopped()) {
            return;
        }
        (void)input_signal_.try_send(IoErrorCode{});
    }

    net::io_context& io_context_;
    net::experimental::channel<void(IoErrorCode)> input_signal_;
    detail::XHttpPacketQueue packet_queue_;
    detail::XHttpUploadStreamSlot stream_input_;
    bool input_closed_ = false;
    bool closed_ = false;
    bool read_cancelled_ = false;
};

[[nodiscard]] std::string_view ExpectedHttpHost(const HttpConfig& cfg) {
    if (!cfg.host.empty()) {
        return cfg.host;
    }
    return FindConfiguredHost(cfg.headers);
}

struct XHttpRequestMeta {
    enum class Kind {
        Unknown,
        StreamOne,
        PacketDown,
        PacketUp,
        StreamUp,
    };

    Kind kind = Kind::Unknown;
    std::string session_id;
    uint64_t seq = 0;
};

[[nodiscard]] std::optional<uint64_t> ParseU64Decimal(std::string_view value) {
    if (value.empty()) {
        return std::nullopt;
    }
    uint64_t out = 0;
    for (char ch : value) {
        if (ch < '0' || ch > '9') {
            return std::nullopt;
        }
        const uint64_t digit = static_cast<uint64_t>(ch - '0');
        if (out > (std::numeric_limits<uint64_t>::max() - digit) / 10) {
            return std::nullopt;
        }
        out = out * 10 + digit;
    }
    return out;
}

[[nodiscard]] std::optional<size_t> ParseContentLength(std::string_view value) {
    value = TrimAscii(value);
    if (value.empty()) {
        return std::nullopt;
    }
    uint64_t out = 0;
    for (char ch : value) {
        if (ch < '0' || ch > '9') {
            return std::nullopt;
        }
        const uint64_t digit = static_cast<uint64_t>(ch - '0');
        if (out > (std::numeric_limits<size_t>::max() - digit) / 10) {
            return std::nullopt;
        }
        out = out * 10 + digit;
    }
    return static_cast<size_t>(out);
}

[[nodiscard]] XHttpRequestMeta ParseXHttpRequestMeta(std::string_view base_path,
                                                     std::string_view request_path,
                                                     std::string_view method) {
    XHttpRequestMeta meta;
    const std::string_view actual = PathWithoutQuery(request_path);
    const std::string_view expected = EffectivePath(base_path);
    if (actual == expected) {
        if (EqualsAsciiCI(method, "POST")) {
            meta.kind = XHttpRequestMeta::Kind::StreamOne;
        }
        return meta;
    }
    if (!actual.starts_with(expected)) {
        return meta;
    }

    std::string_view rest = actual.substr(expected.size());
    while (!rest.empty() && rest.front() == '/') {
        rest.remove_prefix(1);
    }
    if (rest.empty()) {
        return meta;
    }

    const size_t slash = rest.find('/');
    if (slash == std::string_view::npos) {
        meta.session_id.assign(rest.data(), rest.size());
        meta.kind = EqualsAsciiCI(method, "GET")
            ? XHttpRequestMeta::Kind::PacketDown
            : XHttpRequestMeta::Kind::StreamUp;
        return meta;
    }

    const std::string_view session = rest.substr(0, slash);
    const std::string_view seq = rest.substr(slash + 1);
    if (session.empty()) {
        return meta;
    }
    auto parsed_seq = ParseU64Decimal(seq);
    if (!parsed_seq) {
        return meta;
    }
    meta.session_id.assign(session.data(), session.size());
    meta.seq = *parsed_seq;
    meta.kind = XHttpRequestMeta::Kind::PacketUp;
    return meta;
}

[[nodiscard]] std::shared_ptr<XHttpPacketUpSession> GetXHttpPacketSession(
    net::io_context& io_context,
    std::string_view session_id,
    bool create) {
    using SessionMap = memory::ThreadLocalUnorderedMap<
        detail::XHttpPacketSessionKey,
        std::weak_ptr<XHttpPacketUpSession>,
        detail::XHttpPacketSessionKeyHash,
        detail::XHttpPacketSessionKeyEq>;
    thread_local SessionMap sessions;

    if (sessions.size() >= kXHttpMaxPacketSessions) {
        for (auto it = sessions.begin(); it != sessions.end();) {
            if (it->second.expired()) {
                it = sessions.erase(it);
            } else {
                ++it;
            }
        }
    }

    const detail::XHttpPacketSessionKeyRef lookup_key{&io_context, session_id};
    auto it = sessions.find(lookup_key);
    if (it != sessions.end()) {
        if (auto session = it->second.lock()) {
            if (session->AcceptingInput()) {
                return session;
            }
        }
        sessions.erase(it);
    }
    if (!create) {
        return nullptr;
    }
    if (sessions.size() >= kXHttpMaxPacketSessions) {
        return nullptr;
    }
    auto session = std::make_shared<XHttpPacketUpSession>(io_context);
    detail::XHttpPacketSessionKey stored_key{
        .owner = &io_context,
        .session_id = {},
    };
    stored_key.session_id.assign(session_id.data(), session_id.size());
    sessions.emplace(std::move(stored_key), session);
    return session;
}

class XHttpPacketUpServerStream final : public AsyncStream {
public:
    XHttpPacketUpServerStream(std::shared_ptr<XHttpPacketUpSession> session,
                              std::unique_ptr<AsyncStream> downlink)
        : session_(std::move(session))
        , downlink_(std::move(downlink)) {}

    ~XHttpPacketUpServerStream() noexcept override {
        Close();
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        if (!session_) {
            co_return 0;
        }
        co_return co_await session_->AsyncRead(buffer);
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (!downlink_) {
            throw IoSystemError(io_error::operation_aborted, "xhttp downlink closed");
        }
        co_return co_await downlink_->AsyncWrite(buffer);
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!session_) {
            co_return buf::MultiBuffer{};
        }
        co_return co_await session_->ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!downlink_) {
            mb.clear();
            throw IoSystemError(io_error::operation_aborted, "xhttp downlink closed");
        }
        co_await downlink_->WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        if (!downlink_) {
            throw IoSystemError(io_error::operation_aborted, "xhttp downlink closed");
        }
        co_await downlink_->WriteBuffers(buffers);
    }

    void ShutdownRead() override {
        if (session_) {
            session_->Close();
        }
    }

    void ShutdownWrite() override {
        if (downlink_) {
            downlink_->ShutdownWrite();
        }
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (downlink_) {
            co_await downlink_->AsyncShutdownWrite();
        }
    }

    void Cancel() noexcept override {
        if (session_) {
            session_->CancelPendingOperations();
        }
        if (downlink_) {
            downlink_->Cancel();
        }
    }

    void Close() override {
        if (closed_) {
            return;
        }
        closed_ = true;
        if (session_) {
            session_->Close();
        }
        if (downlink_) {
            downlink_->Close();
        }
    }

    void CloseAbortive() override {
        if (closed_) {
            return;
        }
        closed_ = true;
        if (session_) {
            session_->Close();
        }
        if (downlink_) {
            downlink_->CloseAbortive();
        }
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

private:
    std::shared_ptr<XHttpPacketUpSession> session_;
    std::unique_ptr<AsyncStream> downlink_;
    bool closed_ = false;
};

namespace {

[[nodiscard]] std::string FormatHexPrefix(std::span<const uint8_t> data, size_t max_bytes = 24) {
    if (data.empty()) {
        return "-";
    }

    const size_t limit = std::min(data.size(), max_bytes);
    std::string out;
    out.reserve(limit * 3 + 8);
    static constexpr char kHex[] = "0123456789abcdef";

    for (size_t i = 0; i < limit; ++i) {
        if (i > 0) out.push_back(' ');
        const uint8_t byte = data[i];
        out.push_back(kHex[(byte >> 4) & 0x0F]);
        out.push_back(kHex[byte & 0x0F]);
    }

    if (data.size() > limit) {
        out.append(" ...");
    }
    return out;
}

constexpr std::string_view kHttp2ClientPreface =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr size_t kHttp2FrameHeaderSize = 9;
constexpr size_t kHttp2MaxFramePayload = 16 * 1024;
constexpr size_t kHttp2MaxHeaderBlockSize = 64 * 1024;
constexpr uint32_t kGrpcInitialWindow = 4 * 1024 * 1024;

enum class H2FrameType : uint8_t {
    DATA = 0x0,
    HEADERS = 0x1,
    PRIORITY = 0x2,
    RST_STREAM = 0x3,
    SETTINGS = 0x4,
    PUSH_PROMISE = 0x5,
    PING = 0x6,
    GOAWAY = 0x7,
    WINDOW_UPDATE = 0x8,
    CONTINUATION = 0x9,
};

struct H2Frame {
    uint32_t length = 0;
    H2FrameType type = H2FrameType::DATA;
    uint8_t flags = 0;
    uint32_t stream_id = 0;
    memory::ByteVector payload;
};

[[nodiscard]] uint32_t ReadU24(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8) |
           static_cast<uint32_t>(p[2]);
}

[[nodiscard]] uint32_t ReadU32(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

void WriteU32(uint8_t* p, uint32_t value) noexcept {
    p[0] = static_cast<uint8_t>(value >> 24);
    p[1] = static_cast<uint8_t>(value >> 16);
    p[2] = static_cast<uint8_t>(value >> 8);
    p[3] = static_cast<uint8_t>(value);
}

net::awaitable<bool> ReadFullFromStream(AsyncStream& stream,
                                        uint8_t* data,
                                        size_t len) {
    size_t done = 0;
    while (done < len) {
        const size_t n = co_await stream.AsyncRead(
            net::buffer(data + done, len - done));
        if (n == 0) {
            co_return false;
        }
        done += n;
    }
    co_return true;
}

net::awaitable<std::optional<H2Frame>> ReadH2Frame(AsyncStream& stream) {
    std::array<uint8_t, kHttp2FrameHeaderSize> header{};
    if (!co_await ReadFullFromStream(stream, header.data(), header.size())) {
        co_return std::nullopt;
    }

    H2Frame frame;
    frame.length = ReadU24(header.data());
    frame.type = static_cast<H2FrameType>(header[3]);
    frame.flags = header[4];
    frame.stream_id = ReadU32(header.data() + 5) & 0x7fff'ffffu;

    if (frame.length > 16 * 1024 * 1024) {
        co_return std::nullopt;
    }
    frame.payload.resize(frame.length);
    if (frame.length > 0 &&
        !co_await ReadFullFromStream(
            stream, frame.payload.data(), frame.payload.size())) {
        co_return std::nullopt;
    }
    co_return frame;
}

net::awaitable<bool> WriteBuffersFullToStream(
    AsyncStream& stream,
    std::span<const net::const_buffer> buffers) {
    co_await stream.WriteBuffers(buffers);
    co_return true;
}

net::awaitable<bool> WriteH2FrameBuffers(
    AsyncStream& stream,
    H2FrameType type,
    uint8_t flags,
    uint32_t stream_id,
    std::span<const net::const_buffer> payloads) {
    size_t payload_len = 0;
    for (const auto& payload : payloads) {
        payload_len += payload.size();
    }
    if (payload_len > 0x00ff'ffffu) {
        co_return false;
    }

    std::array<uint8_t, kHttp2FrameHeaderSize> header{};
    header[0] = static_cast<uint8_t>((payload_len >> 16) & 0xff);
    header[1] = static_cast<uint8_t>((payload_len >> 8) & 0xff);
    header[2] = static_cast<uint8_t>(payload_len & 0xff);
    header[3] = static_cast<uint8_t>(type);
    header[4] = flags;
    WriteU32(header.data() + 5, stream_id & 0x7fff'ffffu);

    std::array<net::const_buffer, 8> all{};
    size_t count = 0;
    all[count++] = net::buffer(header);
    for (const auto& payload : payloads) {
        if (payload.size() > 0) {
            if (count >= all.size()) {
                co_return false;
            }
            all[count++] = payload;
        }
    }
    co_return co_await WriteBuffersFullToStream(
        stream, std::span<const net::const_buffer>(all.data(), count));
}

net::awaitable<bool> WriteH2Frame(
    AsyncStream& stream,
    H2FrameType type,
    uint8_t flags,
    uint32_t stream_id,
    std::span<const uint8_t> payload = {}) {
    std::array<net::const_buffer, 1> buffers{
        net::buffer(payload.data(), payload.size())
    };
    co_return co_await WriteH2FrameBuffers(
        stream,
        type,
        flags,
        stream_id,
        payload.empty()
            ? std::span<const net::const_buffer>{}
            : std::span<const net::const_buffer>(buffers.data(), buffers.size()));
}

void AppendHpackInt(memory::ByteVector& out,
                    uint8_t prefix_bits,
                    uint8_t first_mask,
                    uint32_t value) {
    const uint8_t max_prefix = static_cast<uint8_t>((1u << prefix_bits) - 1u);
    if (value < max_prefix) {
        out.push_back(static_cast<uint8_t>(first_mask | value));
        return;
    }

    out.push_back(static_cast<uint8_t>(first_mask | max_prefix));
    value -= max_prefix;
    while (value >= 128) {
        out.push_back(static_cast<uint8_t>((value & 0x7f) | 0x80));
        value >>= 7;
    }
    out.push_back(static_cast<uint8_t>(value));
}

void AppendHpackString(memory::ByteVector& out, std::string_view value) {
    AppendHpackInt(out, 7, 0, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

void AppendHpackIndexed(memory::ByteVector& out, uint32_t index) {
    AppendHpackInt(out, 7, 0x80, index);
}

void AppendHpackLiteralIndexedName(memory::ByteVector& out,
                                   uint32_t name_index,
                                   std::string_view value) {
    AppendHpackInt(out, 4, 0, name_index);
    AppendHpackString(out, value);
}

void AppendHpackLiteralNewName(memory::ByteVector& out,
                               std::string_view name,
                               std::string_view value) {
    out.push_back(0);
    AppendHpackString(out, name);
    AppendHpackString(out, value);
}

[[nodiscard]] memory::ByteVector EncodeGrpcRequestHeaders(
    std::string_view authority,
    std::string_view path,
    bool tls,
    std::string_view user_agent) {
    memory::ByteVector h;
    h.reserve(128 + authority.size() + path.size() + user_agent.size());
    AppendHpackIndexed(h, 3); // :method: POST
    AppendHpackIndexed(h, tls ? 7 : 6); // :scheme
    AppendHpackLiteralIndexedName(h, 4, path); // :path
    if (!authority.empty()) {
        AppendHpackLiteralIndexedName(h, 1, authority); // :authority
    }
    AppendHpackLiteralIndexedName(h, 31, "application/grpc");
    AppendHpackLiteralNewName(h, "te", "trailers");
    if (!user_agent.empty()) {
        AppendHpackLiteralIndexedName(h, 58, user_agent);
    }
    return h;
}

[[nodiscard]] memory::ByteVector EncodeGrpcResponseHeaders() {
    memory::ByteVector h;
    h.reserve(32);
    AppendHpackIndexed(h, 8); // :status: 200
    AppendHpackLiteralIndexedName(h, 31, "application/grpc");
    return h;
}

[[nodiscard]] memory::ByteVector EncodeGrpcTrailers() {
    memory::ByteVector h;
    h.reserve(24);
    AppendHpackLiteralNewName(h, "grpc-status", "0");
    return h;
}

enum class H2PayloadCodec : uint8_t {
    GrpcHunk,
    RawData,
};

[[nodiscard]] std::string_view EffectiveHttpMethod(std::string_view method) {
    return method.empty() ? std::string_view("PUT") : method;
}

[[nodiscard]] memory::ByteVector EncodeHttpRequestHeaders(
    std::string_view authority,
    std::string_view path,
    bool tls,
    const HttpConfig& cfg) {
    const std::string_view method = EffectiveHttpMethod(cfg.method);
    const std::string_view req_path = EffectivePath(path);
    memory::ByteVector h;
    h.reserve(128 + authority.size() + req_path.size() + method.size() +
              cfg.headers.size() * 32);

    if (method == "GET") {
        AppendHpackIndexed(h, 2); // :method: GET
    } else if (method == "POST") {
        AppendHpackIndexed(h, 3); // :method: POST
    } else {
        AppendHpackLiteralIndexedName(h, 2, method); // :method
    }
    AppendHpackIndexed(h, tls ? 7 : 6); // :scheme
    if (req_path == "/") {
        AppendHpackIndexed(h, 4); // :path: /
    } else {
        AppendHpackLiteralIndexedName(h, 4, req_path); // :path
    }
    if (!authority.empty()) {
        AppendHpackLiteralIndexedName(h, 1, authority); // :authority
    }
    for (const auto& [key, value] : cfg.headers) {
        if (key.empty() || IsHostHeader(key)) {
            continue;
        }
        AppendHpackLiteralNewName(h, key, value);
    }
    return h;
}

[[nodiscard]] memory::ByteVector EncodeHttpResponseHeaders(
    const transport::internet::HttpHeaders& headers) {
    memory::ByteVector h;
    h.reserve(64 + headers.size() * 32);
    AppendHpackIndexed(h, 8); // :status: 200
    AppendHpackLiteralNewName(h, "cache-control", "no-store");
    for (const auto& [key, value] : headers) {
        if (key.empty()) {
            continue;
        }
        AppendHpackLiteralNewName(h, key, value);
    }
    return h;
}

net::awaitable<bool> WriteH2DataPayload(
    AsyncStream& stream,
    uint32_t stream_id,
    std::span<const uint8_t> data,
    bool end_stream = false) {
    if (data.empty()) {
        co_return co_await WriteH2Frame(
            stream,
            H2FrameType::DATA,
            end_stream ? 0x1 : 0,
            stream_id);
    }

    size_t offset = 0;
    while (offset < data.size()) {
        const size_t chunk = std::min(
            data.size() - offset,
            kHttp2MaxFramePayload);
        std::array<net::const_buffer, 1> payload{
            net::buffer(data.data() + offset, chunk)
        };
        const bool last = (offset + chunk) >= data.size();
        if (!co_await WriteH2FrameBuffers(
                stream,
                H2FrameType::DATA,
                (end_stream && last) ? 0x1 : 0,
                stream_id,
                payload)) {
            co_return false;
        }
        offset += chunk;
    }
    co_return true;
}

net::awaitable<bool> WriteH2DataPayloadBuffers(
    AsyncStream& stream,
    uint32_t stream_id,
    std::span<const net::const_buffer> buffers,
    bool end_stream = false) {
    size_t total = 0;
    for (const auto& buffer : buffers) {
        total += buffer.size();
    }
    if (total == 0) {
        if (!end_stream) {
            co_return true;
        }
        co_return co_await WriteH2Frame(
            stream,
            H2FrameType::DATA,
            0x1,
            stream_id);
    }

    size_t buffer_index = 0;
    size_t buffer_offset = 0;
    size_t written = 0;
    while (written < total) {
        std::array<net::const_buffer, 7> payloads{};
        size_t count = 0;
        size_t frame_len = 0;

        while (buffer_index < buffers.size() &&
               frame_len < kHttp2MaxFramePayload &&
               count < payloads.size()) {
            const auto& source = buffers[buffer_index];
            const size_t source_size = source.size();
            if (buffer_offset >= source_size) {
                ++buffer_index;
                buffer_offset = 0;
                continue;
            }

            const auto* data = static_cast<const uint8_t*>(source.data());
            const size_t take = std::min(
                source_size - buffer_offset,
                kHttp2MaxFramePayload - frame_len);
            if (take == 0) {
                break;
            }

            payloads[count++] = net::buffer(data + buffer_offset, take);
            frame_len += take;
            written += take;
            buffer_offset += take;
            if (buffer_offset >= source_size) {
                ++buffer_index;
                buffer_offset = 0;
            }
        }

        if (count == 0) {
            co_return false;
        }

        const bool last = written >= total;
        if (!co_await WriteH2FrameBuffers(
                stream,
                H2FrameType::DATA,
                (end_stream && last) ? 0x1 : 0,
                stream_id,
                std::span<const net::const_buffer>(payloads.data(), count))) {
            co_return false;
        }
    }

    co_return true;
}

size_t WriteProtoVarint(uint8_t* out, uint64_t value) noexcept;

[[noreturn]] void ThrowGrpcStreamError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

net::awaitable<bool> WriteGrpcHunkMessage(
    AsyncStream& stream,
    uint32_t stream_id,
    std::span<const uint8_t> data) {
    std::array<uint8_t, 16> prefix{};
    size_t prefix_len = 0;
    prefix[prefix_len++] = 0;
    const uint64_t hunk_len =
        1 + ((data.size() < 0x80) ? 1 :
             (data.size() < 0x4000) ? 2 :
             (data.size() < 0x20'0000) ? 3 :
             (data.size() < 0x1000'0000) ? 4 : 5) +
        data.size();
    if (hunk_len > 0xffff'ffffull) {
        co_return false;
    }
    WriteU32(prefix.data() + prefix_len, static_cast<uint32_t>(hunk_len));
    prefix_len += 4;
    prefix[prefix_len++] = 0x0a; // Hunk.data field, length-delimited.
    prefix_len += WriteProtoVarint(
        prefix.data() + prefix_len,
        static_cast<uint64_t>(data.size()));

    size_t offset = 0;
    const size_t first_chunk = std::min(
        data.size(),
        kHttp2MaxFramePayload - prefix_len);
    std::array<net::const_buffer, 2> first_buffers{
        net::buffer(prefix.data(), prefix_len),
        net::buffer(data.data(), first_chunk)
    };
    if (!co_await WriteH2FrameBuffers(
            stream,
            H2FrameType::DATA,
            0,
            stream_id,
            std::span<const net::const_buffer>(
                first_buffers.data(),
                first_chunk == 0 ? 1 : 2))) {
        co_return false;
    }
    offset += first_chunk;

    while (offset < data.size()) {
        const size_t chunk = std::min(
            data.size() - offset,
            kHttp2MaxFramePayload);
        std::array<net::const_buffer, 1> chunk_buffer{
            net::buffer(data.data() + offset, chunk)
        };
        if (!co_await WriteH2FrameBuffers(
                stream,
                H2FrameType::DATA,
                0,
                stream_id,
                chunk_buffer)) {
            co_return false;
        }
        offset += chunk;
    }
    co_return true;
}

size_t WriteProtoVarint(uint8_t* out, uint64_t value) noexcept {
    size_t n = 0;
    while (value >= 0x80) {
        out[n++] = static_cast<uint8_t>((value & 0x7f) | 0x80);
        value >>= 7;
    }
    out[n++] = static_cast<uint8_t>(value);
    return n;
}

bool ReadProtoVarint(std::span<const uint8_t> data,
                     size_t& offset,
                     uint64_t& value) noexcept {
    value = 0;
    uint32_t shift = 0;
    while (offset < data.size() && shift < 64) {
        const uint8_t byte = data[offset++];
        value |= static_cast<uint64_t>(byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) {
            return true;
        }
        shift += 7;
    }
    return false;
}

struct GrpcHunkData {
    size_t offset = 0;
    size_t size = 0;
};

[[nodiscard]] std::optional<GrpcHunkData> DecodeGrpcHunkData(
    std::span<const uint8_t> message) {
    size_t offset = 0;
    while (offset < message.size()) {
        uint64_t key = 0;
        if (!ReadProtoVarint(message, offset, key)) {
            return std::nullopt;
        }
        const uint32_t field = static_cast<uint32_t>(key >> 3);
        const uint32_t wire = static_cast<uint32_t>(key & 0x7);
        if (field == 1 && wire == 2) {
            uint64_t len = 0;
            if (!ReadProtoVarint(message, offset, len) ||
                len > message.size() - offset) {
                return std::nullopt;
            }
            return GrpcHunkData{
                .offset = offset,
                .size = static_cast<size_t>(len),
            };
        }

        switch (wire) {
        case 0: {
            uint64_t ignored = 0;
            if (!ReadProtoVarint(message, offset, ignored)) {
                return std::nullopt;
            }
            break;
        }
        case 1:
            if (message.size() - offset < 8) return std::nullopt;
            offset += 8;
            break;
        case 2: {
            uint64_t len = 0;
            if (!ReadProtoVarint(message, offset, len) ||
                len > message.size() - offset) {
                return std::nullopt;
            }
            offset += static_cast<size_t>(len);
            break;
        }
        case 5:
            if (message.size() - offset < 4) return std::nullopt;
            offset += 4;
            break;
        default:
            return std::nullopt;
        }
    }
    return GrpcHunkData{};
}

net::awaitable<void> AcknowledgeH2Settings(AsyncStream& stream) {
    (void)co_await WriteH2Frame(stream, H2FrameType::SETTINGS, 0x1, 0);
}

net::awaitable<void> ReplyH2Ping(AsyncStream& stream, const H2Frame& frame) {
    if (frame.payload.size() == 8 && (frame.flags & 0x1) == 0) {
        (void)co_await WriteH2Frame(
            stream,
            H2FrameType::PING,
            0x1,
            0,
            std::span<const uint8_t>(frame.payload.data(), frame.payload.size()));
    }
}

net::awaitable<void> SendWindowUpdate(AsyncStream& stream,
                                      uint32_t stream_id,
                                      uint32_t increment) {
    if (increment == 0) {
        co_return;
    }
    std::array<uint8_t, 4> payload{};
    WriteU32(payload.data(), increment & 0x7fff'ffffu);
    (void)co_await WriteH2Frame(
        stream,
        H2FrameType::WINDOW_UPDATE,
        0,
        stream_id,
        payload);
}

[[nodiscard]] std::span<const uint8_t> H2DataPayload(const H2Frame& frame) {
    if (frame.payload.empty()) {
        return {};
    }
    size_t start = 0;
    size_t end = frame.payload.size();
    if ((frame.flags & 0x8) != 0) {
        const size_t pad_len = frame.payload[0];
        start = 1;
        if (pad_len > end - start) {
            return {};
        }
        end -= pad_len;
    }
    return std::span<const uint8_t>(
        frame.payload.data() + start,
        end - start);
}

[[nodiscard]] std::optional<std::span<const uint8_t>> H2HeaderBlockPayload(
    const H2Frame& frame) {
    size_t start = 0;
    size_t end = frame.payload.size();
    if ((frame.flags & 0x8) != 0) {
        if (frame.payload.empty()) {
            return std::nullopt;
        }
        const size_t pad_len = frame.payload[0];
        start = 1;
        if (pad_len > end - start) {
            return std::nullopt;
        }
        end -= pad_len;
    }
    if ((frame.flags & 0x20) != 0) {
        if (end - start < 5) {
            return std::nullopt;
        }
        start += 5;
    }
    return std::span<const uint8_t>(
        frame.payload.data() + start,
        end - start);
}

struct HpackHeaderField {
    memory::ThreadLocalString name;
    memory::ThreadLocalString value;
};

class HpackDecoder final {
public:
    using HeaderFields = memory::ThreadLocalVector<HpackHeaderField>;
    using DynamicTable = memory::ThreadLocalDeque<HpackHeaderField>;

    std::optional<HeaderFields> Decode(
        std::span<const uint8_t> block) {
        HeaderFields fields;
        size_t offset = 0;
        while (offset < block.size()) {
            const uint8_t first = block[offset];
            if ((first & 0x80) != 0) {
                auto index = ReadInteger(block, offset, 7);
                if (!index || *index == 0) {
                    return std::nullopt;
                }
                auto field = Indexed(*index);
                if (!field) {
                    return std::nullopt;
                }
                fields.push_back(std::move(*field));
                continue;
            }
            if ((first & 0x40) != 0) {
                auto field = ReadLiteral(block, offset, 6);
                if (!field) {
                    return std::nullopt;
                }
                AddDynamic(*field);
                fields.push_back(std::move(*field));
                continue;
            }
            if ((first & 0x20) != 0) {
                auto size = ReadInteger(block, offset, 5);
                if (!size) {
                    return std::nullopt;
                }
                ResizeDynamic(*size);
                continue;
            }
            auto field = ReadLiteral(block, offset, 4);
            if (!field) {
                return std::nullopt;
            }
            fields.push_back(std::move(*field));
        }
        return fields;
    }

private:
    struct StaticField {
        std::string_view name;
        std::string_view value;
    };

    static constexpr std::array<StaticField, 61> kStaticTable{{
        {":authority", ""},
        {":method", "GET"},
        {":method", "POST"},
        {":path", "/"},
        {":path", "/index.html"},
        {":scheme", "http"},
        {":scheme", "https"},
        {":status", "200"},
        {":status", "204"},
        {":status", "206"},
        {":status", "304"},
        {":status", "400"},
        {":status", "404"},
        {":status", "500"},
        {"accept-charset", ""},
        {"accept-encoding", "gzip, deflate"},
        {"accept-language", ""},
        {"accept-ranges", ""},
        {"accept", ""},
        {"access-control-allow-origin", ""},
        {"age", ""},
        {"allow", ""},
        {"authorization", ""},
        {"cache-control", ""},
        {"content-disposition", ""},
        {"content-encoding", ""},
        {"content-language", ""},
        {"content-length", ""},
        {"content-location", ""},
        {"content-range", ""},
        {"content-type", ""},
        {"cookie", ""},
        {"date", ""},
        {"etag", ""},
        {"expect", ""},
        {"expires", ""},
        {"from", ""},
        {"host", ""},
        {"if-match", ""},
        {"if-modified-since", ""},
        {"if-none-match", ""},
        {"if-range", ""},
        {"if-unmodified-since", ""},
        {"last-modified", ""},
        {"link", ""},
        {"location", ""},
        {"max-forwards", ""},
        {"proxy-authenticate", ""},
        {"proxy-authorization", ""},
        {"range", ""},
        {"referer", ""},
        {"refresh", ""},
        {"retry-after", ""},
        {"server", ""},
        {"set-cookie", ""},
        {"strict-transport-security", ""},
        {"transfer-encoding", ""},
        {"user-agent", ""},
        {"vary", ""},
        {"via", ""},
        {"www-authenticate", ""},
    }};

    static constexpr std::array<uint32_t, 256> kHpackHuffmanCodes{{
        0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
        0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
        0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
        0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
        0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
        0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
        0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
        0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
        0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
        0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
        0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22,
        0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26,
        0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7,
        0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78,
        0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
        0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
        0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
        0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
        0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
        0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
        0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
        0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
        0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
        0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
        0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
        0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
        0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
        0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
        0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
        0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
        0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
    }};

    static constexpr std::array<uint8_t, 256> kHpackHuffmanCodeLen{{
        13, 23, 28, 28, 28, 28, 28, 28,
        28, 24, 30, 28, 28, 30, 28, 28,
        28, 28, 28, 28, 28, 28, 30, 28,
        28, 28, 28, 28, 28, 28, 28, 28,
        6, 10, 10, 12, 13, 6, 8, 11,
        10, 10, 8, 11, 8, 6, 6, 6,
        5, 5, 5, 6, 6, 6, 6, 6,
        6, 6, 7, 8, 15, 6, 12, 10,
        13, 6, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7,
        8, 7, 8, 13, 19, 13, 14, 6,
        15, 5, 6, 5, 6, 5, 6, 6,
        6, 5, 7, 7, 6, 6, 6, 5,
        6, 7, 6, 5, 5, 6, 7, 7,
        7, 7, 7, 15, 11, 14, 13, 28,
        20, 22, 20, 20, 22, 22, 22, 23,
        22, 23, 23, 23, 23, 23, 24, 23,
        24, 24, 22, 23, 24, 23, 23, 23,
        23, 21, 22, 23, 22, 23, 23, 24,
        22, 21, 20, 22, 22, 23, 23, 21,
        23, 22, 22, 24, 21, 22, 23, 23,
        21, 21, 22, 21, 23, 22, 23, 23,
        20, 22, 22, 22, 23, 22, 22, 23,
        26, 26, 20, 19, 22, 23, 22, 25,
        26, 26, 26, 27, 27, 26, 24, 25,
        19, 21, 26, 27, 27, 26, 27, 24,
        21, 21, 26, 26, 28, 27, 27, 27,
        20, 24, 20, 21, 22, 21, 21, 23,
        22, 22, 25, 25, 24, 24, 26, 23,
        26, 27, 26, 26, 27, 27, 27, 27,
        27, 28, 27, 27, 27, 27, 27, 26,
    }};

    static std::optional<uint32_t> ReadInteger(std::span<const uint8_t> block,
                                               size_t& offset,
                                               uint8_t prefix_bits) {
        if (offset >= block.size() || prefix_bits == 0 || prefix_bits > 8) {
            return std::nullopt;
        }
        const uint8_t mask = static_cast<uint8_t>((1u << prefix_bits) - 1u);
        uint32_t value = block[offset++] & mask;
        if (value < mask) {
            return value;
        }
        uint32_t shift = 0;
        while (offset < block.size() && shift <= 28) {
            const uint8_t byte = block[offset++];
            const uint32_t add = static_cast<uint32_t>(byte & 0x7f) << shift;
            if (value > std::numeric_limits<uint32_t>::max() - add) {
                return std::nullopt;
            }
            value += add;
            if ((byte & 0x80) == 0) {
                return value;
            }
            shift += 7;
        }
        return std::nullopt;
    }

    static std::optional<memory::ThreadLocalString> DecodeHuffman(
        std::span<const uint8_t> data) {
        memory::ThreadLocalString out;
        out.reserve(data.size());
        uint32_t code = 0;
        uint8_t bits = 0;
        for (uint8_t byte : data) {
            for (int bit = 7; bit >= 0; --bit) {
                code = (code << 1) | ((byte >> bit) & 0x1u);
                ++bits;
                bool matched = false;
                for (size_t sym = 0; sym < kHpackHuffmanCodes.size(); ++sym) {
                    if (kHpackHuffmanCodeLen[sym] == bits &&
                        kHpackHuffmanCodes[sym] == code) {
                        out.push_back(static_cast<char>(sym));
                        code = 0;
                        bits = 0;
                        matched = true;
                        break;
                    }
                }
                (void)matched;
            }
        }
        if (bits > 7) {
            return std::nullopt;
        }
        if (bits > 0 && code != ((1u << bits) - 1u)) {
            return std::nullopt;
        }
        return out;
    }

    static std::optional<memory::ThreadLocalString> ReadString(
        std::span<const uint8_t> block,
        size_t& offset) {
        if (offset >= block.size()) {
            return std::nullopt;
        }
        const bool huffman = (block[offset] & 0x80) != 0;
        auto len = ReadInteger(block, offset, 7);
        if (!len || *len > block.size() - offset) {
            return std::nullopt;
        }
        std::span<const uint8_t> encoded(block.data() + offset, *len);
        offset += *len;
        if (huffman) {
            return DecodeHuffman(encoded);
        }
        memory::ThreadLocalString value(
            unsafe::ptr_cast<const char>(encoded.data()),
            encoded.size());
        return value;
    }

    std::optional<HpackHeaderField> Indexed(uint32_t index) const {
        if (index == 0) {
            return std::nullopt;
        }
        if (index <= kStaticTable.size()) {
            const auto& field = kStaticTable[index - 1];
            return HpackHeaderField{
                memory::ThreadLocalString(field.name.data(), field.name.size()),
                memory::ThreadLocalString(field.value.data(), field.value.size()),
            };
        }
        const uint32_t dynamic_index =
            index - static_cast<uint32_t>(kStaticTable.size()) - 1;
        if (dynamic_index >= dynamic_table_.size()) {
            return std::nullopt;
        }
        return dynamic_table_[dynamic_index];
    }

    std::optional<memory::ThreadLocalString> IndexedName(uint32_t index) const {
        auto field = Indexed(index);
        if (!field) {
            return std::nullopt;
        }
        return std::move(field->name);
    }

    std::optional<HpackHeaderField> ReadLiteral(std::span<const uint8_t> block,
                                                size_t& offset,
                                                uint8_t prefix_bits) const {
        auto name_index = ReadInteger(block, offset, prefix_bits);
        if (!name_index) {
            return std::nullopt;
        }
        memory::ThreadLocalString name;
        if (*name_index == 0) {
            auto decoded = ReadString(block, offset);
            if (!decoded) {
                return std::nullopt;
            }
            name = std::move(*decoded);
        } else {
            auto decoded = IndexedName(*name_index);
            if (!decoded) {
                return std::nullopt;
            }
            name = std::move(*decoded);
        }
        auto value = ReadString(block, offset);
        if (!value) {
            return std::nullopt;
        }
        return HpackHeaderField{std::move(name), std::move(*value)};
    }

    void AddDynamic(const HpackHeaderField& field) {
        const size_t entry_size = field.name.size() + field.value.size() + 32;
        if (entry_size > dynamic_max_size_) {
            dynamic_table_.clear();
            dynamic_size_ = 0;
            return;
        }
        dynamic_table_.push_front(field);
        dynamic_size_ += entry_size;
        EvictDynamic();
    }

    void ResizeDynamic(uint32_t size) {
        dynamic_max_size_ = size;
        EvictDynamic();
    }

    void EvictDynamic() {
        while (dynamic_size_ > dynamic_max_size_ && !dynamic_table_.empty()) {
            const auto& field = dynamic_table_.back();
            dynamic_size_ -= field.name.size() + field.value.size() + 32;
            dynamic_table_.pop_back();
        }
    }

    DynamicTable dynamic_table_;
    size_t dynamic_size_ = 0;
    size_t dynamic_max_size_ = 4096;
};

struct H2RequestHeaders {
    memory::ThreadLocalString method;
    memory::ThreadLocalString path;
    memory::ThreadLocalString authority;
};

[[nodiscard]] std::optional<H2RequestHeaders> DecodeH2RequestHeaders(
    HpackDecoder& decoder,
    std::span<const uint8_t> block) {
    auto fields = decoder.Decode(block);
    if (!fields) {
        return std::nullopt;
    }
    H2RequestHeaders request;
    for (const auto& field : *fields) {
        if (field.name == ":method") {
            request.method = field.value;
        } else if (field.name == ":path") {
            request.path = field.value;
        } else if (field.name == ":authority" || field.name == "host") {
            request.authority = field.value;
        }
    }
    if (request.method.empty() || request.path.empty()) {
        return std::nullopt;
    }
    return request;
}

class GrpcStream final : public AsyncStream {
public:
    enum class Role {
        Client,
        Server,
    };

    GrpcStream(std::unique_ptr<AsyncStream> inner,
               uint32_t stream_id,
               Role role,
               H2PayloadCodec payload_codec,
               uint64_t conn_id)
        : inner_(std::move(inner))
        , stream_id_(stream_id)
        , role_(role)
        , payload_codec_(payload_codec)
        , conn_id_(conn_id) {}

    ~GrpcStream() noexcept override {
        Close();
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        auto* out = static_cast<uint8_t*>(buffer.data());
        const size_t capacity = buffer.size();
        if (capacity == 0) {
            co_return 0;
        }

        if (payload_codec_ == H2PayloadCodec::RawData) {
            while (h2_data_offset_ >= h2_data_end_) {
                h2_data_.clear();
                h2_data_offset_ = 0;
                h2_data_end_ = 0;
                if (!co_await ReadNextDataFrame()) {
                    co_return 0;
                }
            }
            const size_t n = std::min(capacity, h2_data_end_ - h2_data_offset_);
            std::memcpy(out, h2_data_.data() + h2_data_offset_, n);
            h2_data_offset_ += n;
            if (h2_data_offset_ >= h2_data_end_) {
                h2_data_.clear();
                h2_data_offset_ = 0;
                h2_data_end_ = 0;
            }
            co_return n;
        }

        while (read_offset_ >= read_payload_end_) {
            if (!co_await ReadNextGrpcMessage()) {
                co_return 0;
            }
        }

        const size_t n = std::min(capacity, read_payload_end_ - read_offset_);
        std::memcpy(out, read_payload_.data() + read_offset_, n);
        read_offset_ += n;
        if (read_offset_ >= read_payload_end_) {
            read_payload_.clear();
            read_offset_ = 0;
            read_payload_end_ = 0;
        }
        co_return n;
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (write_closed_) {
            ThrowGrpcStreamError("gRPC write on closed stream");
        }
        const auto* data = static_cast<const uint8_t*>(buffer.data());
        const size_t len = buffer.size();
        if (payload_codec_ == H2PayloadCodec::RawData) {
            if (!co_await WriteH2DataPayload(
                    *inner_,
                    stream_id_,
                    std::span<const uint8_t>(data, len))) {
                ThrowGrpcStreamError("HTTP/2 raw write failed");
            }
            co_return len;
        }
        if (!co_await WriteGrpcMessage(std::span<const uint8_t>(data, len))) {
            ThrowGrpcStreamError("gRPC write failed");
        }
        co_return len;
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) {
            throw std::bad_alloc();
        }
        size_t n = co_await AsyncRead(
            net::buffer(buffer->Tail().data(), buffer->Available()));
        if (n == 0) {
            co_return buf::MultiBuffer{};
        }
        buffer->Produce(static_cast<uint32_t>(n));
        buf::MultiBuffer mb;
        mb.push_back(buffer.release());
        co_return mb;
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (payload_codec_ == H2PayloadCodec::RawData) {
            ConstBufferSpanBuilder<16> payloads;
            payloads.AppendMultiBuffer(mb);

            try {
                if (!payloads.empty()) {
                    if (!co_await WriteH2DataPayloadBuffers(
                            *inner_,
                            stream_id_,
                            payloads.Span())) {
                        ThrowGrpcStreamError("HTTP/2 raw WriteMultiBuffer failed");
                    }
                }
            } catch (...) {
                mb.clear();
                throw;
            }

            mb.clear();
            co_return;
        }

        for (buf::Buffer*& buffer : mb) {
            if (!buffer) {
                continue;
            }
            if (!buffer->IsEmpty()) {
                const auto bytes = buffer->Bytes();
                if (!co_await WriteGrpcMessage(bytes)) {
                    mb.FreeSlot(buffer);
                    ThrowGrpcStreamError("gRPC WriteMultiBuffer failed");
                }
            }
            mb.FreeSlot(buffer);
        }
        mb.clear();
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        if (payload_codec_ == H2PayloadCodec::RawData) {
            if (!co_await WriteH2DataPayloadBuffers(
                    *inner_,
                    stream_id_,
                    buffers)) {
                ThrowGrpcStreamError("HTTP/2 raw WriteBuffers failed");
            }
            co_return;
        }

        for (const auto& buffer : buffers) {
            if (buffer.size() == 0) {
                continue;
            }
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            if (!co_await WriteGrpcMessage(
                    std::span<const uint8_t>(data, buffer.size()))) {
                ThrowGrpcStreamError("gRPC WriteBuffers failed");
            }
        }
    }

    void ShutdownRead() override {
        read_closed_ = true;
        read_payload_.clear();
        read_offset_ = 0;
        read_payload_end_ = 0;
        h2_data_.clear();
        h2_data_offset_ = 0;
        h2_data_end_ = 0;
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
        if (payload_codec_ == H2PayloadCodec::RawData) {
            (void)co_await WriteH2DataPayload(*inner_, stream_id_, {}, true);
        } else if (role_ == Role::Server) {
            auto trailers = EncodeGrpcTrailers();
            (void)co_await WriteH2Frame(
                *inner_,
                H2FrameType::HEADERS,
                0x4 | 0x1,
                stream_id_,
                trailers);
        } else {
            (void)co_await WriteH2Frame(
                *inner_,
                H2FrameType::DATA,
                0x1,
                stream_id_);
        }
    }

    void Cancel() noexcept override {
        inner_->Cancel();
    }

    void Close() override {
        if (closed_) {
            return;
        }
        closed_ = true;
        read_payload_.clear();
        read_offset_ = 0;
        read_payload_end_ = 0;
        h2_data_.clear();
        h2_data_offset_ = 0;
        h2_data_end_ = 0;
        inner_->Close();
    }

    void CloseAbortive() override {
        if (closed_) {
            return;
        }
        closed_ = true;
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
    net::awaitable<bool> WriteGrpcMessage(std::span<const uint8_t> data) {
        co_return co_await WriteGrpcHunkMessage(*inner_, stream_id_, data);
    }

    net::awaitable<bool> ReadClientResponseHeaders(H2Frame frame) {
        const bool end_stream = (frame.flags & 0x1) != 0;
        auto first_fragment = H2HeaderBlockPayload(frame);
        if (!first_fragment || first_fragment->size() > kHttp2MaxHeaderBlockSize) {
            ThrowGrpcStreamError("invalid HTTP/2 response header block");
        }

        memory::ByteVector header_block(
            first_fragment->begin(),
            first_fragment->end());
        while ((frame.flags & 0x4) == 0) {
            auto continuation = co_await ReadH2Frame(*inner_);
            if (!continuation ||
                continuation->type != H2FrameType::CONTINUATION ||
                continuation->stream_id != stream_id_ ||
                continuation->payload.size() >
                    kHttp2MaxHeaderBlockSize - header_block.size()) {
                ThrowGrpcStreamError("invalid HTTP/2 response continuation");
            }
            header_block.insert(
                header_block.end(),
                continuation->payload.begin(),
                continuation->payload.end());
            frame = std::move(*continuation);
        }

        auto fields = response_decoder_.Decode(header_block);
        if (!fields) {
            ThrowGrpcStreamError("failed to decode HTTP/2 response headers");
        }
        std::string_view status;
        for (const auto& field : *fields) {
            if (field.name == ":status") {
                status = field.value;
                break;
            }
        }
        if (status.size() != 3 || status.front() != '2') {
            ThrowGrpcStreamError("HTTP/2 server rejected request");
        }
        response_headers_received_ = true;
        co_return end_stream;
    }

    net::awaitable<bool> ReadNextGrpcMessage() {
        if (read_closed_) {
            co_return false;
        }

        std::array<uint8_t, 5> prefix{};
        if (!co_await ReadGrpcBytes(prefix.data(), prefix.size())) {
            co_return false;
        }
        if (prefix[0] != 0) {
            LOG_ACCESS_DEBUG("[gRPC:{}] compressed messages are not supported", conn_id_);
            co_return false;
        }
        const uint32_t len = ReadU32(prefix.data() + 1);
        memory::ByteVector message(len);
        read_offset_ = 0;
        if (len > 0 &&
            !co_await ReadGrpcBytes(message.data(), message.size())) {
            co_return false;
        }

        auto hunk = DecodeGrpcHunkData(message);
        if (!hunk) {
            LOG_ACCESS_DEBUG("[gRPC:{}] invalid Hunk protobuf message", conn_id_);
            co_return false;
        }
        read_payload_ = std::move(message);
        read_offset_ = hunk->offset;
        read_payload_end_ = hunk->offset + hunk->size;
        co_return true;
    }

    net::awaitable<bool> ReadGrpcBytes(uint8_t* out, size_t len) {
        size_t copied = 0;
        while (copied < len) {
            if (h2_data_offset_ >= h2_data_end_) {
                h2_data_.clear();
                h2_data_offset_ = 0;
                h2_data_end_ = 0;
                if (!co_await ReadNextDataFrame()) {
                    co_return false;
                }
                continue;
            }

            const size_t n = std::min(
                len - copied,
                h2_data_end_ - h2_data_offset_);
            std::memcpy(out + copied, h2_data_.data() + h2_data_offset_, n);
            copied += n;
            h2_data_offset_ += n;
        }
        co_return true;
    }

    net::awaitable<bool> ReadNextDataFrame() {
        while (!read_closed_) {
            auto frame = co_await ReadH2Frame(*inner_);
            if (!frame) {
                if (role_ == Role::Client && !response_headers_received_) {
                    ThrowGrpcStreamError("HTTP/2 peer closed before response headers");
                }
                co_return false;
            }

            switch (frame->type) {
            case H2FrameType::SETTINGS:
                if ((frame->flags & 0x1) == 0) {
                    co_await AcknowledgeH2Settings(*inner_);
                }
                break;
            case H2FrameType::PING:
                co_await ReplyH2Ping(*inner_, *frame);
                break;
            case H2FrameType::WINDOW_UPDATE:
            case H2FrameType::PRIORITY:
            case H2FrameType::CONTINUATION:
                break;
            case H2FrameType::HEADERS:
                if (frame->stream_id == stream_id_) {
                    if (role_ == Role::Client && !response_headers_received_) {
                        if (co_await ReadClientResponseHeaders(std::move(*frame))) {
                            read_closed_ = true;
                            co_return false;
                        }
                    } else if ((frame->flags & 0x1) != 0) {
                        read_closed_ = true;
                        co_return false;
                    }
                }
                break;
            case H2FrameType::DATA: {
                if (frame->stream_id != stream_id_) {
                    break;
                }
                if (role_ == Role::Client && !response_headers_received_) {
                    ThrowGrpcStreamError("HTTP/2 DATA arrived before response headers");
                }
                const auto data = H2DataPayload(*frame);
                const size_t data_len = data.size();
                if (data_len > 0) {
                    h2_data_offset_ = static_cast<size_t>(
                        data.data() - frame->payload.data());
                    h2_data_end_ = h2_data_offset_ + data_len;
                    h2_data_ = std::move(frame->payload);
                    co_await SendWindowUpdate(
                        *inner_,
                        0,
                        static_cast<uint32_t>(data_len));
                    co_await SendWindowUpdate(
                        *inner_,
                        stream_id_,
                        static_cast<uint32_t>(data_len));
                    co_return true;
                }
                if ((frame->flags & 0x1) != 0) {
                    read_closed_ = true;
                    co_return false;
                }
                break;
            }
            case H2FrameType::RST_STREAM:
                if (frame->stream_id == stream_id_) {
                    ThrowGrpcStreamError("HTTP/2 stream reset by peer");
                }
                break;
            case H2FrameType::GOAWAY:
                ThrowGrpcStreamError("HTTP/2 connection closed by peer");
            default:
                break;
            }
        }
        co_return false;
    }

    std::unique_ptr<AsyncStream> inner_;
    uint32_t stream_id_ = 1;
    Role role_ = Role::Client;
    H2PayloadCodec payload_codec_ = H2PayloadCodec::GrpcHunk;
    uint64_t conn_id_ = 0;
    HpackDecoder response_decoder_;
    memory::ByteVector h2_data_;
    size_t h2_data_offset_ = 0;
    size_t h2_data_end_ = 0;
    memory::ByteVector read_payload_;
    size_t read_offset_ = 0;
    size_t read_payload_end_ = 0;
    bool read_closed_ = false;
    bool write_closed_ = false;
    bool closed_ = false;
    bool response_headers_received_ = false;
};

class GrpcServerSession;

class GrpcServerSubStreamState final {
public:
    GrpcServerSubStreamState(net::io_context& io_context,
                             std::shared_ptr<GrpcServerSession> session,
                             uint32_t stream_id,
                             H2PayloadCodec payload_codec,
                             uint64_t conn_id);

    [[nodiscard]] uint32_t StreamId() const noexcept {
        return stream_id_;
    }

    [[nodiscard]] std::shared_ptr<GrpcServerSession> LockSession() const noexcept {
        return session_.lock();
    }

    bool PushH2Data(memory::ByteVector data, size_t offset, size_t size);
    void CloseInput();
    void CancelFromSession() noexcept;
    void CancelPendingOperations() noexcept;
    void CloseLocal() noexcept;
    void ShutdownRead() noexcept;
    void ShutdownWrite() noexcept;

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer);
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer);
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer();
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb);
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers);
    net::awaitable<void> AsyncShutdownWrite();

private:
    void WakeInputReader() noexcept {
        if (io_context_.stopped()) {
            return;
        }
        (void)input_signal_.try_send(IoErrorCode{});
    }

    net::awaitable<bool> ReadNextGrpcMessage();
    net::awaitable<bool> ReadGrpcBytes(uint8_t* out, size_t len);
    net::awaitable<size_t> AsyncReadRaw(net::mutable_buffer buffer);
    void MarkQueueForShrinkIfLarge() noexcept;
    void ShrinkQueueIfDrained() noexcept;
    void ClearH2Queue() noexcept;

    net::io_context& io_context_;
    net::experimental::channel<void(IoErrorCode)> input_signal_;
    std::weak_ptr<GrpcServerSession> session_;
    uint32_t stream_id_ = 0;
    H2PayloadCodec payload_codec_ = H2PayloadCodec::GrpcHunk;
    uint64_t conn_id_ = 0;
    struct QueuedH2Data {
        memory::ByteVector data;
        size_t offset = 0;
        size_t end = 0;

        [[nodiscard]] size_t Size() const noexcept {
            return end > offset ? end - offset : 0;
        }
    };
    memory::ThreadLocalDeque<QueuedH2Data> h2_data_queue_;
    size_t h2_data_offset_ = 0;
    size_t queued_bytes_ = 0;
    bool shrink_h2_queue_on_drain_ = false;
    memory::ByteVector read_payload_;
    size_t read_offset_ = 0;
    size_t read_payload_end_ = 0;
    bool input_done_ = false;
    bool read_cancelled_ = false;
    bool read_closed_ = false;
    bool write_closed_ = false;
    bool trailers_sent_ = false;
    bool closing_local_ = false;
    bool cancelled_ = false;
};

class GrpcServerSubStream final : public AsyncStream {
public:
    explicit GrpcServerSubStream(std::shared_ptr<GrpcServerSubStreamState> state)
        : state_(std::move(state)) {}

    ~GrpcServerSubStream() noexcept override {
        Close();
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        if (!state_) {
            co_return 0;
        }
        co_return co_await state_->AsyncRead(buffer);
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (!state_) {
            ThrowGrpcStreamError("gRPC write on closed stream");
        }
        co_return co_await state_->AsyncWrite(buffer);
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!state_) {
            co_return buf::MultiBuffer{};
        }
        co_return co_await state_->ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!state_) {
            mb.clear();
            ThrowGrpcStreamError("gRPC WriteMultiBuffer on closed stream");
        }
        co_await state_->WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        if (!state_) {
            ThrowGrpcStreamError("gRPC WriteBuffers on closed stream");
        }
        co_await state_->WriteBuffers(buffers);
    }

    void ShutdownRead() override {
        if (state_) {
            state_->ShutdownRead();
        }
    }

    void ShutdownWrite() override {
        if (state_) {
            state_->ShutdownWrite();
        }
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (state_) {
            co_await state_->AsyncShutdownWrite();
        }
    }

    void Cancel() noexcept override {
        if (state_) {
            state_->CancelPendingOperations();
        }
    }

    void Close() override {
        if (!state_) {
            return;
        }
        state_->CloseLocal();
        state_.reset();
    }

    void CloseAbortive() override {
        Close();
    }

    int NativeHandle() const override;
    bool IsOpen() const override;

protected:
    TcpStream* BaseTcpStream() override;
    const TcpStream* BaseTcpStream() const override;

private:
    std::shared_ptr<GrpcServerSubStreamState> state_;
};

class GrpcServerSession final
    : public std::enable_shared_from_this<GrpcServerSession> {
public:
    GrpcServerSession(net::io_context& io_context,
                      std::unique_ptr<AsyncStream> stream,
                      std::shared_ptr<InboundTransportStreamHandler> stream_handler,
                      H2PayloadCodec payload_codec,
                      transport::internet::HttpHeaders response_headers,
                      uint64_t conn_id,
                      std::optional<HttpConfig> http_config = std::nullopt,
                      std::optional<XHttpConfig> xhttp_config = std::nullopt)
        : io_context_(io_context)
        , stream_(std::move(stream))
        , stream_handler_(std::move(stream_handler))
        , write_gate_(io_context)
        , payload_codec_(payload_codec)
        , response_headers_(std::move(response_headers))
        , http_config_(std::move(http_config))
        , xhttp_config_(std::move(xhttp_config))
        , conn_id_(conn_id) {}

    ~GrpcServerSession() noexcept {
        CancelAll();
    }

    GrpcServerSession(const GrpcServerSession&) = delete;
    GrpcServerSession& operator=(const GrpcServerSession&) = delete;

    [[nodiscard]] AsyncStream* InnerStream() noexcept {
        return stream_.get();
    }

    [[nodiscard]] const AsyncStream* InnerStream() const noexcept {
        return stream_.get();
    }

    std::shared_ptr<GrpcServerSubStreamState> CreateStream(uint32_t stream_id) {
        auto it = streams_.find(stream_id);
        if (it != streams_.end()) {
            return it->second;
        }
        auto sub = std::make_shared<GrpcServerSubStreamState>(
            io_context_,
            shared_from_this(),
            stream_id,
            payload_codec_,
            conn_id_);
        streams_.emplace(stream_id, sub);
        return sub;
    }

    void RemoveStream(uint32_t stream_id) noexcept {
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        auto sub = std::move(it->second);
        streams_.erase(it);
        if (sub) {
            sub->CancelFromSession();
        }
    }

    void CancelAll() noexcept {
        if (cancelled_) {
            return;
        }
        cancelled_ = true;
        write_gate_.Cancel();
        for (auto& [stream_id, sub] : streams_) {
            (void)stream_id;
            if (sub) {
                sub->CancelFromSession();
            }
        }
        streams_.clear();
        if (stream_) {
            stream_->CloseAbortive();
        }
    }

    net::awaitable<bool> WriteFrameSerialized(
        H2FrameType type,
        uint8_t flags,
        uint32_t stream_id,
        std::span<const uint8_t> payload = {}) {
        auto write_lease = co_await write_gate_.Acquire();
        if (!write_lease || cancelled_ || !stream_) {
            co_return false;
        }

        co_return co_await WriteH2Frame(
            *stream_,
            type,
            flags,
            stream_id,
            payload);
    }

    net::awaitable<bool> WriteGrpcMessageSerialized(
        uint32_t stream_id,
        std::span<const uint8_t> data) {
        auto write_lease = co_await write_gate_.Acquire();
        if (!write_lease || cancelled_ || !stream_) {
            co_return false;
        }

        co_return co_await WriteGrpcHunkMessage(*stream_, stream_id, data);
    }

    net::awaitable<bool> WriteRawDataSerialized(
        uint32_t stream_id,
        std::span<const uint8_t> data,
        bool end_stream = false) {
        auto write_lease = co_await write_gate_.Acquire();
        if (!write_lease || cancelled_ || !stream_) {
            co_return false;
        }

        co_return co_await WriteH2DataPayload(
            *stream_,
            stream_id,
            data,
            end_stream);
    }

    net::awaitable<bool> WriteRawDataBuffersSerialized(
        uint32_t stream_id,
        std::span<const net::const_buffer> buffers,
        bool end_stream = false) {
        auto write_lease = co_await write_gate_.Acquire();
        if (!write_lease || cancelled_ || !stream_) {
            co_return false;
        }

        co_return co_await WriteH2DataPayloadBuffers(
            *stream_,
            stream_id,
            buffers,
            end_stream);
    }

    net::awaitable<bool> WriteTrailersSerialized(uint32_t stream_id) {
        auto trailers = EncodeGrpcTrailers();
        co_return co_await WriteFrameSerialized(
            H2FrameType::HEADERS,
            0x4 | 0x1,
            stream_id,
            trailers);
    }

    net::awaitable<bool> WriteRawEndSerialized(uint32_t stream_id) {
        co_return co_await WriteRawDataSerialized(stream_id, {}, true);
    }

    net::awaitable<bool> WriteHttpResponseHeadersSerialized(
        uint32_t stream_id,
        bool end_stream = false) {
        auto response_headers = EncodeHttpResponseHeaders(response_headers_);
        co_return co_await WriteFrameSerialized(
            H2FrameType::HEADERS,
            static_cast<uint8_t>(0x4 | (end_stream ? 0x1 : 0)),
            stream_id,
            response_headers);
    }

    net::awaitable<bool> SendWindowUpdateSerialized(
        uint32_t stream_id,
        uint32_t increment) {
        if (increment == 0) {
            co_return true;
        }
        std::array<uint8_t, 4> payload{};
        WriteU32(payload.data(), increment & 0x7fff'ffffu);
        co_return co_await WriteFrameSerialized(
            H2FrameType::WINDOW_UPDATE,
            0,
            stream_id,
            payload);
    }

    net::awaitable<bool> HandleInitialHeadersFrame(H2Frame frame) {
        co_return co_await HandleHeadersFrame(std::move(frame));
    }

    net::awaitable<void> RunReadLoop() {
        try {
            while (!cancelled_ && stream_) {
                auto frame = co_await ReadH2Frame(*stream_);
                if (!frame) {
                    break;
                }

                switch (frame->type) {
                case H2FrameType::SETTINGS:
                    if ((frame->flags & 0x1) == 0) {
                        (void)co_await WriteFrameSerialized(
                            H2FrameType::SETTINGS,
                            0x1,
                            0);
                    }
                    break;
                case H2FrameType::PING:
                    if (frame->payload.size() == 8 &&
                        (frame->flags & 0x1) == 0) {
                        (void)co_await WriteFrameSerialized(
                            H2FrameType::PING,
                            0x1,
                            0,
                            std::span<const uint8_t>(
                                frame->payload.data(),
                                frame->payload.size()));
                    }
                    break;
                case H2FrameType::HEADERS:
                    if (!co_await HandleHeadersFrame(std::move(*frame))) {
                        CancelAll();
                        co_return;
                    }
                    break;
                case H2FrameType::DATA:
                    co_await HandleDataFrame(std::move(*frame));
                    break;
                case H2FrameType::RST_STREAM:
                    if (frame->stream_id != 0) {
                        RemoveStream(frame->stream_id);
                    }
                    break;
                case H2FrameType::GOAWAY:
                    CancelAll();
                    co_return;
                case H2FrameType::WINDOW_UPDATE:
                case H2FrameType::PRIORITY:
                case H2FrameType::CONTINUATION:
                    break;
                default:
                    break;
                }
            }
        } catch (const std::exception& e) {
            LOG_ACCESS_DEBUG(
                "[gRPC:{}] server: read loop exception: {}",
                conn_id_,
                e.what());
        } catch (...) {
            LOG_ACCESS_DEBUG(
                "[gRPC:{}] server: read loop exception: unknown",
                conn_id_);
        }
        CancelAll();
    }

private:
    net::awaitable<bool> HandleHeadersFrame(H2Frame frame) {
        if (frame.stream_id == 0) {
            co_return false;
        }

        const uint8_t initial_flags = frame.flags;
        const uint32_t stream_id = frame.stream_id;
        auto first_fragment = H2HeaderBlockPayload(frame);
        if (!first_fragment) {
            co_return false;
        }
        memory::ByteVector header_block(
            first_fragment->begin(),
            first_fragment->end());
        while ((frame.flags & 0x4) == 0) {
            auto cont = co_await ReadH2Frame(*stream_);
            if (!cont ||
                cont->type != H2FrameType::CONTINUATION ||
                cont->stream_id != stream_id) {
                co_return false;
            }
            header_block.insert(
                header_block.end(),
                cont->payload.begin(),
                cont->payload.end());
            frame = std::move(*cont);
        }

        if (xhttp_config_ && http_config_ &&
            payload_codec_ == H2PayloadCodec::RawData) {
            co_return co_await HandleXHttpHeadersFrame(
                stream_id,
                initial_flags,
                std::span<const uint8_t>(
                    header_block.data(),
                    header_block.size()));
        }

        auto sub = CreateStream(stream_id);
        if (payload_codec_ == H2PayloadCodec::RawData) {
            if (!co_await WriteHttpResponseHeadersSerialized(stream_id)) {
                co_return false;
            }
        } else {
            auto response_headers = EncodeGrpcResponseHeaders();
            if (!co_await WriteFrameSerialized(
                    H2FrameType::HEADERS,
                    0x4,
                    stream_id,
                    response_headers)) {
                co_return false;
            }
        }

        if ((initial_flags & 0x1) != 0 && sub) {
            sub->CloseInput();
        }

        LOG_ACCESS_DEBUG(
            "[{}:{}] server: accepted logical stream_id={}",
            payload_codec_ == H2PayloadCodec::RawData ? "HTTP/2" : "gRPC",
            conn_id_,
            stream_id);

        auto handler = stream_handler_;
        if (handler && sub) {
            handler->OnInboundTransportStream(
                std::make_unique<GrpcServerSubStream>(std::move(sub)));
        } else if (sub) {
            sub->CloseLocal();
        }
        co_return true;
    }

    net::awaitable<bool> HandleXHttpHeadersFrame(uint32_t stream_id,
                                                 uint8_t initial_flags,
                                                 std::span<const uint8_t> header_block) {
        auto request = DecodeH2RequestHeaders(hpack_decoder_, header_block);
        if (!request) {
            LOG_ACCESS_DEBUG("[XHTTP:{}] server: failed to decode H2 request headers stream_id={}",
                             conn_id_,
                             stream_id);
            co_return false;
        }
        if (const std::string_view expected_host = TrimAscii(ExpectedHttpHost(*http_config_));
            !expected_host.empty() &&
            !EqualsAsciiCI(TrimAscii(request->authority), expected_host)) {
            LOG_ACCESS_DEBUG(
                "[XHTTP:{}] server: H2 host mismatch expected='{}' actual='{}'",
                conn_id_,
                SanitizeForLog(expected_host),
                SanitizeForLog(request->authority));
            co_return false;
        }

        const auto meta = ParseXHttpRequestMeta(
            http_config_->path,
            request->path,
            request->method);
        if (meta.kind == XHttpRequestMeta::Kind::Unknown) {
            LOG_ACCESS_DEBUG("[XHTTP:{}] server: unknown H2 request method='{}' path='{}'",
                             conn_id_,
                             SanitizeForLog(request->method),
                             SanitizeForLog(request->path));
            co_return false;
        }

        if (meta.kind == XHttpRequestMeta::Kind::StreamOne) {
            if (!xhttp_config_->AcceptsStreamOne()) {
                co_return false;
            }
            auto sub = CreateStream(stream_id);
            if (!co_await WriteHttpResponseHeadersSerialized(stream_id)) {
                co_return false;
            }
            if ((initial_flags & 0x1) != 0 && sub) {
                sub->CloseInput();
            }
            LOG_ACCESS_DEBUG("[XHTTP:{}] server: H2 stream-one ready stream_id={}",
                             conn_id_,
                             stream_id);
            auto handler = stream_handler_;
            if (handler && sub) {
                handler->OnInboundTransportStream(
                    std::make_unique<GrpcServerSubStream>(std::move(sub)));
            } else if (sub) {
                sub->CloseLocal();
            }
            co_return true;
        }

        if (meta.kind == XHttpRequestMeta::Kind::PacketDown) {
            if (!xhttp_config_->AcceptsPacketUp() &&
                !xhttp_config_->AcceptsStreamUp()) {
                co_return false;
            }
            auto xsession = GetXHttpPacketSession(
                io_context_,
                meta.session_id,
                true);
            if (!xsession) {
                co_return false;
            }
            auto sub = CreateStream(stream_id);
            if (!co_await WriteHttpResponseHeadersSerialized(stream_id)) {
                co_return false;
            }
            if ((initial_flags & 0x1) != 0 && sub) {
                sub->CloseInput();
            }
            LOG_ACCESS_DEBUG("[XHTTP:{}] server: H2 split downlink ready session={} stream_id={} mode={}",
                             conn_id_,
                             meta.session_id,
                             stream_id,
                             xhttp_config_->AcceptsStreamUp() ? "stream-up" : "packet-up");
            auto handler = stream_handler_;
            if (handler && sub) {
                handler->OnInboundTransportStream(
                    std::make_unique<XHttpPacketUpServerStream>(
                        std::move(xsession),
                        std::make_unique<GrpcServerSubStream>(std::move(sub))));
            } else if (sub) {
                sub->CloseLocal();
            }
            co_return true;
        }

        if (meta.kind == XHttpRequestMeta::Kind::StreamUp) {
            if (!xhttp_config_->AcceptsStreamUp()) {
                co_return false;
            }
            auto xsession = GetXHttpPacketSession(
                io_context_,
                meta.session_id,
                true);
            if (!xsession) {
                co_return false;
            }
            auto sub = CreateStream(stream_id);
            if (!co_await WriteHttpResponseHeadersSerialized(stream_id)) {
                co_return false;
            }
            if ((initial_flags & 0x1) != 0 && sub) {
                sub->CloseInput();
            }
            LOG_ACCESS_DEBUG("[XHTTP:{}] server: H2 stream-up upload ready session={} stream_id={}",
                             conn_id_,
                             meta.session_id,
                             stream_id);
            if (!xsession->AttachStream(
                    std::make_unique<GrpcServerSubStream>(std::move(sub)))) {
                LOG_ACCESS_DEBUG(
                    "[XHTTP:{}] server: rejected concurrent H2 stream-up session={}",
                    conn_id_,
                    meta.session_id);
            }
            co_return true;
        }

        if (meta.kind == XHttpRequestMeta::Kind::PacketUp) {
            if (!xhttp_config_->AcceptsPacketUp()) {
                co_return false;
            }
            auto xsession = GetXHttpPacketSession(
                io_context_,
                meta.session_id,
                false);
            if (!xsession) {
                co_return false;
            }
            auto sub = CreateStream(stream_id);
            if (!co_await WriteHttpResponseHeadersSerialized(stream_id)) {
                co_return false;
            }
            if ((initial_flags & 0x1) != 0 && sub) {
                sub->CloseInput();
            }
            auto upload = std::make_unique<GrpcServerSubStream>(std::move(sub));
            try {
                net::co_spawn(
                    io_context_.get_executor(),
                    [stream = std::move(upload),
                     xsession = std::move(xsession),
                     seq = meta.seq,
                     conn_id = conn_id_]() mutable -> net::awaitable<void> {
                        buf::MultiBuffer payload;
                        try {
                            while (true) {
                                const size_t n = co_await ReadToMultiBufferTail(
                                    *stream,
                                    payload,
                                    buf::Buffer::kSize);
                                if (n == 0) {
                                    break;
                                }
                                if (buf::TotalLen(payload) >
                                    detail::XHttpPacketQueue::kMaxQueuedBytes) {
                                    throw IoSystemError(
                                        io_error::message_size,
                                        "xhttp packet-up payload exceeds queue limit");
                                }
                            }
                            if (!xsession->Push(seq, std::move(payload))) {
                                LOG_ACCESS_DEBUG(
                                    "[XHTTP:{}] server: H2 packet-up queue exhausted seq={}",
                                    conn_id,
                                    seq);
                            }
                        } catch (const std::exception& e) {
                            LOG_ACCESS_DEBUG(
                                "[XHTTP:{}] server: H2 packet-up read failed seq={} error={}",
                                conn_id,
                                seq,
                                e.what());
                        } catch (...) {
                            LOG_ACCESS_DEBUG(
                                "[XHTTP:{}] server: H2 packet-up read failed seq={} error=unknown",
                                conn_id,
                                seq);
                        }
                        stream->Close();
                    },
                    net::detached);
            } catch (...) {
                upload->CloseAbortive();
                co_return false;
            }
            co_return true;
        }

        co_return false;
    }

    net::awaitable<void> HandleDataFrame(H2Frame frame) {
        if (frame.stream_id == 0) {
            co_return;
        }

        const auto data = H2DataPayload(frame);
        const size_t data_len = data.size();
        if (data_len > 0) {
            (void)co_await SendWindowUpdateSerialized(
                0,
                static_cast<uint32_t>(data_len));
            (void)co_await SendWindowUpdateSerialized(
                frame.stream_id,
                static_cast<uint32_t>(data_len));

            auto it = streams_.find(frame.stream_id);
            if (it != streams_.end() && it->second) {
                const size_t data_offset = static_cast<size_t>(
                    data.data() - frame.payload.data());
                const bool queued = it->second->PushH2Data(
                    std::move(frame.payload),
                    data_offset,
                    data_len);
                if (!queued) {
                    RemoveStream(frame.stream_id);
                    (void)co_await WriteFrameSerialized(
                        H2FrameType::RST_STREAM,
                        0,
                        frame.stream_id);
                }
            }
        }

        if ((frame.flags & 0x1) != 0) {
            auto it = streams_.find(frame.stream_id);
            if (it != streams_.end() && it->second) {
                it->second->CloseInput();
            }
        }
    }

    net::io_context& io_context_;
    std::unique_ptr<AsyncStream> stream_;
    std::shared_ptr<InboundTransportStreamHandler> stream_handler_;
    transport::internet::AsyncWriteGate write_gate_;
    memory::ThreadLocalUnorderedMap<uint32_t, std::shared_ptr<GrpcServerSubStreamState>>
        streams_;
    H2PayloadCodec payload_codec_ = H2PayloadCodec::GrpcHunk;
    transport::internet::HttpHeaders response_headers_;
    std::optional<HttpConfig> http_config_;
    std::optional<XHttpConfig> xhttp_config_;
    HpackDecoder hpack_decoder_;
    uint64_t conn_id_ = 0;
    bool cancelled_ = false;
};

GrpcServerSubStreamState::GrpcServerSubStreamState(
    net::io_context& io_context,
    std::shared_ptr<GrpcServerSession> session,
    uint32_t stream_id,
    H2PayloadCodec payload_codec,
    uint64_t conn_id)
    : io_context_(io_context)
    , input_signal_(io_context, 1)
    , session_(std::move(session))
    , stream_id_(stream_id)
    , payload_codec_(payload_codec)
    , conn_id_(conn_id) {}

bool GrpcServerSubStreamState::PushH2Data(
    memory::ByteVector data,
    size_t offset,
    size_t size) {
    if (cancelled_ || input_done_ || size == 0) {
        return !cancelled_;
    }
    if (offset > data.size() || size > data.size() - offset) {
        CancelFromSession();
        return false;
    }
    constexpr size_t kMaxQueuedBytes = 4 * 1024 * 1024;
    if (queued_bytes_ + size > kMaxQueuedBytes) {
        CancelFromSession();
        return false;
    }

    queued_bytes_ += size;
    h2_data_queue_.push_back(QueuedH2Data{
        .data = std::move(data),
        .offset = offset,
        .end = offset + size,
    });
    MarkQueueForShrinkIfLarge();
    WakeInputReader();
    return true;
}

void GrpcServerSubStreamState::CloseInput() {
    if (input_done_) {
        return;
    }
    input_done_ = true;
    WakeInputReader();
}

void GrpcServerSubStreamState::CancelFromSession() noexcept {
    if (cancelled_) {
        return;
    }
    cancelled_ = true;
    input_done_ = true;
    read_closed_ = true;
    write_closed_ = true;
    trailers_sent_ = true;
    closing_local_ = true;
    ClearH2Queue();
    read_payload_.clear();
    read_offset_ = 0;
    read_payload_end_ = 0;
    WakeInputReader();
}

void GrpcServerSubStreamState::CancelPendingOperations() noexcept {
    if (cancelled_) {
        return;
    }
    read_cancelled_ = true;
    WakeInputReader();
}

void GrpcServerSubStreamState::CloseLocal() noexcept {
    if (cancelled_ || closing_local_) {
        return;
    }
    closing_local_ = true;
    input_done_ = true;
    read_closed_ = true;
    ClearH2Queue();
    read_payload_.clear();
    read_offset_ = 0;
    read_payload_end_ = 0;
    WakeInputReader();

    auto session = session_.lock();
    if (!session) {
        CancelFromSession();
        return;
    }

    const uint32_t stream_id = stream_id_;
    if (!trailers_sent_) {
        trailers_sent_ = true;
        write_closed_ = true;
        try {
            net::co_spawn(
                io_context_.get_executor(),
                [session, stream_id, codec = payload_codec_]() -> net::awaitable<void> {
                    struct StreamRemovalGuard final {
                        std::shared_ptr<GrpcServerSession> session;
                        uint32_t stream_id;

                        ~StreamRemovalGuard() noexcept {
                            session->RemoveStream(stream_id);
                        }
                    };
                    StreamRemovalGuard removal_guard{session, stream_id};
                    (void)removal_guard;

                    if (codec == H2PayloadCodec::RawData) {
                        (void)co_await session->WriteRawEndSerialized(stream_id);
                    } else {
                        (void)co_await session->WriteTrailersSerialized(stream_id);
                    }
                },
                net::detached);
        } catch (...) {
            session->RemoveStream(stream_id);
        }
    } else {
        session->RemoveStream(stream_id);
    }
}

void GrpcServerSubStreamState::ShutdownRead() noexcept {
    read_closed_ = true;
    input_done_ = true;
    ClearH2Queue();
    read_payload_.clear();
    read_offset_ = 0;
    read_payload_end_ = 0;
    WakeInputReader();
}

void GrpcServerSubStreamState::ShutdownWrite() noexcept {
    write_closed_ = true;
}

net::awaitable<size_t> GrpcServerSubStreamState::AsyncRead(
    net::mutable_buffer buffer) {
    auto* out = static_cast<uint8_t*>(buffer.data());
    const size_t capacity = buffer.size();
    if (capacity == 0) {
        co_return 0;
    }

    if (payload_codec_ == H2PayloadCodec::RawData) {
        co_return co_await AsyncReadRaw(buffer);
    }

    while (read_offset_ >= read_payload_end_) {
        if (!co_await ReadNextGrpcMessage()) {
            co_return 0;
        }
    }

    const size_t n = std::min(capacity, read_payload_end_ - read_offset_);
    std::memcpy(out, read_payload_.data() + read_offset_, n);
    read_offset_ += n;
    if (read_offset_ >= read_payload_end_) {
        read_payload_.clear();
        read_offset_ = 0;
        read_payload_end_ = 0;
    }
    co_return n;
}

net::awaitable<size_t> GrpcServerSubStreamState::AsyncWrite(
    net::const_buffer buffer) {
    if (write_closed_ || cancelled_) {
        ThrowGrpcStreamError("gRPC write on closed server stream");
    }
    auto session = session_.lock();
    if (!session) {
        ThrowGrpcStreamError("gRPC write without server session");
    }
    const auto* data = static_cast<const uint8_t*>(buffer.data());
    const size_t len = buffer.size();
    if (payload_codec_ == H2PayloadCodec::RawData) {
        if (!co_await session->WriteRawDataSerialized(
                stream_id_,
                std::span<const uint8_t>(data, len))) {
            ThrowGrpcStreamError("HTTP/2 raw server stream write failed");
        }
        co_return len;
    }
    if (!co_await session->WriteGrpcMessageSerialized(
            stream_id_,
            std::span<const uint8_t>(data, len))) {
        ThrowGrpcStreamError("gRPC server stream write failed");
    }
    co_return len;
}

net::awaitable<buf::MultiBuffer> GrpcServerSubStreamState::ReadMultiBuffer() {
    buf::BufferGuard buffer{buf::Buffer::New()};
    if (!buffer) {
        throw std::bad_alloc();
    }
    size_t n = co_await AsyncRead(
        net::buffer(buffer->Tail().data(), buffer->Available()));
    if (n == 0) {
        co_return buf::MultiBuffer{};
    }
    buffer->Produce(static_cast<uint32_t>(n));
    buf::MultiBuffer mb;
    mb.push_back(buffer.release());
    co_return mb;
}

net::awaitable<void> GrpcServerSubStreamState::WriteMultiBuffer(
    buf::MultiBuffer mb) {
    if (payload_codec_ == H2PayloadCodec::RawData) {
        ConstBufferSpanBuilder<16> payloads;
        payloads.AppendMultiBuffer(mb);

        try {
            if (!payloads.empty()) {
                if (write_closed_ || cancelled_) {
                    ThrowGrpcStreamError("gRPC write on closed server stream");
                }
                auto session = session_.lock();
                if (!session) {
                    ThrowGrpcStreamError("gRPC write without server session");
                }
                if (!co_await session->WriteRawDataBuffersSerialized(
                        stream_id_,
                        payloads.Span())) {
                    ThrowGrpcStreamError("HTTP/2 raw server stream WriteMultiBuffer failed");
                }
            }
        } catch (...) {
            mb.clear();
            throw;
        }

        mb.clear();
        co_return;
    }

    for (buf::Buffer*& buffer : mb) {
        if (!buffer) {
            continue;
        }
        if (!buffer->IsEmpty()) {
            const auto bytes = buffer->Bytes();
            const size_t len = bytes.size();
            try {
                (void)co_await AsyncWrite(
                    net::buffer(bytes.data(), bytes.size()));
            } catch (...) {
                mb.FreeSlot(buffer);
                mb.clear();
                throw;
            }
            (void)len;
        }
        mb.FreeSlot(buffer);
    }
    mb.clear();
}

net::awaitable<void> GrpcServerSubStreamState::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    if (payload_codec_ == H2PayloadCodec::RawData) {
        bool has_data = false;
        for (const auto& buffer : buffers) {
            if (buffer.size() > 0) {
                has_data = true;
                break;
            }
        }
        if (!has_data) {
            co_return;
        }
        if (write_closed_ || cancelled_) {
            ThrowGrpcStreamError("gRPC write on closed server stream");
        }
        auto session = session_.lock();
        if (!session) {
            ThrowGrpcStreamError("gRPC write without server session");
        }
        if (!co_await session->WriteRawDataBuffersSerialized(
                stream_id_,
                buffers)) {
            ThrowGrpcStreamError("HTTP/2 raw server stream WriteBuffers failed");
        }
        co_return;
    }

    for (const auto& buffer : buffers) {
        if (buffer.size() == 0) {
            continue;
        }
        (void)co_await AsyncWrite(buffer);
    }
}

net::awaitable<void> GrpcServerSubStreamState::AsyncShutdownWrite() {
    if (trailers_sent_) {
        co_return;
    }
    write_closed_ = true;
    trailers_sent_ = true;
    auto session = session_.lock();
    if (session) {
        if (payload_codec_ == H2PayloadCodec::RawData) {
            (void)co_await session->WriteRawEndSerialized(stream_id_);
        } else {
            (void)co_await session->WriteTrailersSerialized(stream_id_);
        }
    }
}

void GrpcServerSubStreamState::MarkQueueForShrinkIfLarge() noexcept {
    if (h2_data_queue_.size() >= kGrpcServerH2QueueShrinkItems) {
        shrink_h2_queue_on_drain_ = true;
    }
}

void GrpcServerSubStreamState::ShrinkQueueIfDrained() noexcept {
    if (h2_data_queue_.empty() && shrink_h2_queue_on_drain_) {
        TryShrinkSequence(h2_data_queue_);
        shrink_h2_queue_on_drain_ = false;
    }
}

void GrpcServerSubStreamState::ClearH2Queue() noexcept {
    h2_data_queue_.clear();
    queued_bytes_ = 0;
    h2_data_offset_ = 0;
    if (shrink_h2_queue_on_drain_) {
        TryShrinkSequence(h2_data_queue_);
        shrink_h2_queue_on_drain_ = false;
    }
}

net::awaitable<size_t> GrpcServerSubStreamState::AsyncReadRaw(
    net::mutable_buffer buffer) {
    auto* out = static_cast<uint8_t*>(buffer.data());
    const size_t capacity = buffer.size();

    while (!cancelled_) {
        if (read_cancelled_) {
            read_cancelled_ = false;
            throw IoSystemError(io_error::operation_aborted, "HTTP/2 raw read cancelled");
        }

        while (!h2_data_queue_.empty()) {
            const auto& front = h2_data_queue_.front();
            if (h2_data_offset_ < front.offset) {
                h2_data_offset_ = front.offset;
            }
            if (h2_data_offset_ < front.end) {
                break;
            }
            queued_bytes_ -= std::min(queued_bytes_, front.Size());
            h2_data_queue_.pop_front();
            ShrinkQueueIfDrained();
            h2_data_offset_ = 0;
        }

        if (!h2_data_queue_.empty()) {
            const auto& front = h2_data_queue_.front();
            const size_t n = std::min(
                capacity,
                front.end - h2_data_offset_);
            std::memcpy(out, front.data.data() + h2_data_offset_, n);
            h2_data_offset_ += n;
            co_return n;
        }

        if (input_done_ || read_closed_) {
            co_return 0;
        }

        auto [ec] = co_await input_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (ec) {
            co_return 0;
        }
    }
    co_return 0;
}

net::awaitable<bool> GrpcServerSubStreamState::ReadNextGrpcMessage() {
    if (read_closed_ || cancelled_) {
        co_return false;
    }

    std::array<uint8_t, 5> prefix{};
    if (!co_await ReadGrpcBytes(prefix.data(), prefix.size())) {
        co_return false;
    }
    if (prefix[0] != 0) {
        LOG_ACCESS_DEBUG(
            "[gRPC:{}] server: compressed messages are not supported",
            conn_id_);
        co_return false;
    }
    const uint32_t len = ReadU32(prefix.data() + 1);
    memory::ByteVector message(len);
    read_offset_ = 0;
    if (len > 0 &&
        !co_await ReadGrpcBytes(message.data(), message.size())) {
        co_return false;
    }

    auto hunk = DecodeGrpcHunkData(message);
    if (!hunk) {
        LOG_ACCESS_DEBUG(
            "[gRPC:{}] server: invalid Hunk protobuf message",
            conn_id_);
        co_return false;
    }
    read_payload_ = std::move(message);
    read_offset_ = hunk->offset;
    read_payload_end_ = hunk->offset + hunk->size;
    co_return true;
}

net::awaitable<bool> GrpcServerSubStreamState::ReadGrpcBytes(
    uint8_t* out,
    size_t len) {
    size_t copied = 0;
    while (copied < len && !cancelled_) {
        if (read_cancelled_) {
            read_cancelled_ = false;
            throw IoSystemError(io_error::operation_aborted, "gRPC read cancelled");
        }

        while (!h2_data_queue_.empty()) {
            const auto& front = h2_data_queue_.front();
            if (h2_data_offset_ < front.offset) {
                h2_data_offset_ = front.offset;
            }
            if (h2_data_offset_ < front.end) {
                break;
            }
            queued_bytes_ -= std::min(queued_bytes_, front.Size());
            h2_data_queue_.pop_front();
            ShrinkQueueIfDrained();
            h2_data_offset_ = 0;
        }

        if (!h2_data_queue_.empty()) {
            const auto& front = h2_data_queue_.front();
            const size_t n = std::min(
                len - copied,
                front.end - h2_data_offset_);
            std::memcpy(out + copied, front.data.data() + h2_data_offset_, n);
            copied += n;
            h2_data_offset_ += n;
            continue;
        }

        if (input_done_ || read_closed_) {
            co_return false;
        }

        auto [ec] = co_await input_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (ec) {
            co_return false;
        }
    }
    if (read_cancelled_) {
        read_cancelled_ = false;
        throw IoSystemError(io_error::operation_aborted, "gRPC read cancelled");
    }
    co_return copied == len;
}

int GrpcServerSubStream::NativeHandle() const {
    if (!state_) {
        return -1;
    }
    auto session = state_->LockSession();
    auto* inner = session ? session->InnerStream() : nullptr;
    return inner ? inner->NativeHandle() : -1;
}

bool GrpcServerSubStream::IsOpen() const {
    if (!state_) {
        return false;
    }
    auto session = state_->LockSession();
    auto* inner = session ? session->InnerStream() : nullptr;
    return inner && inner->IsOpen();
}

TcpStream* GrpcServerSubStream::BaseTcpStream() {
    if (!state_) {
        return nullptr;
    }
    auto session = state_->LockSession();
    auto* inner = session ? session->InnerStream() : nullptr;
    return inner ? BaseTcpStreamOf(*inner) : nullptr;
}

const TcpStream* GrpcServerSubStream::BaseTcpStream() const {
    if (!state_) {
        return nullptr;
    }
    auto session = state_->LockSession();
    const auto* inner = session ? session->InnerStream() : nullptr;
    return inner ? BaseTcpStreamOf(*inner) : nullptr;
}

[[nodiscard]] uint32_t GrpcInitialWindow(const GrpcConfig& cfg) noexcept {
    return cfg.initial_window_size.value_or(kGrpcInitialWindow);
}

net::awaitable<TransportBuildResult> DoGrpcServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const GrpcConfig& cfg,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id) {
    std::array<uint8_t, 24> preface{};
    if (!co_await ReadFullFromStream(*stream, preface.data(), preface.size()) ||
        std::string_view(unsafe::ptr_cast<const char>(preface.data()), preface.size()) !=
            kHttp2ClientPreface) {
        LOG_ACCESS_DEBUG("[gRPC:{}] server: invalid HTTP/2 client preface", conn_id);
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    auto settings = transport::internet::EncodeInitialWindowSetting(
        GrpcInitialWindow(cfg));
    if (!co_await WriteH2Frame(
            *stream,
            H2FrameType::SETTINGS,
            0,
            0,
            settings)) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    while (true) {
        auto frame = co_await ReadH2Frame(*stream);
        if (!frame) {
            co_return std::unexpected(ErrorCode::SOCKET_EOF);
        }

        switch (frame->type) {
        case H2FrameType::SETTINGS:
            if ((frame->flags & 0x1) == 0) {
                co_await AcknowledgeH2Settings(*stream);
            }
            break;
        case H2FrameType::PING:
            co_await ReplyH2Ping(*stream, *frame);
            break;
        case H2FrameType::HEADERS: {
            if (frame->stream_id == 0) {
                co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            uint32_t stream_id = frame->stream_id;
            while ((frame->flags & 0x4) == 0) {
                auto cont = co_await ReadH2Frame(*stream);
                if (!cont ||
                    cont->type != H2FrameType::CONTINUATION ||
                    cont->stream_id != stream_id) {
                    co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                frame = std::move(cont);
            }

            auto session = std::make_shared<GrpcServerSession>(
                io_context,
                std::move(stream),
                std::move(stream_handler),
                H2PayloadCodec::GrpcHunk,
                transport::internet::HttpHeaders{},
                conn_id);
            auto sub = session->CreateStream(stream_id);
            auto response_headers = EncodeGrpcResponseHeaders();
            if (!co_await session->WriteFrameSerialized(
                    H2FrameType::HEADERS,
                    0x4,
                    stream_id,
                    response_headers)) {
                co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
            }
            if ((frame->flags & 0x1) != 0 && sub) {
                sub->CloseInput();
            }

            LOG_ACCESS_DEBUG(
                "[gRPC:{}] server: handshake ok stream_id={} path={}",
                conn_id,
                stream_id,
                cfg.RequestPath());
            net::co_spawn(
                io_context.get_executor(),
                [session]() -> net::awaitable<void> {
                    co_await session->RunReadLoop();
                },
                net::detached);
            co_return std::unique_ptr<AsyncStream>(
                std::make_unique<GrpcServerSubStream>(std::move(sub)));
        }
        default:
            break;
        }
    }
}

net::awaitable<TransportBuildResult> DoGrpcClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const GrpcConfig& cfg,
    std::string_view authority,
    bool tls,
    uint64_t conn_id) {
    if (!co_await WriteFullToStream(
            *stream,
            unsafe::ptr_cast<const uint8_t>(kHttp2ClientPreface.data()),
            kHttp2ClientPreface.size())) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    auto settings = transport::internet::EncodeInitialWindowSetting(
        GrpcInitialWindow(cfg));
    if (!co_await WriteH2Frame(
            *stream,
            H2FrameType::SETTINGS,
            0,
            0,
            settings)) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    const std::string path = cfg.RequestPath();
    const std::string fallback_ua = "grpc-go/1.0";
    auto headers = EncodeGrpcRequestHeaders(
        authority,
        path,
        tls,
        cfg.user_agent.empty() ? fallback_ua : cfg.user_agent);
    if (!co_await WriteH2Frame(
            *stream,
            H2FrameType::HEADERS,
            0x4,
            1,
            headers)) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    LOG_ACCESS_DEBUG(
        "[gRPC:{}] client: handshake sent authority={} path={}",
        conn_id,
        authority.empty() ? "-" : std::string(authority),
        path);
    co_return std::unique_ptr<AsyncStream>(
        std::make_unique<GrpcStream>(
            std::move(stream),
            1,
            GrpcStream::Role::Client,
        H2PayloadCodec::GrpcHunk,
            conn_id));
}

[[nodiscard]] uint32_t HttpInitialWindow(const HttpConfig& cfg) noexcept {
    return cfg.initial_window_size.value_or(kGrpcInitialWindow);
}

[[nodiscard]] bool HttpPathMatches(std::string_view configured,
                                   std::string_view actual) {
    const std::string_view expected = EffectivePath(configured);
    actual = PathWithoutQuery(actual);
    if (expected == "/") {
        return actual.starts_with("/");
    }
    return actual.starts_with(expected);
}

[[nodiscard]] std::string BuildXHttpResponseHeaders(const HttpConfig& cfg,
                                                    bool chunked_body) {
    std::string response;
    response.reserve(192 + cfg.headers.size() * 32);
    response.append("HTTP/1.1 200 OK\r\n");
    response.append("X-Accel-Buffering: no\r\n");
    response.append("Cache-Control: no-store\r\n");
    response.append("Access-Control-Allow-Origin: *\r\n");
    response.append("Access-Control-Allow-Methods: GET, POST\r\n");
    if (chunked_body) {
        response.append("Transfer-Encoding: chunked\r\n");
    } else {
        response.append("Content-Length: 0\r\n");
    }
    for (const auto& [key, value] : cfg.headers) {
        if (key.empty() ||
            EqualsAsciiCI(key, "Transfer-Encoding") ||
            EqualsAsciiCI(key, "Content-Length")) {
            continue;
        }
        response.append(key);
        response.append(": ");
        response.append(value);
        response.append("\r\n");
    }
    response.append("\r\n");
    return response;
}

net::awaitable<std::optional<buf::MultiBuffer>> ReadXHttpPacketBody(
    Http1BodyStream& body,
    std::optional<size_t> content_length,
    bool chunked) {
    buf::MultiBuffer payload;

    if (content_length) {
        if (*content_length > detail::XHttpPacketQueue::kMaxQueuedBytes) {
            co_return std::nullopt;
        }
        size_t remaining = *content_length;
        while (remaining > 0) {
            const size_t n = co_await ReadToMultiBufferTail(
                body,
                payload,
                std::min(static_cast<size_t>(buf::Buffer::kSize), remaining));
            if (n == 0) {
                co_return std::nullopt;
            }
            remaining -= n;
        }
        co_return payload;
    }

    if (chunked) {
        while (true) {
            const size_t n = co_await ReadToMultiBufferTail(
                body,
                payload,
                buf::Buffer::kSize);
            if (n == 0) {
                break;
            }
            if (buf::TotalLen(payload) >
                detail::XHttpPacketQueue::kMaxQueuedBytes) {
                payload.clear();
                co_return std::nullopt;
            }
        }
    }
    co_return payload;
}

[[nodiscard]] HttpConfig XHttpStreamOneHttpConfig(const XHttpConfig& cfg,
                                                  bool outbound) {
    HttpConfig http;
    http.path = cfg.NormalizedPath();
    http.host = cfg.host;
    http.method = outbound ? "POST" : "";
    http.headers = cfg.headers;
    http.force_http2 = true;
    if (outbound && !cfg.no_grpc_header) {
        bool has_content_type = false;
        for (const auto& [key, _] : http.headers) {
            if (EqualsAsciiCI(key, "Content-Type")) {
                has_content_type = true;
                break;
            }
        }
        if (!has_content_type) {
            http.headers.emplace("content-type", "application/grpc");
        }
    }
    if (outbound) {
        bool has_referer = false;
        for (const auto& [key, _] : http.headers) {
            if (EqualsAsciiCI(key, "Referer")) {
                has_referer = true;
                break;
            }
        }
        if (!has_referer) {
            std::string referer = "https://";
            referer.append(http.host.empty() ? "example.com" : http.host);
            referer.append(http.path.empty() ? "/" : http.path);
            referer.append("?x_padding=");
            referer.append(100, 'X');
            http.headers.emplace("referer", std::move(referer));
        }
    }
    if (!outbound && !cfg.no_sse_header) {
        bool has_content_type = false;
        for (const auto& [key, _] : http.headers) {
            if (EqualsAsciiCI(key, "Content-Type")) {
                has_content_type = true;
                break;
            }
        }
        if (!has_content_type) {
            http.headers.emplace("content-type", "text/event-stream");
        }
    }
    return http;
}

[[nodiscard]] std::string_view ExtractStatusLine(std::string_view response);
[[nodiscard]] bool IsHttpOkStatus(std::string_view status_line);
net::awaitable<TransportBuildResult> DoHttp2ClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    std::string_view authority,
    bool tls,
    uint64_t conn_id);

[[nodiscard]] bool HasHeaderCI(const transport::internet::HttpHeaders& headers,
                               std::string_view key) {
    for (const auto& [name, _] : headers) {
        if (EqualsAsciiCI(name, key)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::string BuildXHttpReferer(std::string_view host,
                                            std::string_view path,
                                            bool tls) {
    std::string referer = tls ? "https://" : "http://";
    referer.append(host.empty() ? "example.com" : host);
    const std::string_view req_path = EffectivePath(path);
    referer.append(req_path);
    referer.push_back(req_path.find('?') == std::string_view::npos ? '?' : '&');
    referer.append("x_padding=");
    referer.append(100, 'X');
    return referer;
}

[[nodiscard]] HttpConfig XHttpClientHttpConfig(const XHttpConfig& cfg,
                                               std::string_view path,
                                               std::string_view method,
                                               bool tls,
                                               XHttpClientRequestKind kind) {
    HttpConfig http;
    http.path.assign(path.data(), path.size());
    http.host = cfg.host;
    http.method.assign(method.data(), method.size());
    http.headers = cfg.headers;
    http.force_http2 = true;
    if (kind == XHttpClientRequestKind::StreamUp &&
        !cfg.no_grpc_header &&
        !HasHeaderCI(http.headers, "Content-Type")) {
        http.headers.emplace("content-type", "application/grpc");
    }
    if (!HasHeaderCI(http.headers, "Referer")) {
        http.headers.emplace("referer", BuildXHttpReferer(http.host, http.path, tls));
    }
    return http;
}

[[nodiscard]] bool ShouldUseHttp2ForXHttp(const StreamSettings& s) {
    if (s.IsReality()) {
        return std::ranges::find(s.tls.alpn, "h2") != s.tls.alpn.end();
    }
    if (!s.IsTlsLike()) {
        return false;
    }
    if (s.tls.alpn.size() == 1 &&
        EqualsAsciiCI(s.tls.alpn.front(), "http/1.1")) {
        return false;
    }
    return true;
}

[[nodiscard]] bool ShouldUseHttp2ForHttp(const StreamSettings& s) {
    if (s.http.force_http2) {
        return true;
    }
    if (!s.IsTlsLike()) {
        return false;
    }
    if (s.tls.alpn.size() == 1 &&
        EqualsAsciiCI(s.tls.alpn.front(), "http/1.1")) {
        return false;
    }
    return true;
}

[[nodiscard]] bool IsHopByHopBodyHeader(std::string_view key) {
    return IsHostHeader(key) ||
           EqualsAsciiCI(key, "Content-Length") ||
           EqualsAsciiCI(key, "Transfer-Encoding");
}

[[nodiscard]] std::string BuildXHttp1ClientRequest(
    const HttpConfig& cfg,
    std::string_view host,
    std::string_view content_length = {},
    bool chunked_upload = false) {
    const std::string_view req_path = EffectivePath(cfg.path);
    const std::string_view method = EffectiveHttpMethod(cfg.method);
    size_t reserve_size = 224 + method.size() + req_path.size() + host.size() +
                          content_length.size() + cfg.headers.size() * 32;

    std::string request;
    request.reserve(reserve_size);
    request.append(method);
    request.push_back(' ');
    request.append(req_path);
    request.append(" HTTP/1.1\r\n");
    request.append("Host: ");
    request.append(host);
    request.append("\r\n");
    if (chunked_upload) {
        request.append("Transfer-Encoding: chunked\r\n");
    } else if (!content_length.empty()) {
        request.append("Content-Length: ");
        request.append(content_length);
        request.append("\r\n");
    }
    for (const auto& [key, value] : cfg.headers) {
        if (key.empty() || IsHopByHopBodyHeader(key)) {
            continue;
        }
        request.append(key);
        request.append(": ");
        request.append(value);
        request.append("\r\n");
    }
    request.append("\r\n");
    return request;
}

net::awaitable<TransportBuildResult> DoXHttp1ClientRequest(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    std::string_view host,
    XHttpClientRequestKind kind,
    std::span<const net::const_buffer> packet_payload,
    uint64_t conn_id) {
    size_t payload_len = 0;
    for (const auto& buffer : packet_payload) {
        payload_len += buffer.size();
    }

    std::array<char, 32> content_length_buf{};
    std::string_view content_length;
    if (kind == XHttpClientRequestKind::PacketUp) {
        auto [ptr, ec] = std::to_chars(
            content_length_buf.data(),
            content_length_buf.data() + content_length_buf.size(),
            payload_len);
        if (ec != std::errc{}) {
            co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
        }
        content_length = std::string_view(
            content_length_buf.data(),
            static_cast<size_t>(ptr - content_length_buf.data()));
    }

    const bool chunked_upload = kind == XHttpClientRequestKind::StreamUp;
    const std::string request = BuildXHttp1ClientRequest(
        cfg,
        host,
        content_length,
        chunked_upload);
    if (kind == XHttpClientRequestKind::StreamUp && payload_len > 0) {
        std::array<char, sizeof(size_t) * 2 + 2> prefix{};
        auto [ptr, ec] = std::to_chars(
            prefix.data(),
            prefix.data() + prefix.size() - 2,
            payload_len,
            16);
        if (ec != std::errc{}) {
            co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
        }
        *ptr++ = '\r';
        *ptr++ = '\n';
        constexpr std::array<char, 2> kChunkTail{'\r', '\n'};

        ConstBufferSpanBuilder<20> out;
        out.Append(net::buffer(request.data(), request.size()));
        out.Append(net::buffer(prefix.data(), static_cast<size_t>(ptr - prefix.data())));
        out.AppendBuffers(packet_payload);
        out.Append(net::buffer(kChunkTail.data(), kChunkTail.size()));

        try {
            co_await stream->WriteBuffers(out.Span());
        } catch (...) {
            co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }

        auto body = std::make_unique<Http1BodyStream>(
            std::move(stream),
            false,
            true);
        LOG_ACCESS_DEBUG("[XHTTP:{}] client: H1 stream-up ready path={} initial={}B",
                         conn_id,
                         EffectivePath(cfg.path),
                         payload_len);
        co_return std::unique_ptr<AsyncStream>(std::move(body));
    }
    if (!co_await WriteFullToStream(
            *stream,
            unsafe::ptr_cast<const uint8_t>(request.data()),
            request.size())) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }
    if (kind == XHttpClientRequestKind::StreamUp) {
        auto body = std::make_unique<Http1BodyStream>(
            std::move(stream),
            false,
            true);
        LOG_ACCESS_DEBUG("[XHTTP:{}] client: H1 stream-up ready path={}",
                         conn_id,
                         EffectivePath(cfg.path));
        co_return std::unique_ptr<AsyncStream>(std::move(body));
    }
    if (kind == XHttpClientRequestKind::PacketUp && payload_len > 0) {
        try {
            co_await stream->WriteBuffers(packet_payload);
        } catch (...) {
            co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }
    }

    buf::BufferGuard response_buf{buf::Buffer::New()};
    if (!response_buf) {
        co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    char* response_data = unsafe::ptr_cast<char>(response_buf->Tail().data());
    const size_t response_capacity = response_buf->Available();
    size_t response_len = 0;
    bool found_end = false;
    size_t header_end = 0;

    while (!found_end && response_len < response_capacity) {
        size_t n = co_await stream->AsyncRead(
            net::buffer(response_data + response_len,
                        response_capacity - response_len));
        if (n == 0) {
            co_return std::unexpected(ErrorCode::SOCKET_EOF);
        }
        response_len += n;
        std::string_view response(response_data, response_len);
        const size_t pos = response.find("\r\n\r\n");
        if (pos != std::string_view::npos) {
            found_end = true;
            header_end = pos + 4;
        }
    }
    if (!found_end) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const std::string_view response(response_data, response_len);
    if (!IsHttpOkStatus(ExtractStatusLine(response))) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (kind == XHttpClientRequestKind::PacketUp) {
        stream->Close();
        co_return std::unique_ptr<AsyncStream>{};
    }

    const bool read_chunked = kind == XHttpClientRequestKind::Downlink &&
        HeaderContainsTokenCI(ExtractHeaderValueCI(response, "Transfer-Encoding"), "chunked");
    auto body = std::make_unique<Http1BodyStream>(
        std::move(stream),
        read_chunked,
        chunked_upload);
    if (header_end < response_len) {
        body->SetPendingData(
            unsafe::ptr_cast<const uint8_t>(response_data + header_end),
            response_len - header_end);
    }
    LOG_ACCESS_DEBUG("[XHTTP:{}] client: H1 {} ready path={}",
                     conn_id,
                     kind == XHttpClientRequestKind::Downlink ? "downlink" : "stream-up",
                     EffectivePath(cfg.path));
    co_return std::unique_ptr<AsyncStream>(std::move(body));
}

net::awaitable<TransportBuildResult> DoXHttp2PacketUpClientRequest(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    std::string_view host,
    bool tls,
    std::span<const net::const_buffer> packet_payload,
    uint64_t conn_id) {
    auto upload = co_await DoHttp2ClientHandshake(
        std::move(stream),
        cfg,
        host,
        tls,
        conn_id);
    if (!upload) {
        co_return std::unexpected(upload.error());
    }
    auto body = std::move(*upload);
    try {
        co_await body->WriteBuffers(packet_payload);
        co_await body->AsyncShutdownWrite();
        std::array<uint8_t, 1> scratch{};
        (void)co_await body->AsyncRead(net::buffer(scratch));
    } catch (...) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }
    body->Close();
    co_return std::unique_ptr<AsyncStream>{};
}

[[nodiscard]] std::string_view ExtractStatusLine(std::string_view response);

[[nodiscard]] bool IsHttpOkStatus(std::string_view status_line) {
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
    return pos + 3 <= status_line.size() &&
           status_line[pos] == '2' &&
           status_line[pos + 1] == '0' &&
           status_line[pos + 2] == '0' &&
           (pos + 3 == status_line.size() || status_line[pos + 3] == ' ');
}

net::awaitable<TransportBuildResult> DoHttp2ServerHandshakeAfterPreface(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id,
    const XHttpConfig* xhttp_config = nullptr) {
    auto settings = transport::internet::EncodeInitialWindowSetting(
        HttpInitialWindow(cfg));
    if (!co_await WriteH2Frame(
            *stream,
            H2FrameType::SETTINGS,
            0,
            0,
            settings)) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    while (true) {
        auto frame = co_await ReadH2Frame(*stream);
        if (!frame) {
            co_return std::unexpected(ErrorCode::SOCKET_EOF);
        }

        switch (frame->type) {
        case H2FrameType::SETTINGS:
            if ((frame->flags & 0x1) == 0) {
                co_await AcknowledgeH2Settings(*stream);
            }
            break;
        case H2FrameType::PING:
            co_await ReplyH2Ping(*stream, *frame);
            break;
        case H2FrameType::HEADERS: {
            if (frame->stream_id == 0) {
                co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            auto session = std::make_shared<GrpcServerSession>(
                io_context,
                std::move(stream),
                std::move(stream_handler),
                H2PayloadCodec::RawData,
                cfg.headers,
                conn_id,
                cfg,
                xhttp_config ? std::optional<XHttpConfig>(*xhttp_config) : std::nullopt);
            if (!co_await session->HandleInitialHeadersFrame(std::move(*frame))) {
                co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            net::co_spawn(
                io_context.get_executor(),
                [session]() -> net::awaitable<void> {
                    co_await session->RunReadLoop();
                },
                net::detached);
            co_return std::unique_ptr<AsyncStream>{};
        }
        default:
            break;
        }
    }
}

net::awaitable<TransportBuildResult> DoXHttp1ServerHandshake(
    net::io_context& io_context,
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    const XHttpConfig& xhttp_cfg,
    uint64_t conn_id,
    std::string* out_real_ip,
    std::span<const uint8_t> initial) {
    buf::BufferGuard handshake_buf{buf::Buffer::New()};
    if (!handshake_buf) {
        co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    uint8_t* data = handshake_buf->Tail().data();
    const size_t capacity = handshake_buf->Available();
    if (initial.size() > capacity) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    std::memcpy(data, initial.data(), initial.size());
    size_t total = initial.size();

    bool found = std::string_view(
        unsafe::ptr_cast<char>(data),
        total).find("\r\n\r\n") != std::string_view::npos;
    while (!found && total < capacity) {
        size_t n = co_await stream->AsyncRead(
            net::buffer(data + total, capacity - total));
        if (n == 0) {
            LOG_ACCESS_DEBUG("[XHTTP:{}] server: peer closed during H1 request read", conn_id);
            co_return std::unexpected(ErrorCode::SOCKET_EOF);
        }
        total += n;
        std::string_view sv(unsafe::ptr_cast<char>(data), total);
        if (sv.find("\r\n\r\n") != std::string_view::npos) {
            found = true;
        }
    }
    if (!found) {
        LOG_ACCESS_DEBUG("[XHTTP:{}] server: H1 request too large or incomplete", conn_id);
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const std::string_view request(unsafe::ptr_cast<char>(data), total);
    const std::string_view request_line = ExtractRequestLine(request);
    const std::string_view method = ExtractRequestMethod(request_line);
    const std::string_view request_path = ExtractRequestPathAny(request_line);
    const std::string_view host = TrimAscii(ExtractHeaderValueCI(request, "Host"));
    const std::string_view transfer_encoding =
        ExtractHeaderValueCI(request, "Transfer-Encoding");
    const std::string_view expect_header =
        ExtractHeaderValueCI(request, "Expect");
    const bool request_chunked = HeaderContainsTokenCI(transfer_encoding, "chunked");
    const auto content_length =
        ParseContentLength(ExtractHeaderValueCI(request, "Content-Length"));
    const auto meta = ParseXHttpRequestMeta(cfg.path, request_path, method);

    LOG_ACCESS_TRACE(
        "[XHTTP:{}] server: H1 request line='{}' method='{}' path='{}' host='{}' bytes={}",
        conn_id,
        SanitizeForLog(request_line),
        SanitizeForLog(method),
        SanitizeForLog(request_path),
        SanitizeForLog(host),
        total);

    if (method.empty() || meta.kind == XHttpRequestMeta::Kind::Unknown) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (const std::string_view expected_host = TrimAscii(ExpectedHttpHost(cfg));
        !expected_host.empty() && !EqualsAsciiCI(host, expected_host)) {
        LOG_ACCESS_DEBUG(
            "[XHTTP:{}] server: host mismatch expected='{}' actual='{}'",
            conn_id,
            SanitizeForLog(expected_host),
            SanitizeForLog(host));
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (out_real_ip && !cfg.real_ip_header.empty()) {
        std::string_view val = ExtractHeaderValueCI(request, cfg.real_ip_header);
        if (!val.empty()) {
            const size_t comma = val.find(',');
            if (comma != std::string_view::npos) {
                val = val.substr(0, comma);
            }
            val = TrimAscii(val);
            if (!val.empty()) {
                *out_real_ip = std::string(val);
            }
        }
    }

    const size_t header_end = request.find("\r\n\r\n") + 4;

    if (meta.kind == XHttpRequestMeta::Kind::PacketDown) {
        if (!xhttp_cfg.AcceptsPacketUp() && !xhttp_cfg.AcceptsStreamUp()) {
            co_return std::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
        }
        auto session = GetXHttpPacketSession(io_context, meta.session_id, true);
        if (!session) {
            co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        }
        const std::string response = BuildXHttpResponseHeaders(cfg, true);
        if (!co_await WriteFullToStream(
                *stream,
                unsafe::ptr_cast<const uint8_t>(response.data()),
                response.size())) {
            co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }

        auto downlink = std::make_unique<Http1BodyStream>(
            std::move(stream),
            false,
            true);
        if (header_end < total) {
            downlink->SetPendingData(data + header_end, total - header_end);
        }
        LOG_ACCESS_DEBUG("[XHTTP:{}] server: split downlink ready session={} mode={}",
                         conn_id,
                         meta.session_id,
                         xhttp_cfg.AcceptsStreamUp() ? "stream-up" : "packet-up");
        co_return std::unique_ptr<AsyncStream>(
            std::make_unique<XHttpPacketUpServerStream>(
                std::move(session),
                std::move(downlink)));
    }

    if (meta.kind == XHttpRequestMeta::Kind::PacketUp) {
        if (!xhttp_cfg.AcceptsPacketUp()) {
            co_return std::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
        }
        auto session = GetXHttpPacketSession(io_context, meta.session_id, false);
        if (!session) {
            co_return std::unexpected(ErrorCode::NOT_FOUND);
        }
        auto body = std::make_unique<Http1BodyStream>(
            std::move(stream),
            request_chunked,
            false);
        if (header_end < total) {
            body->SetPendingData(data + header_end, total - header_end);
        }
        auto payload = co_await ReadXHttpPacketBody(
            *body,
            request_chunked ? std::optional<size_t>{} : content_length,
            request_chunked);
        if (!payload) {
            co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        if (!session->Push(meta.seq, std::move(*payload))) {
            co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        }

        const std::string response = BuildXHttpResponseHeaders(cfg, false);
        if (!co_await WriteFullToStream(
                *body,
                unsafe::ptr_cast<const uint8_t>(response.data()),
                response.size())) {
            co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }
        LOG_ACCESS_TRACE("[XHTTP:{}] server: packet-up payload accepted session={} seq={}",
                         conn_id,
                         meta.session_id,
                         meta.seq);
        co_return std::unique_ptr<AsyncStream>{};
    }

    if (meta.kind == XHttpRequestMeta::Kind::StreamUp) {
        if (!xhttp_cfg.AcceptsStreamUp()) {
            co_return std::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
        }
        auto session = GetXHttpPacketSession(io_context, meta.session_id, true);
        if (!session) {
            co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        }
        if (HeaderContainsTokenCI(expect_header, "100-continue")) {
            constexpr std::string_view continue_response = "HTTP/1.1 100 Continue\r\n\r\n";
            if (!co_await WriteFullToStream(
                    *stream,
                    unsafe::ptr_cast<const uint8_t>(continue_response.data()),
                    continue_response.size())) {
                co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
            }
        }
        // Keep the upload response body open while the VLESS stream reads request chunks.
        const std::string response =
            "HTTP/1.1 200 OK\r\n"
            "X-Accel-Buffering: no\r\n"
            "Cache-Control: no-store\r\n"
            "\r\n";
        if (!co_await WriteFullToStream(
                *stream,
                unsafe::ptr_cast<const uint8_t>(response.data()),
                response.size())) {
            co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }
        auto body = std::make_unique<Http1BodyStream>(
            std::move(stream),
            request_chunked,
            false);
        if (header_end < total) {
            body->SetPendingData(data + header_end, total - header_end);
        }
        LOG_ACCESS_DEBUG("[XHTTP:{}] server: stream-up upload ready session={}",
                         conn_id,
                         meta.session_id);
        if (!session->AttachStream(std::move(body))) {
            co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        }
        co_return std::unique_ptr<AsyncStream>{};
    }

    co_return std::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
}

net::awaitable<TransportBuildResult> DoHttp1ServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    uint64_t conn_id,
    std::string* out_real_ip,
    std::span<const uint8_t> initial) {
    buf::BufferGuard handshake_buf{buf::Buffer::New()};
    if (!handshake_buf) {
        co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    uint8_t* data = handshake_buf->Tail().data();
    const size_t capacity = handshake_buf->Available();
    if (initial.size() > capacity) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    std::memcpy(data, initial.data(), initial.size());
    size_t total = initial.size();

    bool found = std::string_view(
        unsafe::ptr_cast<char>(data),
        total).find("\r\n\r\n") != std::string_view::npos;
    while (!found && total < capacity) {
        size_t n = co_await stream->AsyncRead(
            net::buffer(data + total, capacity - total));
        if (n == 0) {
            LOG_ACCESS_DEBUG("[HTTP:{}] server: peer closed during request read", conn_id);
            co_return std::unexpected(ErrorCode::SOCKET_EOF);
        }
        total += n;
        std::string_view sv(unsafe::ptr_cast<char>(data), total);
        if (sv.find("\r\n\r\n") != std::string_view::npos) {
            found = true;
        }
    }
    if (!found) {
        LOG_ACCESS_DEBUG("[HTTP:{}] server: request too large or incomplete", conn_id);
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const std::string_view request(unsafe::ptr_cast<char>(data), total);
    const std::string_view request_line = ExtractRequestLine(request);
    const std::string_view method = ExtractRequestMethod(request_line);
    const std::string_view request_path = ExtractRequestPathAny(request_line);
    const std::string_view host = TrimAscii(ExtractHeaderValueCI(request, "Host"));
    const std::string_view user_agent = ExtractHeaderValueCI(request, "User-Agent");

    LOG_ACCESS_TRACE(
        "[HTTP:{}] server: request line='{}' method='{}' path='{}' host='{}' ua='{}' bytes={}",
        conn_id,
        SanitizeForLog(request_line),
        SanitizeForLog(method),
        SanitizeForLog(request_path),
        SanitizeForLog(host),
        SanitizeForLog(user_agent),
        total);

    if (method.empty() || !HttpPathMatches(cfg.path, request_path)) {
        LOG_ACCESS_DEBUG(
            "[HTTP:{}] server: path mismatch expected='{}' actual='{}'",
            conn_id,
            EffectivePath(cfg.path),
            SanitizeForLog(request_path));
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (!cfg.method.empty() && !EqualsAsciiCI(method, cfg.method)) {
        LOG_ACCESS_DEBUG(
            "[HTTP:{}] server: method mismatch expected='{}' actual='{}'",
            conn_id,
            cfg.method,
            SanitizeForLog(method));
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (const std::string_view expected_host = TrimAscii(ExpectedHttpHost(cfg));
        !expected_host.empty() && !EqualsAsciiCI(host, expected_host)) {
        LOG_ACCESS_DEBUG(
            "[HTTP:{}] server: host mismatch expected='{}' actual='{}'",
            conn_id,
            SanitizeForLog(expected_host),
            SanitizeForLog(host));
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (out_real_ip && !cfg.real_ip_header.empty()) {
        std::string_view val = ExtractHeaderValueCI(request, cfg.real_ip_header);
        if (!val.empty()) {
            const size_t comma = val.find(',');
            if (comma != std::string_view::npos) {
                val = val.substr(0, comma);
            }
            val = TrimAscii(val);
            if (!val.empty()) {
                *out_real_ip = std::string(val);
            }
        }
    }

    std::string response;
    response.reserve(96 + cfg.headers.size() * 32);
    response.append("HTTP/1.1 200 OK\r\n");
    response.append("Cache-Control: no-store\r\n");
    for (const auto& [key, value] : cfg.headers) {
        if (key.empty()) {
            continue;
        }
        response.append(key);
        response.append(": ");
        response.append(value);
        response.append("\r\n");
    }
    response.append("\r\n");

    if (!co_await WriteFullToStream(
            *stream,
            unsafe::ptr_cast<const uint8_t>(response.data()),
            response.size())) {
        LOG_ACCESS_DEBUG("[HTTP:{}] server: failed to send 200 response", conn_id);
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    const size_t header_end = request.find("\r\n\r\n") + 4;
    auto http = std::make_unique<HttpUpgradeStream>(std::move(stream));
    if (header_end < total) {
        http->SetPendingData(data + header_end, total - header_end);
    }
    LOG_ACCESS_DEBUG("[HTTP:{}] server: handshake ok (path={})",
                     conn_id,
                     EffectivePath(cfg.path));
    co_return std::unique_ptr<AsyncStream>(std::move(http));
}

net::awaitable<TransportBuildResult> DoHttpServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id,
    std::string* out_real_ip,
    bool require_http2 = false,
    const XHttpConfig* xhttp_config = nullptr) {
    std::array<uint8_t, 24> first{};
    size_t total = 0;
    while (total < first.size()) {
        const size_t n = co_await stream->AsyncRead(
            net::buffer(first.data() + total, first.size() - total));
        if (n == 0) {
            co_return std::unexpected(ErrorCode::SOCKET_EOF);
        }
        total += n;
        std::string_view prefix(
            unsafe::ptr_cast<const char>(first.data()),
            total);
        if (!kHttp2ClientPreface.starts_with(prefix)) {
            break;
        }
    }

    if (total == first.size() &&
        std::string_view(unsafe::ptr_cast<const char>(first.data()), first.size()) ==
            kHttp2ClientPreface) {
        co_return co_await DoHttp2ServerHandshakeAfterPreface(
            std::move(stream),
            cfg,
            io_context,
            std::move(stream_handler),
            conn_id,
            xhttp_config);
    }

    if (require_http2) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (xhttp_config) {
        co_return co_await DoXHttp1ServerHandshake(
            io_context,
            std::move(stream),
            cfg,
            *xhttp_config,
            conn_id,
            out_real_ip,
            std::span<const uint8_t>(first.data(), total));
    }

    co_return co_await DoHttp1ServerHandshake(
        std::move(stream),
        cfg,
        conn_id,
        out_real_ip,
        std::span<const uint8_t>(first.data(), total));
}

net::awaitable<TransportBuildResult> DoHttp2ClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    std::string_view authority,
    bool tls,
    uint64_t conn_id) {
    if (!co_await WriteFullToStream(
            *stream,
            unsafe::ptr_cast<const uint8_t>(kHttp2ClientPreface.data()),
            kHttp2ClientPreface.size())) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    auto settings = transport::internet::EncodeInitialWindowSetting(
        HttpInitialWindow(cfg));
    if (!co_await WriteH2Frame(
            *stream,
            H2FrameType::SETTINGS,
            0,
            0,
            settings)) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    auto headers = EncodeHttpRequestHeaders(
        authority,
        cfg.path,
        tls,
        cfg);
    const bool request_body_expected =
        !EqualsAsciiCI(EffectiveHttpMethod(cfg.method), "GET");
    if (!co_await WriteH2Frame(
            *stream,
            H2FrameType::HEADERS,
            static_cast<uint8_t>(0x4 | (request_body_expected ? 0 : 0x1)),
            1,
            headers)) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    LOG_ACCESS_DEBUG(
        "[HTTP/2:{}] client: handshake sent authority={} path={}",
        conn_id,
        authority.empty() ? "-" : std::string(authority),
        EffectivePath(cfg.path));
    co_return std::unique_ptr<AsyncStream>(
        std::make_unique<GrpcStream>(
            std::move(stream),
            1,
            GrpcStream::Role::Client,
            H2PayloadCodec::RawData,
            conn_id));
}

net::awaitable<TransportBuildResult> DoHttp1ClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    std::string_view host,
    uint64_t conn_id) {
    const std::string_view req_path = EffectivePath(cfg.path);
    const std::string_view method = EffectiveHttpMethod(cfg.method);
    size_t reserve_size = 192 + method.size() + req_path.size() + host.size();
    for (const auto& [key, value] : cfg.headers) {
        if (!IsHostHeader(key)) {
            reserve_size += key.size() + value.size() + 4;
        }
    }

    std::string request;
    request.reserve(reserve_size);
    request.append(method);
    request.push_back(' ');
    request.append(req_path);
    request.append(" HTTP/1.1\r\n");
    request.append("Host: ");
    request.append(host);
    request.append("\r\n");
    for (const auto& [key, value] : cfg.headers) {
        if (IsHostHeader(key)) {
            continue;
        }
        request.append(key);
        request.append(": ");
        request.append(value);
        request.append("\r\n");
    }
    request.append("\r\n");

    if (!co_await WriteFullToStream(
            *stream,
            unsafe::ptr_cast<const uint8_t>(request.data()),
            request.size())) {
        LOG_ACCESS_DEBUG("[HTTP:{}] client: failed to send request", conn_id);
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    buf::BufferGuard response_buf{buf::Buffer::New()};
    if (!response_buf) {
        co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    char* response_data = unsafe::ptr_cast<char>(response_buf->Tail().data());
    const size_t response_capacity = response_buf->Available();
    size_t response_len = 0;
    bool found_end = false;
    size_t header_end = 0;

    while (!found_end && response_len < response_capacity) {
        size_t n = co_await stream->AsyncRead(
            net::buffer(response_data + response_len,
                        response_capacity - response_len));
        if (n == 0) {
            LOG_ACCESS_DEBUG("[HTTP:{}] client: peer closed during response read", conn_id);
            co_return std::unexpected(ErrorCode::SOCKET_EOF);
        }
        response_len += n;
        std::string_view response(response_data, response_len);
        const size_t pos = response.find("\r\n\r\n");
        if (pos != std::string_view::npos) {
            found_end = true;
            header_end = pos + 4;
        }
    }

    if (!found_end) {
        LOG_ACCESS_DEBUG("[HTTP:{}] client: incomplete response", conn_id);
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const std::string_view response(response_data, response_len);
    const std::string_view status_line = ExtractStatusLine(response);
    if (!IsHttpOkStatus(status_line)) {
        LOG_ACCESS_DEBUG("[HTTP:{}] client: server rejected request: {}",
                         conn_id,
                         SanitizeForLog(status_line));
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    auto http = std::make_unique<HttpUpgradeStream>(std::move(stream));
    if (header_end < response_len) {
        http->SetPendingData(
            unsafe::ptr_cast<const uint8_t>(response_data + header_end),
            response_len - header_end);
    }
    LOG_ACCESS_DEBUG("[HTTP:{}] client: handshake ok (host={} path={})",
                     conn_id,
                     host,
                     req_path);
    co_return std::unique_ptr<AsyncStream>(std::move(http));
}

net::awaitable<TransportBuildResult> DoHttpUpgradeServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpUpgradeConfig& cfg,
    uint64_t conn_id,
    std::string* out_real_ip) {
    buf::BufferGuard handshake_buf{buf::Buffer::New()};
    if (!handshake_buf) {
        co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    uint8_t* data = handshake_buf->Tail().data();
    const size_t capacity = handshake_buf->Available();
    size_t total = 0;
    bool found = false;

    while (!found && total < capacity) {
        size_t n = co_await stream->AsyncRead(
            net::buffer(data + total, capacity - total));
        if (n == 0) {
            LOG_ACCESS_DEBUG("[HTTPUpgrade:{}] server: peer closed during request read", conn_id);
            co_return std::unexpected(ErrorCode::SOCKET_EOF);
        }
        total += n;
        std::string_view sv(unsafe::ptr_cast<char>(data), total);
        if (sv.find("\r\n\r\n") != std::string_view::npos) {
            found = true;
        }
    }

    if (!found) {
        LOG_ACCESS_DEBUG("[HTTPUpgrade:{}] server: request too large or incomplete", conn_id);
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const std::string_view request(unsafe::ptr_cast<char>(data), total);
    const std::string_view request_line = ExtractRequestLine(request);
    const std::string_view request_path = ExtractRequestPath(request_line);
    const std::string_view host = TrimAscii(ExtractHeaderValueCI(request, "Host"));
    const std::string_view upgrade = TrimAscii(ExtractHeaderValueCI(request, "Upgrade"));
    const std::string_view connection = ExtractHeaderValueCI(request, "Connection");
    const std::string_view user_agent = ExtractHeaderValueCI(request, "User-Agent");

    LOG_ACCESS_TRACE(
        "[HTTPUpgrade:{}] server: request line='{}' path='{}' host='{}' upgrade='{}' connection='{}' ua='{}' bytes={}",
        conn_id,
        SanitizeForLog(request_line),
        SanitizeForLog(request_path),
        SanitizeForLog(host),
        SanitizeForLog(upgrade),
        SanitizeForLog(connection),
        SanitizeForLog(user_agent),
        total);

    if (!request_line.starts_with("GET ") ||
        !RequestPathMatches(cfg.path, request_path)) {
        LOG_ACCESS_DEBUG(
            "[HTTPUpgrade:{}] server: path mismatch expected='{}' actual='{}'",
            conn_id,
            EffectivePath(cfg.path),
            SanitizeForLog(request_path));
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (!EqualsAsciiCI(upgrade, "websocket") ||
        !HeaderContainsTokenCI(connection, "upgrade")) {
        LOG_ACCESS_DEBUG("[HTTPUpgrade:{}] server: invalid upgrade headers", conn_id);
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (const std::string_view expected_host = TrimAscii(ExpectedHttpUpgradeHost(cfg));
        !expected_host.empty() && !EqualsAsciiCI(host, expected_host)) {
        LOG_ACCESS_DEBUG(
            "[HTTPUpgrade:{}] server: host mismatch expected='{}' actual='{}'",
            conn_id,
            SanitizeForLog(expected_host),
            SanitizeForLog(host));
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (out_real_ip && !cfg.real_ip_header.empty()) {
        std::string_view val = ExtractHeaderValueCI(request, cfg.real_ip_header);
        if (!val.empty()) {
            const size_t comma = val.find(',');
            if (comma != std::string_view::npos) {
                val = val.substr(0, comma);
            }
            val = TrimAscii(val);
            if (!val.empty()) {
                *out_real_ip = std::string(val);
            }
        }
    }

    static constexpr std::string_view kResponse =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "\r\n";
    if (!co_await WriteFullToStream(
            *stream,
            unsafe::ptr_cast<const uint8_t>(kResponse.data()),
            kResponse.size())) {
        LOG_ACCESS_DEBUG("[HTTPUpgrade:{}] server: failed to send 101 response", conn_id);
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    auto upgraded = std::make_unique<HttpUpgradeStream>(std::move(stream));
    const size_t header_end = request.find("\r\n\r\n") + 4;
    if (header_end < total) {
        upgraded->SetPendingData(data + header_end, total - header_end);
    }
    LOG_ACCESS_DEBUG("[HTTPUpgrade:{}] server: handshake ok (path={})",
                     conn_id,
                     EffectivePath(cfg.path));
    co_return std::unique_ptr<AsyncStream>(std::move(upgraded));
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
    return pos + 3 <= status_line.size() &&
           status_line[pos] == '1' &&
           status_line[pos + 1] == '0' &&
           status_line[pos + 2] == '1' &&
           (pos + 3 == status_line.size() || status_line[pos + 3] == ' ');
}

net::awaitable<TransportBuildResult> DoHttpUpgradeClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpUpgradeConfig& cfg,
    std::string_view host,
    uint64_t conn_id) {
    const std::string_view req_path = EffectivePath(cfg.path);
    size_t reserve_size = 192 + req_path.size() + host.size();
    for (const auto& [key, value] : cfg.headers) {
        if (!IsHostHeader(key)) {
            reserve_size += key.size() + value.size() + 4;
        }
    }

    std::string request;
    request.reserve(reserve_size);
    request.append("GET ");
    request.append(req_path);
    request.append(" HTTP/1.1\r\n");
    request.append("Host: ");
    request.append(host);
    request.append("\r\n");
    request.append("Upgrade: websocket\r\n");
    request.append("Connection: Upgrade\r\n");
    for (const auto& [key, value] : cfg.headers) {
        if (IsHostHeader(key)) {
            continue;
        }
        request.append(key);
        request.append(": ");
        request.append(value);
        request.append("\r\n");
    }
    request.append("\r\n");

    if (!co_await WriteFullToStream(
            *stream,
            unsafe::ptr_cast<const uint8_t>(request.data()),
            request.size())) {
        LOG_ACCESS_DEBUG("[HTTPUpgrade:{}] client: failed to send request", conn_id);
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    buf::BufferGuard response_buf{buf::Buffer::New()};
    if (!response_buf) {
        co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    char* response_data = unsafe::ptr_cast<char>(response_buf->Tail().data());
    const size_t response_capacity = response_buf->Available();
    size_t response_len = 0;
    bool found_end = false;
    size_t header_end = 0;

    while (!found_end && response_len < response_capacity) {
        size_t n = co_await stream->AsyncRead(
            net::buffer(response_data + response_len,
                        response_capacity - response_len));
        if (n == 0) {
            LOG_ACCESS_DEBUG("[HTTPUpgrade:{}] client: peer closed during response read", conn_id);
            co_return std::unexpected(ErrorCode::SOCKET_EOF);
        }
        response_len += n;
        std::string_view response(response_data, response_len);
        const size_t pos = response.find("\r\n\r\n");
        if (pos != std::string_view::npos) {
            found_end = true;
            header_end = pos + 4;
        }
    }

    if (!found_end) {
        LOG_ACCESS_DEBUG("[HTTPUpgrade:{}] client: incomplete response", conn_id);
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const std::string_view response(response_data, response_len);
    const std::string_view status_line = ExtractStatusLine(response);
    if (!IsSwitchingProtocolsStatus(status_line)) {
        LOG_ACCESS_DEBUG("[HTTPUpgrade:{}] client: server rejected upgrade: {}",
                         conn_id,
                         SanitizeForLog(status_line));
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    auto upgraded = std::make_unique<HttpUpgradeStream>(std::move(stream));
    if (header_end < response_len) {
        upgraded->SetPendingData(
            unsafe::ptr_cast<const uint8_t>(response_data + header_end),
            response_len - header_end);
    }
    LOG_ACCESS_DEBUG("[HTTPUpgrade:{}] client: handshake ok (host={} path={})",
                     conn_id,
                     host,
                     req_path);
    co_return std::unique_ptr<AsyncStream>(std::move(upgraded));
}

// WebSocket 服务端握手（从原始流读 HTTP 请求，回复 101，返回 WsServerStream）
net::awaitable<TransportBuildResult> DoWsServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const WsConfig& ws_cfg,
    uint64_t conn_id,
    std::string* out_real_ip)
{
    buf::BufferGuard handshake_buf{buf::Buffer::New()};
    if (!handshake_buf) {
        co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    uint8_t* data = handshake_buf->Tail().data();
    const size_t capacity = handshake_buf->Available();
    size_t total = 0;

    // 读取直到找到 \r\n\r\n
    bool found = false;
    while (!found && total < capacity) {
        size_t n = co_await stream->AsyncRead(
            net::buffer(data + total, capacity - total));
        if (n == 0) {
            LOG_ACCESS_DEBUG("[WS:{}] server: peer closed during HTTP upgrade read", conn_id);
            std::string_view partial(unsafe::ptr_cast<char>(data), total);
            LOG_ACCESS_TRACE("[WS:{}] server: peer closed during upgrade read bytes={} first_line='{}' prefix_hex={}",
                             conn_id,
                             total,
                             SanitizeForLog(ExtractRequestLine(partial)),
                             FormatHexPrefix(std::span<const uint8_t>(data, total)));
            co_return std::unexpected(ErrorCode::SOCKET_EOF);
        }
        total += n;
        std::string_view sv(unsafe::ptr_cast<char>(data), total);
        if (sv.find("\r\n\r\n") != std::string_view::npos) found = true;
    }
    if (!found) {
        std::string_view partial(unsafe::ptr_cast<char>(data), total);
        LOG_ACCESS_DEBUG("[WS:{}] server: HTTP upgrade request too large or incomplete", conn_id);
        LOG_ACCESS_TRACE("[WS:{}] server: incomplete upgrade bytes={} first_line='{}'",
                         conn_id,
                         total,
                         SanitizeForLog(ExtractRequestLine(partial)));
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const std::string_view request(unsafe::ptr_cast<char>(data), total);
    const std::string_view request_line = ExtractRequestLine(request);
    const std::string_view request_path = ExtractRequestPath(request_line);
    const std::string_view host = ExtractHeaderValueCI(request, "Host");
    const std::string_view upgrade = ExtractHeaderValueCI(request, "Upgrade");
    const std::string_view connection = ExtractHeaderValueCI(request, "Connection");
    const std::string_view version = ExtractHeaderValueCI(request, "Sec-WebSocket-Version");
    const std::string_view user_agent = ExtractHeaderValueCI(request, "User-Agent");
    const std::string_view origin = ExtractHeaderValueCI(request, "Origin");
    const std::string_view subprotocol = ExtractHeaderValueCI(request, "Sec-WebSocket-Protocol");

    LOG_ACCESS_TRACE(
        "[WS:{}] server: upgrade request line='{}' path='{}' host='{}' upgrade='{}' connection='{}' version='{}' ua='{}' origin='{}' proto='{}' bytes={}",
        conn_id,
        SanitizeForLog(request_line),
        SanitizeForLog(request_path),
        SanitizeForLog(host),
        SanitizeForLog(upgrade),
        SanitizeForLog(connection),
        SanitizeForLog(version),
        SanitizeForLog(user_agent),
        SanitizeForLog(origin),
        SanitizeForLog(subprotocol),
        total);

    // 验证 Upgrade 头
    if (!EqualsAsciiCI(TrimAscii(upgrade), "websocket")) {
        LOG_ACCESS_DEBUG("[WS:{}] server: missing 'Upgrade: websocket' header", conn_id);
        LOG_ACCESS_TRACE("[WS:{}] server: reject missing upgrade line='{}' host='{}' upgrade='{}' connection='{}'",
                         conn_id,
                         SanitizeForLog(request_line),
                         SanitizeForLog(host),
                         SanitizeForLog(upgrade),
                         SanitizeForLog(connection));
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    // 验证路径（如果配置了非根路径）
    if (ws_cfg.path != "/" && !ws_cfg.path.empty()) {
        if (request_path != ws_cfg.path) {
            LOG_ACCESS_DEBUG("[WS:{}] server: path mismatch, expected '{}'", conn_id, ws_cfg.path);
            LOG_ACCESS_TRACE("[WS:{}] server: reject path mismatch expected='{}' actual='{}' line='{}'",
                             conn_id,
                             ws_cfg.path,
                             SanitizeForLog(request_path),
                             SanitizeForLog(request_line));
            co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
    }

    // 提取单个 HTTP header 值（找不到则返回空串）
    // 提取 Sec-WebSocket-Key
    std::string_view ws_key = ExtractHeaderValueCI(request, "Sec-WebSocket-Key");
    if (ws_key.empty()) {
        LOG_ACCESS_DEBUG("[WS:{}] server: missing Sec-WebSocket-Key header", conn_id);
        LOG_ACCESS_TRACE("[WS:{}] server: reject missing key line='{}' host='{}' version='{}'",
                         conn_id,
                         SanitizeForLog(request_line),
                         SanitizeForLog(host),
                         SanitizeForLog(version));
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    // 提取真实客户端 IP（CDN 透传头）
    if (out_real_ip && !ws_cfg.real_ip_header.empty()) {
        std::string_view val = ExtractHeaderValueCI(request, ws_cfg.real_ip_header);
        if (!val.empty()) {
            // X-Forwarded-For 可能是逗号分隔列表，取第一个
            auto comma = val.find(',');
            if (comma != std::string_view::npos) val = val.substr(0, comma);
            val = TrimAscii(val);
            if (!val.empty()) *out_real_ip = std::string(val);
        }
    }

    // 计算 Sec-WebSocket-Accept
    std::string accept = ComputeWsAccept(ws_key);

    // 发送 101
    std::string resp = std::format(
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: {}\r\n"
        "\r\n",
        accept);
    size_t sent = 0;
    while (sent < resp.size()) {
        size_t n = co_await stream->AsyncWrite(
            net::buffer(resp.data() + sent, resp.size() - sent));
        if (n == 0) {
            LOG_ACCESS_DEBUG("[WS:{}] server: failed to send 101 response", conn_id);
            co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }
        sent += n;
    }

    // 创建 WsServerStream，将 HTTP 头后的数据作为 pending data
    auto ws = std::make_unique<WsServerStream>(std::move(stream), conn_id);
    size_t header_end = request.find("\r\n\r\n") + 4;
    if (header_end < total) {
        ws->SetPendingData(data + header_end, total - header_end);
    }
    LOG_ACCESS_TRACE(
        "[WS:{}] server: handshake accepted path='{}' host='{}' key_len={} pending={} real_ip_header='{}' real_ip='{}'",
        conn_id,
        ws_cfg.path.empty() ? "/" : ws_cfg.path,
        SanitizeForLog(host),
        TrimAscii(ws_key).size(),
        header_end < total ? (total - header_end) : 0,
        ws_cfg.real_ip_header.empty() ? "-" : ws_cfg.real_ip_header,
        (out_real_ip && !out_real_ip->empty()) ? *out_real_ip : std::string("-"));
    LOG_ACCESS_DEBUG("[WS:{}] server: handshake ok (path={})", conn_id, ws_cfg.path);
    co_return std::unique_ptr<AsyncStream>(std::move(ws));
}

}  // namespace

static std::unique_ptr<TcpStream> TakeOwnedTcpStream(
    std::unique_ptr<AsyncStream>& stream) {
    auto* tcp_raw = stream ? dynamic_cast<TcpStream*>(stream.get()) : nullptr;
    if (!tcp_raw) {
        return nullptr;
    }
    stream.release();
    return std::unique_ptr<TcpStream>(tcp_raw);
}

// ============================================================================
// BuildInboundTransport
// ============================================================================
net::awaitable<TransportBuildResult> BuildInboundTransport(
    net::io_context& io_context,
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
    std::string* out_real_ip,
    uint64_t trace_conn_id,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler)
{
    std::unique_ptr<AsyncStream> stream = std::move(raw);

    const bool reality_supported =
        !s.IsReality() ||
        s.network_mode == NetworkMode::Tcp ||
        s.IsGrpc() ||
        s.IsXHttp();
    if (s.IsUnsupported() || !reality_supported) {
        LOG_ERROR("[Transport] BuildInbound: unsupported transport combination network={} security={}",
                  s.network,
                  s.security);
        co_return std::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    // 1. TLS / REALITY 层（服务端）
    if (s.IsTlsLike()) {
        auto ctx = s.IsReality()
            ? AcquireServerRealityContext(s.reality, s.tls)
            : AcquireServerTlsContext(s.tls);
        if (!ctx) {
            LOG_ERROR("[Transport] BuildInbound: failed to create {} server context",
                      s.IsReality() ? "REALITY" : "TLS");
            co_return std::unexpected(ErrorCode::TLS_CERT_INVALID);
        }

        auto tcp = TakeOwnedTcpStream(stream);
        if (!tcp) {
            LOG_ERROR("[Transport] BuildInbound: TLS-like security requested but base stream is not TcpStream");
            co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
        }
        auto tls = co_await WrapTlsServer(std::move(tcp), *ctx);
        if (!tls) {
            LOG_ACCESS_DEBUG("[Transport] BuildInbound: {} server handshake failed",
                             s.IsReality() ? "REALITY" : "TLS");
            co_return std::unexpected(ErrorCode::TLS_HANDSHAKE_FAILED);
        }
        LOG_ACCESS_DEBUG("[Transport] BuildInbound: {} handshake ok",
                         s.IsReality() ? "REALITY" : "TLS");
        stream = std::move(tls);
    }

    // 2. gRPC 层（服务端）
    if (s.IsGrpc()) {
        uint64_t conn_id = trace_conn_id;
        if (conn_id == 0) {
            thread_local uint64_t s_conn_counter_grpc = 1;
            conn_id = s_conn_counter_grpc++;
        }
        auto grpc_result = co_await DoGrpcServerHandshake(
            std::move(stream),
            s.grpc,
            io_context,
            std::move(stream_handler),
            conn_id);
        if (!grpc_result) {
            LOG_ACCESS_DEBUG("[Transport] BuildInbound: gRPC server handshake failed ({})",
                             ErrorCodeToString(grpc_result.error()));
            co_return std::unexpected(grpc_result.error());
        }
        stream = std::move(*grpc_result);
    }

    // 3. HTTP / h2 层（服务端）
    if (s.IsHttp()) {
        uint64_t conn_id = trace_conn_id;
        if (conn_id == 0) {
            thread_local uint64_t s_conn_counter_http = 1;
            conn_id = s_conn_counter_http++;
        }
        auto http_result = co_await DoHttpServerHandshake(
            std::move(stream),
            s.http,
            io_context,
            std::move(stream_handler),
            conn_id,
            out_real_ip);
        if (!http_result) {
            LOG_ACCESS_DEBUG("[Transport] BuildInbound: HTTP server handshake failed ({})",
                             ErrorCodeToString(http_result.error()));
            co_return std::unexpected(http_result.error());
        }
        stream = std::move(*http_result);
    }

    // 4. XHTTP 层（服务端：H2 stream-one 或 H1 packet-up）
    if (s.IsXHttp()) {
        if (!s.xhttp.AcceptsStreamOne() &&
            !s.xhttp.AcceptsPacketUp() &&
            !s.xhttp.AcceptsStreamUp()) {
            LOG_ERROR("[Transport] BuildInbound: XHTTP mode '{}' is not supported yet",
                      s.xhttp.mode.empty() ? "auto" : s.xhttp.mode);
            co_return std::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
        }
        uint64_t conn_id = trace_conn_id;
        if (conn_id == 0) {
            thread_local uint64_t s_conn_counter_xhttp = 1;
            conn_id = s_conn_counter_xhttp++;
        }
        const HttpConfig http = XHttpStreamOneHttpConfig(s.xhttp, false);
        auto xhttp_result = co_await DoHttpServerHandshake(
            std::move(stream),
            http,
            io_context,
            std::move(stream_handler),
            conn_id,
            out_real_ip,
            false,
            &s.xhttp);
        if (!xhttp_result) {
            LOG_ACCESS_DEBUG("[Transport] BuildInbound: XHTTP server handshake failed ({})",
                             ErrorCodeToString(xhttp_result.error()));
            co_return std::unexpected(xhttp_result.error());
        }
        stream = std::move(*xhttp_result);
    }

    // 5. WebSocket 层（服务端）
    if (s.IsWs()) {
        uint64_t conn_id = trace_conn_id;
        if (conn_id == 0) {
            // 兜底：无上层连接号时使用本线程本地 trace 号，仅用于日志关联。
            thread_local uint64_t s_conn_counter = 1;
            conn_id = s_conn_counter++;
        }
        auto ws_result = co_await DoWsServerHandshake(std::move(stream), s.ws, conn_id, out_real_ip);
        if (!ws_result) {
            LOG_ACCESS_DEBUG("[Transport] BuildInbound: WS server handshake failed ({})",
                             ErrorCodeToString(ws_result.error()));
            co_return std::unexpected(ws_result.error());
        }
        stream = std::move(*ws_result);
    }

    // 6. HTTPUpgrade 层（服务端）
    if (s.IsHttpUpgrade()) {
        uint64_t conn_id = trace_conn_id;
        if (conn_id == 0) {
            thread_local uint64_t s_conn_counter = 1;
            conn_id = s_conn_counter++;
        }
        auto http_upgrade_result = co_await DoHttpUpgradeServerHandshake(
            std::move(stream), s.http_upgrade, conn_id, out_real_ip);
        if (!http_upgrade_result) {
            LOG_ACCESS_DEBUG("[Transport] BuildInbound: HTTPUpgrade server handshake failed ({})",
                             ErrorCodeToString(http_upgrade_result.error()));
            co_return std::unexpected(http_upgrade_result.error());
        }
        stream = std::move(*http_upgrade_result);
    }

    co_return stream;
}

// ============================================================================
// BuildOutboundTransport
// ============================================================================
net::awaitable<TransportBuildResult> BuildOutboundTransport(
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
    std::string_view tls_server_name,
    std::string_view ws_host,
    uint64_t trace_conn_id)
{
    std::unique_ptr<AsyncStream> stream = std::move(raw);

    const bool reality_supported =
        !s.IsReality() ||
        s.network_mode == NetworkMode::Tcp ||
        s.IsGrpc() ||
        s.IsXHttp();
    if (s.IsUnsupported() || !reality_supported) {
        LOG_ERROR("[Transport] BuildOutbound: unsupported transport combination network={} security={}",
                  s.network,
                  s.security);
        co_return std::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    // 1. TLS / REALITY 层（客户端）
    if (s.IsTlsLike()) {
        auto ctx = s.IsReality()
            ? AcquireClientRealityContext(s.reality, s.tls)
            : AcquireClientTlsContext(s.tls);
        if (!ctx) {
            LOG_ERROR("[Transport] BuildOutbound: failed to create {} client context",
                      s.IsReality() ? "REALITY" : "TLS");
            co_return std::unexpected(ErrorCode::TLS_CERT_INVALID);
        }

        std::string sni = tls_server_name.empty()
            ? s.tls.server_name
            : std::string(tls_server_name);
        std::vector<std::string> alpn = s.tls.alpn;
        auto tcp = TakeOwnedTcpStream(stream);
        if (!tcp) {
            LOG_ERROR("[Transport] BuildOutbound: TLS-like security requested but base stream is not TcpStream");
            co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
        }
        auto tls = s.IsReality()
            ? co_await WrapRealityClient(std::move(tcp), *ctx, s.reality, sni, alpn)
            : co_await WrapTlsClient(std::move(tcp), *ctx, sni, alpn);
        if (!tls) {
            LOG_ACCESS_DEBUG("[Transport] BuildOutbound: {} client handshake failed (sni={})",
                             s.IsReality() ? "REALITY" : "TLS",
                             sni);
            co_return std::unexpected(ErrorCode::TLS_HANDSHAKE_FAILED);
        }
        LOG_ACCESS_DEBUG("[Transport] BuildOutbound: {} handshake ok (sni={}, alpn={})",
                         s.IsReality() ? "REALITY" : "TLS",
                         sni,
                         tls->NegotiatedAlpn().empty()
                             ? "-"
                             : tls->NegotiatedAlpn());
        stream = std::move(tls);
    }

    // 2. gRPC 层（客户端）
    if (s.IsGrpc()) {
        uint64_t conn_id = trace_conn_id;
        if (conn_id == 0) {
            thread_local uint64_t s_conn_counter_grpc_out = 1;
            conn_id = s_conn_counter_grpc_out++;
        }
        std::string authority;
        if (!s.grpc.authority.empty()) {
            authority = s.grpc.authority;
        } else if (s.IsReality()) {
            authority.clear();
        } else if (!ws_host.empty()) {
            authority = std::string(ws_host);
        } else {
            authority = std::string(tls_server_name.empty()
                ? s.tls.server_name
                : tls_server_name);
        }
        auto grpc_result = co_await DoGrpcClientHandshake(
            std::move(stream), s.grpc, authority, s.IsTlsLike(), conn_id);
        if (!grpc_result) {
            LOG_ACCESS_DEBUG("[Transport] BuildOutbound: gRPC client handshake failed ({})",
                             ErrorCodeToString(grpc_result.error()));
            co_return std::unexpected(grpc_result.error());
        }
        stream = std::move(*grpc_result);
    }

    // 3. HTTP / h2 层（客户端）
    if (s.IsHttp()) {
        uint64_t conn_id = trace_conn_id;
        if (conn_id == 0) {
            thread_local uint64_t s_conn_counter_http_out = 1;
            conn_id = s_conn_counter_http_out++;
        }
        std::string host = ws_host.empty()
            ? std::string(tls_server_name.empty() ? s.tls.server_name : tls_server_name)
            : std::string(ws_host);
        if (const std::string_view configured_host = TrimAscii(ExpectedHttpHost(s.http));
            !configured_host.empty()) {
            host = std::string(configured_host);
        }
        if (host.empty()) {
            host = "www.example.com";
        }
        if (ShouldUseHttp2ForHttp(s)) {
            auto http2_result = co_await DoHttp2ClientHandshake(
                std::move(stream),
                s.http,
                host,
                s.IsTlsLike(),
                conn_id);
            if (!http2_result) {
                LOG_ACCESS_DEBUG("[Transport] BuildOutbound: HTTP/2 client handshake failed ({})",
                                 ErrorCodeToString(http2_result.error()));
                co_return std::unexpected(http2_result.error());
            }
            stream = std::move(*http2_result);
        } else {
            auto http1_result = co_await DoHttp1ClientHandshake(
                std::move(stream),
                s.http,
                host,
                conn_id);
            if (!http1_result) {
                LOG_ACCESS_DEBUG("[Transport] BuildOutbound: HTTP client handshake failed ({})",
                                 ErrorCodeToString(http1_result.error()));
                co_return std::unexpected(http1_result.error());
            }
            stream = std::move(*http1_result);
        }
    }

    // 4. XHTTP stream-one 层（客户端，HTTP/2 raw body/response）
    if (s.IsXHttp()) {
        const bool auto_reality_stream_one =
            (s.xhttp.mode.empty() || s.xhttp.mode == "auto") &&
            s.IsReality() &&
            !s.xhttp.download_settings;
        if (!s.xhttp.IsStreamOne() && !auto_reality_stream_one) {
            LOG_ERROR("[Transport] BuildOutbound: XHTTP mode '{}' is not supported yet",
                      s.xhttp.mode.empty() ? "auto" : s.xhttp.mode);
            co_return std::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
        }
        uint64_t conn_id = trace_conn_id;
        if (conn_id == 0) {
            thread_local uint64_t s_conn_counter_xhttp_out = 1;
            conn_id = s_conn_counter_xhttp_out++;
        }
        std::string host = ws_host.empty()
            ? std::string(tls_server_name.empty() ? s.tls.server_name : tls_server_name)
            : std::string(ws_host);
        const HttpConfig http = XHttpStreamOneHttpConfig(s.xhttp, true);
        if (const std::string_view configured_host = TrimAscii(ExpectedHttpHost(http));
            !configured_host.empty()) {
            host = std::string(configured_host);
        }
        if (host.empty()) {
            host = "www.example.com";
        }
        auto xhttp_result = co_await DoHttp2ClientHandshake(
            std::move(stream),
            http,
            host,
            s.IsTlsLike(),
            conn_id);
        if (!xhttp_result) {
            LOG_ACCESS_DEBUG("[Transport] BuildOutbound: XHTTP client handshake failed ({})",
                             ErrorCodeToString(xhttp_result.error()));
            co_return std::unexpected(xhttp_result.error());
        }
        stream = std::move(*xhttp_result);
    }

    // 5. WebSocket 层（客户端）
    if (s.IsWs()) {
        uint64_t conn_id = trace_conn_id;
        if (conn_id == 0) {
            thread_local uint64_t s_conn_counter_out = 1;
            conn_id = s_conn_counter_out++;
        }
        std::string host = ws_host.empty()
            ? std::string(tls_server_name.empty() ? s.tls.server_name : tls_server_name)
            : std::string(ws_host);
        auto ws = std::make_unique<WsClientStream>(std::move(stream), conn_id);
        auto ws_result = co_await ws->Handshake(
            host,
            s.ws.path.empty() ? "/" : s.ws.path,
            &s.ws.headers);
        if (!ws_result) {
            LOG_ACCESS_DEBUG("[Transport] BuildOutbound: WS client handshake failed ({})",
                             ErrorCodeToString(ws_result.error()));
            co_return std::unexpected(ws_result.error());
        }
        stream = std::move(ws);
    }

    // 5. HTTPUpgrade 层（客户端）
    if (s.IsHttpUpgrade()) {
        uint64_t conn_id = trace_conn_id;
        if (conn_id == 0) {
            thread_local uint64_t s_conn_counter_http_out = 1;
            conn_id = s_conn_counter_http_out++;
        }
        std::string host = ws_host.empty()
            ? std::string(tls_server_name.empty() ? s.tls.server_name : tls_server_name)
            : std::string(ws_host);
        auto http_upgrade_result = co_await DoHttpUpgradeClientHandshake(
            std::move(stream), s.http_upgrade, host, conn_id);
        if (!http_upgrade_result) {
            LOG_ACCESS_DEBUG("[Transport] BuildOutbound: HTTPUpgrade client handshake failed ({})",
                             ErrorCodeToString(http_upgrade_result.error()));
            co_return std::unexpected(http_upgrade_result.error());
        }
        stream = std::move(*http_upgrade_result);
    }

    co_return stream;
}

net::awaitable<TransportBuildResult> BuildOutboundXHttpClientRequest(
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
    std::string_view tls_server_name,
    std::string_view host,
    std::string_view path,
    XHttpClientRequestKind kind,
    std::span<const net::const_buffer> packet_payload,
    uint64_t trace_conn_id) {
    if (!raw || !s.IsXHttp() || s.IsUnsupported()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    std::unique_ptr<AsyncStream> stream = std::move(raw);
    if (s.IsTlsLike()) {
        auto ctx = s.IsReality()
            ? AcquireClientRealityContext(s.reality, s.tls)
            : AcquireClientTlsContext(s.tls);
        if (!ctx) {
            co_return std::unexpected(ErrorCode::TLS_CERT_INVALID);
        }
        std::string sni = tls_server_name.empty()
            ? s.tls.server_name
            : std::string(tls_server_name);
        std::vector<std::string> alpn = s.tls.alpn;
        auto tcp = TakeOwnedTcpStream(stream);
        if (!tcp) {
            co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
        }
        auto tls = s.IsReality()
            ? co_await WrapRealityClient(std::move(tcp), *ctx, s.reality, sni, alpn)
            : co_await WrapTlsClient(std::move(tcp), *ctx, sni, alpn);
        if (!tls) {
            co_return std::unexpected(ErrorCode::TLS_HANDSHAKE_FAILED);
        }
        stream = std::move(tls);
    }

    const HttpConfig http = XHttpClientHttpConfig(
        s.xhttp,
        path,
        kind == XHttpClientRequestKind::Downlink ? "GET" : "POST",
        s.IsTlsLike(),
        kind);

    std::string authority(host);
    if (authority.empty()) {
        if (s.IsReality() && !s.reality.server_name.empty()) {
            authority = s.reality.server_name;
        } else {
            authority = tls_server_name.empty()
                ? s.tls.server_name
                : std::string(tls_server_name);
        }
    }
    if (const std::string_view configured_host = TrimAscii(ExpectedHttpHost(http));
        !configured_host.empty()) {
        authority = std::string(configured_host);
    }
    if (authority.empty()) {
        authority = "www.example.com";
    }

    const uint64_t conn_id = trace_conn_id;
    if (ShouldUseHttp2ForXHttp(s)) {
        if (kind == XHttpClientRequestKind::PacketUp) {
            co_return co_await DoXHttp2PacketUpClientRequest(
                std::move(stream),
                http,
                authority,
                s.IsTlsLike(),
                packet_payload,
                conn_id);
        }
        auto http2_result = co_await DoHttp2ClientHandshake(
            std::move(stream),
            http,
            authority,
            s.IsTlsLike(),
            conn_id);
        if (!http2_result) {
            co_return std::unexpected(http2_result.error());
        }
        if (kind == XHttpClientRequestKind::StreamUp && !packet_payload.empty()) {
            try {
                co_await (*http2_result)->WriteBuffers(packet_payload);
            } catch (...) {
                co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
            }
        }
        co_return http2_result;
    }

    co_return co_await DoXHttp1ClientRequest(
        std::move(stream),
        http,
        authority,
        kind,
        packet_payload,
        conn_id);
}

}  // namespace acpp
