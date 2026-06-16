#include "acppnode/transport/internet/transport_stack.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/transport/internet/tls_stream.hpp"
#include "acppnode/transport/internet/ws_stream.hpp"
#include "acppnode/common/base64.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/unsafe.hpp"

#include <openssl/sha.h>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/channel.hpp>
#include <array>
#include <cctype>
#include <cstring>
#include <deque>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace acpp {

namespace {

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

std::string MakeTlsCacheKey(std::string_view role, const TlsConfig& config) {
    std::string key;
    key.reserve(256);
    key.append(role);
    key.push_back('|');
    key.append(config.cert_file);
    key.push_back('|');
    key.append(config.key_file);
    key.push_back('|');
    key.append(config.ca_file);
    key.push_back('|');
    key.append(config.server_name);
    key.push_back('|');
    key.append(config.allow_insecure ? "1" : "0");
    key.push_back('|');
    key.append(config.min_version);
    key.push_back('|');
    key.append(config.max_version);

    for (const auto& suite : config.cipher_suites) {
        key.push_back('|');
        key.append(suite);
    }
    for (const auto& proto : config.alpn) {
        key.push_back('|');
        key.append(proto);
    }

    return key;
}

SslContext* AcquireServerTlsContext(const TlsConfig& config) {
    thread_local std::unordered_map<std::string, std::unique_ptr<SslContext>> cache;
    struct LastHit {
        const TlsConfig* config = nullptr;
        bool is_server = false;
        SslContext* ctx = nullptr;
    };
    thread_local LastHit last;

    const bool is_server = config.IsServer();
    if (last.config == &config && last.is_server == is_server && last.ctx) {
        return last.ctx;
    }

    std::string key = is_server
        ? MakeTlsCacheKey("server", config)
        : MakeTlsCacheKey("server-auto-sign", config);

    if (auto it = cache.find(key); it != cache.end()) {
        last = LastHit{&config, is_server, it->second.get()};
        return it->second.get();
    }

    std::unique_ptr<SslContext> ctx;
    if (is_server) {
        ctx = SslContext::CreateServer(config);
    } else {
        ctx = SslContext::CreateServerAutoSign(config);
    }

    if (ctx) {
        auto* raw = ctx.get();
        cache.emplace(std::move(key), std::move(ctx));
        last = LastHit{&config, is_server, raw};
        return raw;
    }
    return nullptr;
}

SslContext* AcquireClientTlsContext(const TlsConfig& config) {
    thread_local std::unordered_map<std::string, std::unique_ptr<SslContext>> cache;
    thread_local const TlsConfig* last_config = nullptr;
    thread_local SslContext* last_ctx = nullptr;

    if (last_config == &config && last_ctx) {
        return last_ctx;
    }

    std::string key = MakeTlsCacheKey("client", config);

    if (auto it = cache.find(key); it != cache.end()) {
        last_config = &config;
        last_ctx = it->second.get();
        return it->second.get();
    }

    std::unique_ptr<SslContext> ctx = SslContext::CreateClient(config);
    if (ctx) {
        auto* raw = ctx.get();
        cache.emplace(std::move(key), std::move(ctx));
        last_config = &config;
        last_ctx = raw;
        return raw;
    }
    return nullptr;
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
    size_t sent = 0;
    while (sent < len) {
        size_t n = co_await stream.AsyncWrite(
            net::buffer(data + sent, len - sent));
        if (n == 0) {
            co_return false;
        }
        sent += n;
    }
    co_return true;
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
        if (!pending_.empty()) {
            co_return PopPendingData(buffer);
        }
        co_return co_await inner_->AsyncRead(buffer);
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        co_return co_await inner_->AsyncWrite(buffer);
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!pending_.empty()) {
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
        closed_ = true;
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
        auto* out = static_cast<uint8_t*>(target.data());
        size_t remaining = target.size();
        size_t copied = 0;
        size_t drained = 0;

        for (buf::Buffer* buffer : pending_) {
            if (remaining == 0) {
                break;
            }
            if (!buffer || buffer->IsEmpty()) {
                ++drained;
                continue;
            }
            const auto bytes = buffer->Bytes();
            const size_t n = std::min(remaining, bytes.size());
            std::memcpy(out + copied, bytes.data(), n);
            buffer->Advance(static_cast<uint32_t>(n));
            copied += n;
            remaining -= n;
            if (buffer->IsEmpty()) {
                ++drained;
            } else {
                break;
            }
        }
        pending_.drop_front(drained);
        return copied;
    }

    std::unique_ptr<AsyncStream> inner_;
    buf::MultiBuffer pending_;
    bool closed_ = false;
    bool write_closed_ = false;
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
    std::vector<uint8_t> payload;
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

void AppendHpackInt(std::vector<uint8_t>& out,
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

void AppendHpackString(std::vector<uint8_t>& out, std::string_view value) {
    AppendHpackInt(out, 7, 0, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

void AppendHpackIndexed(std::vector<uint8_t>& out, uint32_t index) {
    AppendHpackInt(out, 7, 0x80, index);
}

void AppendHpackLiteralIndexedName(std::vector<uint8_t>& out,
                                   uint32_t name_index,
                                   std::string_view value) {
    AppendHpackInt(out, 4, 0, name_index);
    AppendHpackString(out, value);
}

void AppendHpackLiteralNewName(std::vector<uint8_t>& out,
                               std::string_view name,
                               std::string_view value) {
    out.push_back(0);
    AppendHpackString(out, name);
    AppendHpackString(out, value);
}

[[nodiscard]] std::vector<uint8_t> EncodeGrpcRequestHeaders(
    std::string_view authority,
    std::string_view path,
    bool tls,
    std::string_view user_agent) {
    std::vector<uint8_t> h;
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

[[nodiscard]] std::vector<uint8_t> EncodeGrpcResponseHeaders() {
    std::vector<uint8_t> h;
    h.reserve(32);
    AppendHpackIndexed(h, 8); // :status: 200
    AppendHpackLiteralIndexedName(h, 31, "application/grpc");
    return h;
}

[[nodiscard]] std::vector<uint8_t> EncodeGrpcTrailers() {
    std::vector<uint8_t> h;
    h.reserve(24);
    AppendHpackLiteralNewName(h, "grpc-status", "0");
    return h;
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

[[nodiscard]] std::vector<uint8_t> EncodeSettingsPayload(uint32_t initial_window) {
    std::vector<uint8_t> payload;
    if (initial_window > 0) {
        payload.resize(6);
        payload[0] = 0;
        payload[1] = 4; // SETTINGS_INITIAL_WINDOW_SIZE
        WriteU32(payload.data() + 2, initial_window);
    }
    return payload;
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

[[nodiscard]] std::optional<std::span<const uint8_t>> DecodeGrpcHunkData(
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
            return std::span<const uint8_t>(
                message.data() + offset,
                static_cast<size_t>(len));
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
    return std::span<const uint8_t>{};
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

class GrpcStream final : public AsyncStream {
public:
    enum class Role {
        Client,
        Server,
    };

    GrpcStream(std::unique_ptr<AsyncStream> inner,
               uint32_t stream_id,
               Role role,
               uint64_t conn_id)
        : inner_(std::move(inner))
        , stream_id_(stream_id)
        , role_(role)
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

        while (read_offset_ >= read_payload_.size()) {
            if (!co_await ReadNextGrpcMessage()) {
                co_return 0;
            }
        }

        const size_t n = std::min(capacity, read_payload_.size() - read_offset_);
        std::memcpy(out, read_payload_.data() + read_offset_, n);
        read_offset_ += n;
        if (read_offset_ >= read_payload_.size()) {
            read_payload_.clear();
            read_offset_ = 0;
        }
        co_return n;
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (write_closed_) {
            ThrowGrpcStreamError("gRPC write on closed stream");
        }
        const auto* data = static_cast<const uint8_t*>(buffer.data());
        const size_t len = buffer.size();
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
        for (buf::Buffer*& buffer : mb) {
            if (!buffer) {
                continue;
            }
            if (!buffer->IsEmpty()) {
                const auto bytes = buffer->Bytes();
                if (!co_await WriteGrpcMessage(bytes)) {
                    buf::Buffer::Free(buffer);
                    buffer = nullptr;
                    ThrowGrpcStreamError("gRPC WriteMultiBuffer failed");
                }
            }
            buf::Buffer::Free(buffer);
            buffer = nullptr;
        }
        mb.clear();
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
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
        h2_data_.clear();
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
        if (role_ == Role::Server) {
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
        closed_ = true;
        inner_->Cancel();
    }

    void Close() override {
        if (closed_) {
            return;
        }
        closed_ = true;
        read_payload_.clear();
        h2_data_.clear();
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
        std::vector<uint8_t> message(len);
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
        read_payload_.assign(hunk->begin(), hunk->end());
        co_return true;
    }

    net::awaitable<bool> ReadGrpcBytes(uint8_t* out, size_t len) {
        size_t copied = 0;
        while (copied < len) {
            if (h2_data_offset_ >= h2_data_.size()) {
                h2_data_.clear();
                h2_data_offset_ = 0;
                if (!co_await ReadNextDataFrame()) {
                    co_return false;
                }
                continue;
            }

            const size_t n = std::min(
                len - copied,
                h2_data_.size() - h2_data_offset_);
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
                if (frame->stream_id == stream_id_ &&
                    (frame->flags & 0x1) != 0) {
                    read_closed_ = true;
                    co_return false;
                }
                break;
            case H2FrameType::DATA: {
                if (frame->stream_id != stream_id_) {
                    break;
                }
                const auto data = H2DataPayload(*frame);
                if (!data.empty()) {
                    h2_data_.assign(data.begin(), data.end());
                    h2_data_offset_ = 0;
                    co_await SendWindowUpdate(
                        *inner_,
                        0,
                        static_cast<uint32_t>(data.size()));
                    co_await SendWindowUpdate(
                        *inner_,
                        stream_id_,
                        static_cast<uint32_t>(data.size()));
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
                    read_closed_ = true;
                    co_return false;
                }
                break;
            case H2FrameType::GOAWAY:
                read_closed_ = true;
                co_return false;
            default:
                break;
            }
        }
        co_return false;
    }

    std::unique_ptr<AsyncStream> inner_;
    uint32_t stream_id_ = 1;
    Role role_ = Role::Client;
    uint64_t conn_id_ = 0;
    std::vector<uint8_t> h2_data_;
    size_t h2_data_offset_ = 0;
    std::vector<uint8_t> read_payload_;
    size_t read_offset_ = 0;
    bool read_closed_ = false;
    bool write_closed_ = false;
    bool closed_ = false;
};

class GrpcServerSession;

class GrpcServerSubStreamState final {
public:
    GrpcServerSubStreamState(net::io_context& io_context,
                             std::shared_ptr<GrpcServerSession> session,
                             uint32_t stream_id,
                             uint64_t conn_id);

    [[nodiscard]] uint32_t StreamId() const noexcept {
        return stream_id_;
    }

    [[nodiscard]] std::shared_ptr<GrpcServerSession> LockSession() const noexcept {
        return session_.lock();
    }

    bool PushH2Data(std::span<const uint8_t> data);
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
        (void)input_signal_.try_send(IoErrorCode{});
    }

    net::awaitable<bool> ReadNextGrpcMessage();
    net::awaitable<bool> ReadGrpcBytes(uint8_t* out, size_t len);

    net::io_context& io_context_;
    net::experimental::channel<void(IoErrorCode)> input_signal_;
    std::weak_ptr<GrpcServerSession> session_;
    uint32_t stream_id_ = 0;
    uint64_t conn_id_ = 0;
    std::deque<std::vector<uint8_t>> h2_data_queue_;
    size_t h2_data_offset_ = 0;
    size_t queued_bytes_ = 0;
    std::vector<uint8_t> read_payload_;
    size_t read_offset_ = 0;
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
                      uint64_t conn_id)
        : io_context_(io_context)
        , stream_(std::move(stream))
        , stream_handler_(std::move(stream_handler))
        , write_signal_(io_context, 1)
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
        WakeWriter();
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
        while (write_busy_ && !cancelled_) {
            auto [ec] = co_await write_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                co_return false;
            }
        }
        if (cancelled_ || !stream_) {
            co_return false;
        }

        write_busy_ = true;
        auto guard = std::unique_ptr<void, void(*)(void*)>{
            this,
            [](void* ptr) {
                auto* self = static_cast<GrpcServerSession*>(ptr);
                self->write_busy_ = false;
                self->WakeWriter();
            }};
        (void)guard;

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
        while (write_busy_ && !cancelled_) {
            auto [ec] = co_await write_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                co_return false;
            }
        }
        if (cancelled_ || !stream_) {
            co_return false;
        }

        write_busy_ = true;
        auto guard = std::unique_ptr<void, void(*)(void*)>{
            this,
            [](void* ptr) {
                auto* self = static_cast<GrpcServerSession*>(ptr);
                self->write_busy_ = false;
                self->WakeWriter();
            }};
        (void)guard;

        co_return co_await WriteGrpcHunkMessage(*stream_, stream_id, data);
    }

    net::awaitable<bool> WriteTrailersSerialized(uint32_t stream_id) {
        auto trailers = EncodeGrpcTrailers();
        co_return co_await WriteFrameSerialized(
            H2FrameType::HEADERS,
            0x4 | 0x1,
            stream_id,
            trailers);
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
                    co_await HandleDataFrame(*frame);
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
    void WakeWriter() noexcept {
        (void)write_signal_.try_send(IoErrorCode{});
    }

    net::awaitable<bool> HandleHeadersFrame(H2Frame frame) {
        if (frame.stream_id == 0) {
            co_return false;
        }

        const uint32_t stream_id = frame.stream_id;
        while ((frame.flags & 0x4) == 0) {
            auto cont = co_await ReadH2Frame(*stream_);
            if (!cont ||
                cont->type != H2FrameType::CONTINUATION ||
                cont->stream_id != stream_id) {
                co_return false;
            }
            frame = std::move(*cont);
        }

        auto sub = CreateStream(stream_id);
        auto response_headers = EncodeGrpcResponseHeaders();
        if (!co_await WriteFrameSerialized(
                H2FrameType::HEADERS,
                0x4,
                stream_id,
                response_headers)) {
            co_return false;
        }

        if ((frame.flags & 0x1) != 0 && sub) {
            sub->CloseInput();
        }

        LOG_ACCESS_DEBUG(
            "[gRPC:{}] server: accepted logical stream_id={}",
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

    net::awaitable<void> HandleDataFrame(const H2Frame& frame) {
        if (frame.stream_id == 0) {
            co_return;
        }

        const auto data = H2DataPayload(frame);
        if (!data.empty()) {
            (void)co_await SendWindowUpdateSerialized(
                0,
                static_cast<uint32_t>(data.size()));
            (void)co_await SendWindowUpdateSerialized(
                frame.stream_id,
                static_cast<uint32_t>(data.size()));

            auto it = streams_.find(frame.stream_id);
            if (it != streams_.end() && it->second) {
                if (!it->second->PushH2Data(data)) {
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
    net::experimental::channel<void(IoErrorCode)> write_signal_;
    std::unordered_map<uint32_t, std::shared_ptr<GrpcServerSubStreamState>> streams_;
    uint64_t conn_id_ = 0;
    bool write_busy_ = false;
    bool cancelled_ = false;
};

GrpcServerSubStreamState::GrpcServerSubStreamState(
    net::io_context& io_context,
    std::shared_ptr<GrpcServerSession> session,
    uint32_t stream_id,
    uint64_t conn_id)
    : io_context_(io_context)
    , input_signal_(io_context, 1)
    , session_(std::move(session))
    , stream_id_(stream_id)
    , conn_id_(conn_id) {}

bool GrpcServerSubStreamState::PushH2Data(std::span<const uint8_t> data) {
    constexpr size_t kMaxQueuedBytes = 4 * 1024 * 1024;
    if (cancelled_ || input_done_ || data.empty()) {
        return !cancelled_;
    }
    if (queued_bytes_ + data.size() > kMaxQueuedBytes) {
        CancelFromSession();
        return false;
    }

    std::vector<uint8_t> copy;
    copy.assign(data.begin(), data.end());
    queued_bytes_ += copy.size();
    h2_data_queue_.push_back(std::move(copy));
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
    h2_data_queue_.clear();
    queued_bytes_ = 0;
    read_payload_.clear();
    read_offset_ = 0;
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
    h2_data_queue_.clear();
    queued_bytes_ = 0;
    read_payload_.clear();
    read_offset_ = 0;
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
                [session, stream_id]() -> net::awaitable<void> {
                    (void)co_await session->WriteTrailersSerialized(stream_id);
                    session->RemoveStream(stream_id);
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
    h2_data_queue_.clear();
    queued_bytes_ = 0;
    read_payload_.clear();
    read_offset_ = 0;
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

    while (read_offset_ >= read_payload_.size()) {
        if (!co_await ReadNextGrpcMessage()) {
            co_return 0;
        }
    }

    const size_t n = std::min(capacity, read_payload_.size() - read_offset_);
    std::memcpy(out, read_payload_.data() + read_offset_, n);
    read_offset_ += n;
    if (read_offset_ >= read_payload_.size()) {
        read_payload_.clear();
        read_offset_ = 0;
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
                buf::Buffer::Free(buffer);
                buffer = nullptr;
                mb.clear();
                throw;
            }
            (void)len;
        }
        buf::Buffer::Free(buffer);
        buffer = nullptr;
    }
    mb.clear();
}

net::awaitable<void> GrpcServerSubStreamState::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
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
        (void)co_await session->WriteTrailersSerialized(stream_id_);
    }
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
    std::vector<uint8_t> message(len);
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
    read_payload_.assign(hunk->begin(), hunk->end());
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

        while (!h2_data_queue_.empty() &&
               h2_data_offset_ >= h2_data_queue_.front().size()) {
            queued_bytes_ -= std::min(
                queued_bytes_,
                h2_data_queue_.front().size());
            h2_data_queue_.pop_front();
            h2_data_offset_ = 0;
        }

        if (!h2_data_queue_.empty()) {
            const auto& front = h2_data_queue_.front();
            const size_t n = std::min(
                len - copied,
                front.size() - h2_data_offset_);
            std::memcpy(out + copied, front.data() + h2_data_offset_, n);
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
    if (cfg.initial_window_size > 0) {
        return static_cast<uint32_t>(cfg.initial_window_size);
    }
    return kGrpcInitialWindow;
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

    auto settings = EncodeSettingsPayload(GrpcInitialWindow(cfg));
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

    auto settings = EncodeSettingsPayload(GrpcInitialWindow(cfg));
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
            conn_id));
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

    if (s.IsUnsupported() || s.IsReality() || s.IsXHttp()) {
        LOG_ERROR("[Transport] BuildInbound: unsupported transport combination network={} security={}",
                  s.network,
                  s.security);
        co_return std::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    // 1. TLS 层（服务端）
    if (s.IsTls()) {
        auto ctx = AcquireServerTlsContext(s.tls);
        if (!ctx) {
            LOG_ERROR("[Transport] BuildInbound: failed to create TLS server context");
            co_return std::unexpected(ErrorCode::TLS_CERT_INVALID);
        }

        auto tcp = TakeOwnedTcpStream(stream);
        if (!tcp) {
            LOG_ERROR("[Transport] BuildInbound: TLS requested but base stream is not TcpStream");
            co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
        }
        auto tls = co_await WrapTlsServer(std::move(tcp), *ctx);
        if (!tls) {
            LOG_ACCESS_DEBUG("[Transport] BuildInbound: TLS server handshake failed");
            co_return std::unexpected(ErrorCode::TLS_HANDSHAKE_FAILED);
        }
        LOG_ACCESS_DEBUG("[Transport] BuildInbound: TLS handshake ok");
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

    // 3. WebSocket 层（服务端）
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

    // 4. HTTPUpgrade 层（服务端）
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

    if (s.IsUnsupported() || s.IsReality() || s.IsXHttp()) {
        LOG_ERROR("[Transport] BuildOutbound: unsupported transport combination network={} security={}",
                  s.network,
                  s.security);
        co_return std::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    // 1. TLS 层（客户端）
    if (s.IsTls()) {
        auto ctx = AcquireClientTlsContext(s.tls);
        if (!ctx) {
            LOG_ERROR("[Transport] BuildOutbound: failed to create TLS client context");
            co_return std::unexpected(ErrorCode::TLS_CERT_INVALID);
        }

        std::string sni = tls_server_name.empty()
            ? s.tls.server_name
            : std::string(tls_server_name);
        auto tcp = TakeOwnedTcpStream(stream);
        if (!tcp) {
            LOG_ERROR("[Transport] BuildOutbound: TLS requested but base stream is not TcpStream");
            co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
        }
        auto tls = co_await WrapTlsClient(std::move(tcp), *ctx, sni, s.tls.alpn);
        if (!tls) {
            LOG_ACCESS_DEBUG("[Transport] BuildOutbound: TLS client handshake failed (sni={})", sni);
            co_return std::unexpected(ErrorCode::TLS_HANDSHAKE_FAILED);
        }
        LOG_ACCESS_DEBUG("[Transport] BuildOutbound: TLS handshake ok (sni={})", sni);
        stream = std::move(tls);
    }

    // 2. gRPC 层（客户端）
    if (s.IsGrpc()) {
        uint64_t conn_id = trace_conn_id;
        if (conn_id == 0) {
            thread_local uint64_t s_conn_counter_grpc_out = 1;
            conn_id = s_conn_counter_grpc_out++;
        }
        std::string authority = ws_host.empty()
            ? std::string(tls_server_name.empty() ? s.tls.server_name : tls_server_name)
            : std::string(ws_host);
        auto grpc_result = co_await DoGrpcClientHandshake(
            std::move(stream), s.grpc, authority, s.IsTls(), conn_id);
        if (!grpc_result) {
            LOG_ACCESS_DEBUG("[Transport] BuildOutbound: gRPC client handshake failed ({})",
                             ErrorCodeToString(grpc_result.error()));
            co_return std::unexpected(grpc_result.error());
        }
        stream = std::move(*grpc_result);
    }

    // 3. WebSocket 层（客户端）
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

    // 4. HTTPUpgrade 层（客户端）
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

}  // namespace acpp
