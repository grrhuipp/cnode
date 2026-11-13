#include "transport/h2_frame.hpp"
#include "transport/http2_session.hpp"

namespace transport {
// Returns nullopt only on a clean EOF at a frame boundary.
net::awaitable<std::optional<H2Frame>> ReadH2Frame(AsyncStream& stream) {
    std::array<uint8_t, kHttp2FrameHeaderSize> header{};
    size_t received = 0;
    while (received != header.size()) {
        size_t n = 0;
        try {
            n = co_await stream.AsyncRead(
                net::buffer(header.data() + received, header.size() - received));
        } catch (const IoSystemError& error) {
            if (received != 0 && error.code() == io_error::operation_aborted) {
                throw IoSystemError(io_error::connection_reset, "cancelled mid-HTTP/2 frame header");
            }
            throw;
        }
        if (n == 0) {
            if (received == 0) co_return std::nullopt;
            throw IoSystemError(io_error::connection_reset, "truncated HTTP/2 frame header");
        }
        received += n;
    }

    H2Frame frame;
    const uint32_t length = common::LoadU24BE(header.data());
    frame.type = static_cast<H2FrameType>(header[3]);
    frame.flags = header[4];
    frame.stream_id = common::LoadU32BE(header.data() + 5) & 0x7fff'ffffu;

    if (length > kHttp2MaxFramePayload) {
        throw IoSystemError(io_error::message_size, "HTTP/2 frame exceeds receive limit");
    }
    if (length > 0) {
        try {
            if (length <= H2Frame::kInlinePayloadCapacity) {
                size_t filled = 0;
                while (filled < length) {
                    const size_t n = co_await stream.AsyncRead(
                        net::buffer(frame.inline_payload.data() + filled, length - filled));
                    if (n == 0) {
                        throw IoSystemError(
                            io_error::connection_reset, "truncated HTTP/2 frame payload");
                    }
                    filled += n;
                }
                frame.inline_size = static_cast<uint8_t>(length);
            } else {
                size_t filled = 0;
                while (filled < length) {
                    if (filled == frame.heap_payload.size()) {
                        const size_t next_size = std::min<size_t>(
                            length,
                            std::max<size_t>(1024, frame.heap_payload.size() * 2));
                        frame.heap_payload.resize(next_size);
                    }
                    const size_t n = co_await stream.AsyncRead(
                        net::buffer(frame.heap_payload.data() + filled,
                                    frame.heap_payload.size() - filled));
                    if (n == 0) {
                        throw IoSystemError(
                            io_error::connection_reset, "truncated HTTP/2 frame payload");
                    }
                    filled += n;
                }
            }
        } catch (const IoSystemError& error) {
            if (error.code() == io_error::operation_aborted) {
                throw IoSystemError(io_error::connection_reset, "cancelled mid-HTTP/2 frame payload");
            }
            throw;
        }
    }
    co_return frame;
}

// 写入失败抛异常并淘汰物理连接，绝不返回可被误认为健康流的失败值。
net::awaitable<void> WriteH2FrameBuffers(
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
        throw IoSystemError(io_error::message_size, "HTTP/2 frame payload too large");
    }

    std::array<uint8_t, kHttp2FrameHeaderSize> header{};
    EncodeH2FrameHeader(
        header.data(), static_cast<uint32_t>(payload_len), type, flags, stream_id);
    std::array<net::const_buffer, 8> all{};
    size_t count = 0;
    all[count++] = net::buffer(header);
    for (const auto& payload : payloads) {
        if (payload.size() > 0) {
            if (count >= all.size()) {
                throw IoSystemError(io_error::message_size, "too many HTTP/2 frame buffers");
            }
            all[count++] = payload;
        }
    }
    try {
        co_await stream.WriteBuffers(std::span<const net::const_buffer>(all.data(), count));
    } catch (...) {
        // A failed physical write may have emitted a partial frame. Retire the
        // connection before another stream can append bytes to that frame.
        stream.CloseAbortive();
        throw;
    }
}

net::awaitable<void> WriteH2Frame(
    AsyncStream& stream,
    H2FrameType type,
    uint8_t flags,
    uint32_t stream_id,
    std::span<const uint8_t> payload) {
    const net::const_buffer buffer{payload.data(), payload.size()};
    co_await WriteH2FrameBuffers(
        stream,
        type,
        flags,
        stream_id,
        payload.empty()
            ? std::span<const net::const_buffer>{}
            : std::span<const net::const_buffer>(&buffer, 1));
}
[[nodiscard]] HpackBuffer EncodeHttpRequestHeaders(
    std::string_view authority,
    bool tls,
    const HttpClientRequestView& req) {
    const std::string_view method = req.method.empty()
        ? std::string_view("PUT") : req.method;
    const std::string_view req_path = EffectiveHttpPath(req.path);
    const size_t header_count =
        (req.headers ? req.headers->size() : 0) +
        (!req.default_content_type.empty() ? 1 : 0) +
        (!req.default_referer.empty() ? 1 : 0);
    HpackBuffer h;
    h.reserve(128 + authority.size() + req_path.size() + method.size() +
              header_count * 32);

    if (method == "GET") {
        AppendHpackIndexed(h, kHpackStaticMethodGet);
    } else if (method == "POST") {
        AppendHpackIndexed(h, kHpackStaticMethodPost);
    } else {
        AppendHpackLiteralIndexedName(h, kHpackStaticMethodGet, method);
    }
    AppendHpackIndexed(h, tls ? kHpackStaticSchemeHttps : kHpackStaticSchemeHttp);
    if (req_path == "/") {
        AppendHpackIndexed(h, kHpackStaticPath);
    } else {
        AppendHpackLiteralIndexedName(h, kHpackStaticPath, req_path);
    }
    if (!authority.empty()) {
        AppendHpackLiteralIndexedName(h, kHpackStaticAuthority, authority);
    }
    if (req.headers) {
        for (const auto& [key, value] : *req.headers) {
            if (key.empty() || IsConnectionSpecificHttp2Header(key)) {
                continue;
            }
            AppendHpackLiteralNewName(h, key, value);
        }
    }
    if (!req.default_content_type.empty()) {
        AppendHpackLiteralNewName(h, "content-type", req.default_content_type);
    }
    if (!req.default_referer.empty()) {
        AppendHpackLiteralNewName(h, "referer", req.default_referer);
    }
    return h;
}

[[nodiscard]] std::vector<uint8_t> EncodeHttpResponseHeaders(
    const HttpHeaders& headers, std::string_view default_content_type) {
    const size_t count = headers.size() + (!default_content_type.empty() ? 1 : 0);
    std::vector<uint8_t> h;
    h.reserve(64 + count * 32);
    AppendHpackIndexed(h, kHpackStaticStatusOk);
    AppendHpackLiteralNewName(h, "cache-control", "no-store");
    for (const auto& [key, value] : headers) {
        if (key.empty() || IsConnectionSpecificHttp2Header(key)) {
            continue;
        }
        AppendHpackLiteralNewName(h, key, value);
    }
    if (!default_content_type.empty()) {
        AppendHpackLiteralNewName(h, "content-type", default_content_type);
    }
    return h;
}
// Last SETTINGS_INITIAL_WINDOW_SIZE in a validated non-ACK SETTINGS payload;
// a value above 2^31-1 is a FLOW_CONTROL_ERROR connection error (6.5.2).
[[nodiscard]] tl::expected<std::optional<uint32_t>, H2Error> PeerInitialWindowSetting(
    std::span<const uint8_t> payload) {
    std::optional<uint32_t> initial_window;
    for (size_t offset = 0; offset + 6 <= payload.size(); offset += 6) {
        const uint16_t id = common::LoadU16BE(payload.data() + offset);
        if (id != 4) continue;
        const uint32_t value = common::LoadU32BE(payload.data() + offset + 2);
        if (value > H2SendWindow::kMax) return tl::unexpected(H2Error::FlowControl);
        initial_window = value;
    }
    return initial_window;
}

// WINDOW_UPDATE increment (6.9): FRAME_SIZE_ERROR unless the payload is four
// octets; a zero increment is a PROTOCOL_ERROR.
[[nodiscard]] tl::expected<uint32_t, H2Error> WindowUpdateIncrement(const H2Frame& frame) {
    const auto payload = frame.Payload();
    if (payload.size() != 4) return tl::unexpected(H2Error::FrameSize);
    const uint32_t increment = common::LoadU32BE(payload.data()) & 0x7fff'ffffu;
    if (increment == 0) return tl::unexpected(H2Error::Protocol);
    return increment;
}

void EncodeWindowUpdateFrame(uint8_t* out,
                             uint32_t stream_id,
                             uint32_t increment) noexcept {
    common::StoreU24BE(out, 4);
    out[3] = static_cast<uint8_t>(H2FrameType::WINDOW_UPDATE);
    out[4] = 0;
    common::StoreU32BE(out + 5, stream_id & 0x7fff'ffffu);
    common::StoreU32BE(out + 9, increment & 0x7fff'ffffu);
}

// One write carries the connection frame, then the stream frame; a zero
// increment omits its frame (callers never pass two zeros).
net::awaitable<void> SendWindowUpdates(AsyncStream& stream,
                                       uint32_t conn_increment,
                                       uint32_t stream_id,
                                       uint32_t stream_increment) {
    std::array<uint8_t, 26> frames{};
    size_t size = 0;
    if (conn_increment != 0) {
        EncodeWindowUpdateFrame(frames.data(), 0, conn_increment);
        size = 13;
    }
    if (stream_increment != 0) {
        EncodeWindowUpdateFrame(frames.data() + size, stream_id, stream_increment);
        size += 13;
    }
    const net::const_buffer buf = net::buffer(frames.data(), size);
    try {
        co_await stream.WriteBuffers(std::span<const net::const_buffer>(&buf, 1));
    } catch (...) {
        stream.CloseAbortive();
        throw;
    }
}

// DATA payload without padding; empty when the padding length is invalid.
[[nodiscard]] std::span<const uint8_t> H2DataPayload(const H2Frame& frame) {
    const auto payload = frame.Payload();
    if (payload.empty()) {
        return {};
    }
    size_t start = 0;
    size_t end = payload.size();
    if ((frame.flags & kFlagPadded) != 0) {
        const size_t pad_len = payload[0];
        start = 1;
        if (pad_len > end - start) {
            return {};
        }
        end -= pad_len;
    }
    return std::span<const uint8_t>(payload.data() + start, end - start);
}

[[nodiscard]] std::optional<std::span<const uint8_t>> H2HeaderBlockFragment(
    const H2Frame& frame) {
    const auto payload = frame.Payload();
    size_t start = 0;
    size_t end = payload.size();
    if ((frame.flags & kFlagPadded) != 0) {
        if (payload.empty()) {
            return std::nullopt;
        }
        const size_t pad_len = payload[0];
        start = 1;
        if (pad_len > end - start) {
            return std::nullopt;
        }
        end -= pad_len;
    }
    if ((frame.flags & kFlagPriority) != 0) {
        if (end - start < 5) {
            return std::nullopt;
        }
        start += 5;
    }
    return std::span<const uint8_t>(payload.data() + start, end - start);
}
[[nodiscard]] net::awaitable<tl::expected<std::optional<H2RequestHeaders>, H2Error>>
ParseH2RequestHeaders(
    AsyncStream& stream, HpackDecoder& decoder, H2Frame frame,
    std::string_view real_ip_header, bool trailers) {
    H2RequestHeaders request;
    std::optional<std::string> host;
    bool has_method = false;
    bool has_path = false;
    bool has_authority = false;
    bool has_scheme = false;
    bool seen_regular = false;
    bool valid = true;
    const auto take_once = [](bool& seen, std::string& out,
                              std::string_view value) {
        if (seen) return false;
        seen = true;
        out.assign(value);
        return true;
    };
    const auto decoded = co_await ReadH2HeaderFields(
        stream, decoder, std::move(frame),
        [&](std::string_view name, std::string_view value) {
            if (!valid) return;
            if (name.starts_with(':')) {
                if (trailers || seen_regular) {
                    valid = false;
                    return;
                }
                bool accepted = false;
                if (name == ":method") {
                    accepted = take_once(has_method, request.method, value);
                } else if (name == ":path") {
                    accepted = take_once(has_path, request.path, value);
                } else if (name == ":authority") {
                    accepted = take_once(has_authority, request.authority, value);
                } else if (name == ":scheme") {
                    if (!has_scheme && !value.empty()) {
                        has_scheme = true;
                        accepted = true;
                    }
                }
                if (!accepted) {
                    valid = false;
                }
                return;
            }
            if (!IsValidHttp2HeaderName(name)) {
                valid = false;
                return;
            }
            seen_regular = true;
            if (name == "host") {
                if (host) {
                    valid = false;
                    return;
                }
                host.emplace(value);
            } else if (!trailers && !real_ip_header.empty() &&
                       common::EqualsAsciiCI(name, real_ip_header)) {
                if (request.metadata.real_ip.empty()) {
                    const std::string_view real_ip =
                        common::TrimAscii(value.substr(0, value.find(',')));
                    if (!real_ip.empty()) {
                        request.metadata.real_ip.assign(real_ip);
                    }
                }
            }
        });
    if (!decoded) {
        co_return tl::unexpected(decoded.error());
    }
    if (!valid) {
        co_return std::optional<H2RequestHeaders>{};
    }
    if (host) {
        if (has_authority && !common::EqualsAsciiCI(request.authority, *host)) {
            co_return std::optional<H2RequestHeaders>{};
        }
        if (!has_authority) request.authority = std::move(*host);
    }
    if (!trailers && (request.method.empty() || request.path.empty() || !has_scheme)) {
        co_return std::optional<H2RequestHeaders>{};
    }
    co_return std::optional<H2RequestHeaders>{std::move(request)};
}
}  // namespace transport
