#pragma once

#include "common/asio_types.hpp"
#include "transport/internet/http_headers.hpp"
#include "core/naming.hpp"

#include <asio/as_tuple.hpp>
#include <asio/buffers_iterator.hpp>
#include <asio/read.hpp>
#include <asio/streambuf.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <tl/expected.hpp>
#include <istream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace api::v2board::http {

inline constexpr size_t kMaxHttpBodySize = 64 * 1024 * 1024;
inline constexpr size_t kMaxHttpLineSize = 64 * 1024;
inline constexpr size_t kMaxHttpHeaderSize = 256 * 1024;

struct Response {
    int status = 0;
    std::string body;
    std::string etag;
    bool not_modified = false;
};

inline std::string HeaderNameLower(std::string_view name) {
    return naming::LowerAscii(std::string(name));
}

inline std::string TrimHeaderValue(std::string_view value) {
    return std::string(transport::internet::TrimHttpOws(value));
}


inline bool AppendStreambuf(net::streambuf& buffer, std::string& out) {
    if (out.size() > kMaxHttpBodySize ||
        buffer.size() > kMaxHttpBodySize - out.size()) {
        return false;
    }
    std::istream is(&buffer);
    out.append(std::istreambuf_iterator<char>(is), std::istreambuf_iterator<char>());
    return true;
}

inline std::optional<size_t> ParseContentLength(std::string_view value) noexcept {
    if (value.empty()) {
        return std::nullopt;
    }

    size_t length = 0;
    const auto [end, ec] = std::from_chars(
        value.data(), value.data() + value.size(), length);
    if (ec != std::errc{} || end != value.data() + value.size()) {
        return std::nullopt;
    }
    return length;
}

inline std::optional<size_t> FindCrlf(const net::streambuf& buffer) {
    const auto data = buffer.data();
    const auto begin = net::buffers_begin(data);
    const auto end = net::buffers_end(data);
    constexpr std::array<char, 2> delimiter{'\r', '\n'};
    const auto match = std::search(
        begin, end, delimiter.begin(), delimiter.end());
    if (match == end) {
        return std::nullopt;
    }
    return static_cast<size_t>(std::distance(begin, match));
}

template <typename Stream>
net::awaitable<tl::expected<std::string, std::string>> ReadCrlfLine(
    Stream& stream,
    net::streambuf& buffer) {
    for (;;) {
        if (const auto line_size = FindCrlf(buffer)) {
            if (*line_size > kMaxHttpLineSize) {
                co_return tl::unexpected("HTTP line too large");
            }
            std::string line(*line_size, '\0');
            std::istream input(&buffer);
            input.read(line.data(), static_cast<std::streamsize>(*line_size));
            char terminator[2]{};
            input.read(terminator, 2);
            if (!input || terminator[0] != '\r' || terminator[1] != '\n') {
                co_return tl::unexpected("invalid CRLF line");
            }
            co_return line;
        }
        // A maximum-length line can have its CR buffered while the LF is
        // still in flight. The delimiter is not part of the line-size limit.
        if (buffer.size() > kMaxHttpLineSize &&
            (buffer.size() != kMaxHttpLineSize + 1 ||
             *(net::buffers_begin(buffer.data()) + kMaxHttpLineSize) != '\r')) {
            co_return tl::unexpected("HTTP line too large");
        }

        auto [read_ec, bytes] = co_await stream.async_read_some(
            buffer.prepare(8192), net::as_tuple(net::use_awaitable));
        if (bytes > 0) {
            buffer.commit(bytes);
        }
        if (read_ec && !FindCrlf(buffer).has_value()) {
            co_return tl::unexpected(read_ec.message());
        }
    }
}

// Charges one CRLF-terminated line against the cumulative response-head budget,
// which also bounds how many interim 1xx heads and chunked trailer lines a peer
// can send.
inline bool ChargeHeaderLine(size_t& used, size_t line_size) noexcept {
    if (used > kMaxHttpHeaderSize - 2 || line_size > kMaxHttpHeaderSize - used - 2) {
        return false;
    }
    used += line_size + 2;
    return true;
}

template <typename Stream>
net::awaitable<tl::expected<std::string, std::string>> ReadChunkedBody(
    Stream& stream,
    net::streambuf& buffer,
    size_t& header_size) {
    std::string decoded;

    for (;;) {
        auto size_line = co_await ReadCrlfLine(stream, buffer);
        if (!size_line) {
            co_return tl::unexpected(
                "invalid chunked HTTP response: " + size_line.error());
        }

        const auto chunk_size = transport::internet::ParseHttpChunkSize(*size_line);
        if (!chunk_size) {
            co_return tl::unexpected("invalid chunked HTTP response: invalid chunk size");
        }

        if (*chunk_size == 0) {
            // The last chunk is followed by an optional trailer section and a
            // terminating empty line. Consume it without waiting for socket EOF,
            // so keep-alive and Connection: close responses share the same path.
            for (;;) {
                auto trailer = co_await ReadCrlfLine(stream, buffer);
                if (!trailer) {
                    co_return tl::unexpected(
                        "invalid chunked HTTP response: " + trailer.error());
                }
                if (!ChargeHeaderLine(header_size, trailer->size())) {
                    co_return tl::unexpected(
                        "invalid chunked HTTP response: HTTP response headers too large");
                }
                if (trailer->empty()) {
                    if (buffer.size() > 0) {
                        co_return tl::unexpected(
                            "invalid chunked HTTP response: trailing bytes after chunked body");
                    }
                    co_return decoded;
                }
            }
        }

        if (decoded.size() > kMaxHttpBodySize ||
            *chunk_size > kMaxHttpBodySize - decoded.size() ||
            *chunk_size > static_cast<size_t>(
                std::numeric_limits<std::streamsize>::max())) {
            co_return tl::unexpected("invalid chunked HTTP response: body too large");
        }

        const size_t required = *chunk_size + 2;
        if (buffer.size() < required) {
            auto [body_ec, body_bytes] = co_await net::async_read(
                stream,
                buffer,
                net::transfer_exactly(required - buffer.size()),
                net::as_tuple(net::use_awaitable));
            (void)body_bytes;
            if (body_ec) {
                co_return tl::unexpected(
                    "invalid chunked HTTP response: " + body_ec.message());
            }
        }

        const size_t old_size = decoded.size();
        decoded.resize(old_size + *chunk_size);
        std::istream body_stream(&buffer);
        body_stream.read(
            decoded.data() + old_size,
            static_cast<std::streamsize>(*chunk_size));
        char terminator[2]{};
        body_stream.read(terminator, 2);
        if (!body_stream || terminator[0] != '\r' || terminator[1] != '\n') {
            co_return tl::unexpected(
                "invalid chunked HTTP response: missing chunk terminator");
        }
    }
}

// RFC 9112 §6.1: Transfer-Encoding lists codings in the order they were
// applied and multiple field lines form one combined list. This client sends no
// TE field (RFC 9110 §10.1.4), so chunked is the only coding it can decode and
// it must be the single, hence final, coding.
struct TransferCodings {
    size_t count = 0;
    bool only_chunked = true;
};

inline void AppendTransferCodings(std::string_view value, TransferCodings& codings) {
    while (!value.empty()) {
        const size_t comma = value.find(',');
        const std::string coding = TrimHeaderValue(value.substr(0, comma));
        value = comma == std::string_view::npos ? std::string_view{} : value.substr(comma + 1);
        // RFC 9110 §5.6.1: recipients ignore empty list elements.
        if (coding.empty()) {
            continue;
        }
        ++codings.count;
        if (naming::LowerAscii(coding) != "chunked") {
            codings.only_chunked = false;
        }
    }
}

template <typename Stream>
net::awaitable<Response> ReadResponse(Stream& stream) {
    Response result;
    net::streambuf buffer;
    size_t header_size = 0;
    std::string http_version;
    std::optional<size_t> content_length;
    std::optional<TransferCodings> transfer_codings;
    bool has_etag = false;

    // RFC 9110 §15.2: a client must parse interim 1xx responses that precede
    // the final response, even unsolicited ones.
    for (;;) {
        auto status_line_result = co_await ReadCrlfLine(stream, buffer);
        if (!status_line_result) {
            result.status = -1;
            result.body = "invalid HTTP response headers: " + status_line_result.error();
            co_return result;
        }
        if (!ChargeHeaderLine(header_size, status_line_result->size())) {
            result.status = -1;
            result.body = "HTTP response headers too large";
            co_return result;
        }

        result = Response{};
        http_version.clear();
        content_length.reset();
        transfer_codings.reset();
        has_etag = false;

        const std::string_view status_line = *status_line_result;
        const size_t version_end = status_line.find(' ');
        if (version_end == std::string_view::npos) {
            result.status = -1;
            result.body = "invalid HTTP status line";
            co_return result;
        }
        http_version.assign(status_line.substr(0, version_end));
        if (http_version != "HTTP/1.1" && http_version != "HTTP/1.0") {
            result.status = -1;
            result.body = "invalid HTTP status line";
            co_return result;
        }
        const std::string_view rest = status_line.substr(version_end + 1);
        const size_t status_end = rest.find(' ');
        const std::string_view status_token =
            status_end == std::string_view::npos ? rest : rest.substr(0, status_end);
        int parsed_status = 0;
        const auto [ptr, ec] = std::from_chars(
            status_token.data(),
            status_token.data() + status_token.size(),
            parsed_status);
        if (status_token.size() != 3 || ec != std::errc{} ||
            ptr != status_token.data() + status_token.size() ||
            parsed_status < 100 || parsed_status > 599) {
            result.status = -1;
            result.body = "invalid HTTP status line";
            co_return result;
        }
        result.status = parsed_status;

        for (;;) {
            auto line_result = co_await ReadCrlfLine(stream, buffer);
            if (!line_result) {
                result.status = -1;
                result.body = "invalid HTTP response headers: " + line_result.error();
                co_return result;
            }
            if (!ChargeHeaderLine(header_size, line_result->size())) {
                result.status = -1;
                result.body = "HTTP response headers too large";
                co_return result;
            }
            if (line_result->empty()) break;

            const std::string& line = *line_result;

            const size_t colon = line.find(':');
            if (colon == std::string::npos || colon == 0) {
                result.status = -1;
                result.body = "invalid HTTP header line";
                co_return result;
            }

            const auto name = HeaderNameLower(std::string_view(line).substr(0, colon));
            if (!transport::internet::IsValidHttpHeaderName(name)) {
                result.status = -1;
                result.body = "invalid HTTP header name";
                co_return result;
            }
            const auto value = TrimHeaderValue(std::string_view(line).substr(colon + 1));
            if (!transport::internet::IsValidHttpHeaderValue(value)) {
                result.status = -1;
                result.body = "invalid HTTP header value";
                co_return result;
            }

            if (name == "etag") {
                if (has_etag) {
                    result.status = -1;
                    result.body = "duplicate ETag";
                    co_return result;
                }
                has_etag = true;
                result.etag = value;
                if (result.etag.size() >= 2 && result.etag.front() == '"' &&
                    result.etag.back() == '"') {
                    result.etag = result.etag.substr(1, result.etag.size() - 2);
                }
                // The validator is echoed verbatim in If-None-Match. RFC 9110 etag
                // characters are visible ASCII or obs-text (weak W/"..." tags from
                // intermediaries included); control bytes would inject request
                // header lines and reject the response instead.
                if (!std::ranges::all_of(result.etag, [](unsigned char ch) {
                        return ch > 0x20 && ch != 0x7f;
                    })) {
                    result.status = -1;
                    result.body = "invalid ETag";
                    co_return result;
                }
            } else if (name == "transfer-encoding") {
                if (!transfer_codings) {
                    transfer_codings.emplace();
                }
                AppendTransferCodings(value, *transfer_codings);
            } else if (name == "content-length") {
                const auto parsed_length = ParseContentLength(value);
                if (!parsed_length ||
                    (content_length && *content_length != *parsed_length)) {
                    result.status = -1;
                    result.body = "invalid Content-Length";
                    co_return result;
                }
                content_length = parsed_length;
            }
        }

        if (result.status >= 200) break;
        if (result.status == 101) {
            // No request asks for an upgrade, so a protocol switch has no
            // defined continuation for this client.
            result.status = -1;
            result.body = "unexpected HTTP 101 Switching Protocols";
            co_return result;
        }
    }
    result.not_modified = result.status == 304;

    // RFC 9112 §6.3 rule 1: 204 and 304 responses end with the header section
    // whatever framing fields they carry; a 304 may announce the selected
    // representation's Content-Length (RFC 9110 §8.6) without sending it.
    if (result.status == 204 || result.status == 304) {
        co_return result;
    }

    if (content_length && *content_length > kMaxHttpBodySize) {
        result.status = -1;
        result.body = "HTTP body too large";
        co_return result;
    }

    if (transfer_codings) {
        // RFC 9112 §6.1: Transfer-Encoding in an HTTP/1.0 message means the
        // framing is faulty even when Content-Length is present.
        if (http_version == "HTTP/1.0") {
            result.status = -1;
            result.body = "invalid HTTP framing: Transfer-Encoding in HTTP/1.0 response";
            co_return result;
        }
        // RFC 9112 §6.3 rule 3: Transfer-Encoding with Content-Length is a
        // smuggling/splitting signal that ought to be handled as an error.
        if (content_length) {
            result.status = -1;
            result.body = "invalid HTTP framing: both Transfer-Encoding and Content-Length";
            co_return result;
        }
        // RFC 9112 §6.3 rule 4 would read a non-chunked-final body until close,
        // but that body still carries a coding this client cannot decode.
        if (transfer_codings->count != 1 || !transfer_codings->only_chunked) {
            result.status = -1;
            result.body = "unsupported HTTP Transfer-Encoding";
            co_return result;
        }
        auto decoded = co_await ReadChunkedBody(stream, buffer, header_size);
        if (!decoded) {
            result.status = -1;
            result.body = std::move(decoded.error());
            co_return result;
        }
        result.body = std::move(*decoded);
        co_return result;
    }

    if (!AppendStreambuf(buffer, result.body)) {
        result.status = -1;
        result.body = "HTTP body too large";
        co_return result;
    }

    if (content_length) {
        if (result.body.size() < *content_length) {
            auto [read_ec, bytes] = co_await net::async_read(
                stream,
                buffer,
                net::transfer_exactly(*content_length - result.body.size()),
                net::as_tuple(net::use_awaitable));
            (void)bytes;
            if (read_ec) {
                result.status = -1;
                result.body = "invalid HTTP response body: " + read_ec.message();
                co_return result;
            }
            if (!AppendStreambuf(buffer, result.body)) {
                result.status = -1;
                result.body = "HTTP body too large";
                co_return result;
            }
        }
        if (result.body.size() > *content_length || buffer.size() > 0) {
            result.status = -1;
            result.body = "invalid HTTP response body: trailing bytes after Content-Length body";
            co_return result;
        }
    } else {
        for (;;) {
            auto [read_ec, bytes] = co_await stream.async_read_some(
                buffer.prepare(8192), net::as_tuple(net::use_awaitable));
            if (bytes > 0) {
                buffer.commit(bytes);
                if (!AppendStreambuf(buffer, result.body)) {
                    result.status = -1;
                    result.body = "HTTP body too large";
                    co_return result;
                }
            }
            if (read_ec == io_error::eof) break;
            if (read_ec) {
                result.status = -1;
                result.body = read_ec.message();
                co_return result;
            }
        }
    }

    co_return result;
}

}  // namespace api::v2board::http
