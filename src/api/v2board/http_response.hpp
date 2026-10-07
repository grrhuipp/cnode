#pragma once

#include "acppnode/common/asio_types.hpp"

#include <asio/as_tuple.hpp>
#include <asio/buffers_iterator.hpp>
#include <asio/read.hpp>
#include <asio/streambuf.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <expected>
#include <istream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace acpp::api::v2board::http {

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
    std::string out;
    out.reserve(name.size());
    for (unsigned char ch : name) {
        out.push_back(static_cast<char>(std::tolower(ch)));
    }
    return out;
}

inline std::string TrimHeaderValue(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() &&
           (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
        value.remove_suffix(1);
    }
    return std::string(value);
}

inline int HexValue(char ch) noexcept {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

inline std::optional<size_t> ParseChunkSize(std::string_view line) noexcept {
    size_t size = 0;
    bool has_digit = false;
    for (char ch : line) {
        if (ch == ';') break;
        if (ch == ' ' || ch == '\t' || ch == '\r') continue;
        const int value = HexValue(ch);
        if (value < 0) {
            return std::nullopt;
        }
        has_digit = true;
        if (size > (std::numeric_limits<size_t>::max() -
                    static_cast<size_t>(value)) / 16) {
            return std::nullopt;
        }
        size = size * 16 + static_cast<size_t>(value);
    }
    return has_digit ? std::optional<size_t>{size} : std::nullopt;
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
net::awaitable<std::expected<std::string, std::string>> ReadCrlfLine(
    Stream& stream,
    net::streambuf& buffer) {
    for (;;) {
        if (const auto line_size = FindCrlf(buffer)) {
            if (*line_size > kMaxHttpLineSize) {
                co_return std::unexpected("HTTP line too large");
            }
            std::string line(*line_size, '\0');
            std::istream input(&buffer);
            input.read(line.data(), static_cast<std::streamsize>(*line_size));
            char terminator[2]{};
            input.read(terminator, 2);
            if (!input || terminator[0] != '\r' || terminator[1] != '\n') {
                co_return std::unexpected("invalid CRLF line");
            }
            co_return line;
        }
        if (buffer.size() > kMaxHttpLineSize) {
            co_return std::unexpected("HTTP line too large");
        }

        auto [read_ec, bytes] = co_await stream.async_read_some(
            buffer.prepare(8192), net::as_tuple(net::use_awaitable));
        if (bytes > 0) {
            buffer.commit(bytes);
        }
        if (read_ec && bytes == 0) {
            co_return std::unexpected(read_ec.message());
        }
    }
}

template <typename Stream>
net::awaitable<std::expected<std::string, std::string>> ReadChunkedBody(
    Stream& stream,
    net::streambuf& buffer) {
    std::string decoded;

    for (;;) {
        auto size_line = co_await ReadCrlfLine(stream, buffer);
        if (!size_line) {
            co_return std::unexpected(
                "invalid chunked HTTP response: " + size_line.error());
        }

        const auto chunk_size = ParseChunkSize(*size_line);
        if (!chunk_size) {
            co_return std::unexpected("invalid chunked HTTP response: invalid chunk size");
        }

        if (*chunk_size == 0) {
            // The last chunk is followed by an optional trailer section and a
            // terminating empty line. Consume it without waiting for socket EOF,
            // so keep-alive and Connection: close responses share the same path.
            for (;;) {
                auto trailer = co_await ReadCrlfLine(stream, buffer);
                if (!trailer) {
                    co_return std::unexpected(
                        "invalid chunked HTTP response: " + trailer.error());
                }
                if (trailer->empty()) {
                    co_return decoded;
                }
            }
        }

        if (decoded.size() > kMaxHttpBodySize ||
            *chunk_size > kMaxHttpBodySize - decoded.size() ||
            *chunk_size > static_cast<size_t>(
                std::numeric_limits<std::streamsize>::max())) {
            co_return std::unexpected("invalid chunked HTTP response: body too large");
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
                co_return std::unexpected(
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
            co_return std::unexpected(
                "invalid chunked HTTP response: missing chunk terminator");
        }
    }
}

template <typename Stream>
net::awaitable<Response> ReadResponse(Stream& stream) {
    Response result;
    net::streambuf buffer;

    auto status_line_result = co_await ReadCrlfLine(stream, buffer);
    if (!status_line_result) {
        result.status = -1;
        result.body = "invalid HTTP response headers: " + status_line_result.error();
        co_return result;
    }
    std::string status_line = std::move(*status_line_result);
    size_t header_size = status_line.size() + 2;

    std::istringstream status_parser(status_line);
    std::string http_version;
    status_parser >> http_version >> result.status;
    if (result.status <= 0) {
        result.status = -1;
        result.body = "invalid HTTP status line: " + status_line;
        co_return result;
    }
    result.not_modified = result.status == 304;

    size_t content_length = 0;
    bool has_content_length = false;
    bool is_chunked = false;

    for (;;) {
        auto line_result = co_await ReadCrlfLine(stream, buffer);
        if (!line_result) {
            result.status = -1;
            result.body = "invalid HTTP response headers: " + line_result.error();
            co_return result;
        }
        if (header_size > kMaxHttpHeaderSize - 2 ||
            line_result->size() > kMaxHttpHeaderSize - header_size - 2) {
            result.status = -1;
            result.body = "HTTP response headers too large";
            co_return result;
        }
        header_size += line_result->size() + 2;
        if (line_result->empty()) break;

        const std::string& line = *line_result;

        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;

        const auto name = HeaderNameLower(std::string_view(line).substr(0, colon));
        const auto value = TrimHeaderValue(std::string_view(line).substr(colon + 1));

        if (name == "etag") {
            result.etag = value;
            if (result.etag.size() >= 2 && result.etag.front() == '"' &&
                result.etag.back() == '"') {
                result.etag = result.etag.substr(1, result.etag.size() - 2);
            }
        } else if (name == "transfer-encoding") {
            std::string lowered = value;
            for (char& ch : lowered) {
                ch = static_cast<char>(
                    std::tolower(static_cast<unsigned char>(ch)));
            }
            is_chunked = lowered.find("chunked") != std::string::npos;
        } else if (name == "content-length") {
            const auto parsed_length = ParseContentLength(value);
            if (!parsed_length ||
                (has_content_length && content_length != *parsed_length)) {
                result.status = -1;
                result.body = "invalid Content-Length";
                co_return result;
            }
            content_length = *parsed_length;
            has_content_length = true;
        }
    }

    if (has_content_length && content_length > kMaxHttpBodySize) {
        result.status = -1;
        result.body = "HTTP body too large";
        co_return result;
    }

    if (is_chunked) {
        auto decoded = co_await ReadChunkedBody(stream, buffer);
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

    if (has_content_length) {
        if (result.body.size() < content_length) {
            co_await net::async_read(
                stream,
                buffer,
                net::transfer_exactly(content_length - result.body.size()),
                net::use_awaitable);
            if (!AppendStreambuf(buffer, result.body)) {
                result.status = -1;
                result.body = "HTTP body too large";
                co_return result;
            }
        } else if (result.body.size() > content_length) {
            result.body.resize(content_length);
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

}  // namespace acpp::api::v2board::http
