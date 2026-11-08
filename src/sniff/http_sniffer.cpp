#include "sniff/sniffer.hpp"
#include "common/ip_address.hpp"

#include "common/domain_name.hpp"
#include "common/ip_utils.hpp"
#include "common/unsafe.hpp"
#include "core/constants.hpp"
#include "transport/internet/http_headers.hpp"

#include <algorithm>
#include <array>
#include <charconv>

namespace {

struct HostPortView {
    std::string_view host;
    uint16_t port = 0;
};

[[nodiscard]] std::string_view TrimOws(std::string_view value) noexcept {
    return transport::internet::TrimHttpOws(value);
}

[[nodiscard]] bool ParsePort(std::string_view text, uint16_t& port) noexcept {
    uint32_t value = 0;
    const auto [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), value);
    if (text.empty() || error != std::errc{} ||
        end != text.data() + text.size() || value == 0 || value > 65535) {
        return false;
    }
    port = static_cast<uint16_t>(value);
    return true;
}

static constexpr std::array<std::string_view, 9> kHttpMethods{
    "GET", "POST", "PUT", "DELETE", "HEAD",
    "OPTIONS", "PATCH", "CONNECT", "TRACE"};

[[nodiscard]] bool IsSupportedRequestLine(std::string_view line) noexcept {
    const size_t first_space = line.find(' ');
    if (first_space == std::string_view::npos || first_space == 0) return false;
    const size_t second_space = line.find(' ', first_space + 1);
    if (second_space == std::string_view::npos ||
        second_space == first_space + 1 ||
        line.find(' ', second_space + 1) != std::string_view::npos) {
        return false;
    }

    const std::string_view method = line.substr(0, first_space);
    if (std::ranges::find(kHttpMethods, method) == kHttpMethods.end()) return false;

    const std::string_view target =
        line.substr(first_space + 1, second_space - first_space - 1);
    for (const unsigned char character : target) {
        if (character <= 0x20 || character == 0x7f) return false;
    }

    const std::string_view version = line.substr(second_space + 1);
    return version == "HTTP/1.0" || version == "HTTP/1.1";
}

[[nodiscard]] bool IsValidRequestLinePrefix(std::string_view prefix) noexcept {
    if (prefix.empty()) return false;
    const bool trailing_cr = prefix.back() == '\r';
    if (trailing_cr) prefix.remove_suffix(1);
    if (prefix.empty()) return false;
    for (const unsigned char character : prefix) {
        if (character < 0x20 || character == 0x7f) return false;
    }
    if (trailing_cr) {
        return IsSupportedRequestLine(prefix);
    }

    const size_t first_space = prefix.find(' ');
    if (first_space == std::string_view::npos) {
        return std::ranges::any_of(kHttpMethods, [&](std::string_view method) {
            return method.starts_with(prefix);
        });
    }
    if (first_space == 0) return false;
    const std::string_view method = prefix.substr(0, first_space);
    if (std::ranges::find(kHttpMethods, method) == kHttpMethods.end()) return false;

    const size_t second_space = prefix.find(' ', first_space + 1);
    if (second_space == std::string_view::npos) {
        return true;
    }
    if (second_space == first_space + 1 ||
        prefix.find(' ', second_space + 1) != std::string_view::npos) {
        return false;
    }
    const std::string_view version_prefix = prefix.substr(second_space + 1);
    return std::string_view("HTTP/1.0").starts_with(version_prefix) ||
           std::string_view("HTTP/1.1").starts_with(version_prefix);
}

[[nodiscard]] bool IsValidHeaderLinePrefix(std::string_view prefix) noexcept {
    if (prefix.empty()) return true;
    const bool trailing_cr = prefix.back() == '\r';
    if (trailing_cr) prefix.remove_suffix(1);
    if (prefix.empty()) return true;
    if (prefix.front() == ' ' || prefix.front() == '\t') return false;

    const size_t colon = prefix.find(':');
    if (colon == std::string_view::npos) {
        if (trailing_cr) return false;
        return transport::internet::IsValidHttpHeaderName(prefix);
    }
    if (colon == 0) return false;
    const std::string_view name = prefix.substr(0, colon);
    const std::string_view value = TrimOws(prefix.substr(colon + 1));
    return transport::internet::IsValidHttpHeaderName(name) &&
           transport::internet::IsValidHttpHeaderValue(value);
}

[[nodiscard]] std::optional<HostPortView> ParseHostValue(
    std::string_view value) {
    if (value.empty() || !transport::internet::IsValidHttpAuthority(value)) {
        return std::nullopt;
    }

    HostPortView parsed;
    if (value.front() == '[') {
        const size_t close = value.find(']');
        if (close == std::string_view::npos || close == 1 ||
            value.substr(1, close - 1).find(':') == std::string_view::npos) {
            return std::nullopt;
        }
        parsed.host = value.substr(1, close - 1);
        const auto address = iputil::ParseLiteral(parsed.host);
        if (!address || !address->is_v6()) return std::nullopt;
        const std::string_view suffix = value.substr(close + 1);
        if (!suffix.empty() &&
            (suffix.front() != ':' ||
             !ParsePort(suffix.substr(1), parsed.port))) {
            return std::nullopt;
        }
        return parsed;
    }

    if (value.find('[') != std::string_view::npos ||
        value.find(']') != std::string_view::npos) {
        return std::nullopt;
    }
    const size_t colon = value.find(':');
    if (colon == std::string_view::npos) {
        parsed.host = value;
    } else {
        if (value.rfind(':') != colon || colon == 0 ||
            !ParsePort(value.substr(colon + 1), parsed.port)) {
            return std::nullopt;
        }
        parsed.host = value.substr(0, colon);
    }
    if (!domain::IsValidDnsHostname(
            parsed.host, domain::TrailingDotPolicy::Allow)) {
        return std::nullopt;
    }
    if (parsed.host.ends_with('.') &&
        iputil::ParseLiteral(domain::WithoutTrailingRootDot(parsed.host)).has_value()) {
        return std::nullopt;
    }
    return parsed;
}

}  // namespace

// Single pass over CRLF-terminated lines: the request line, then header fields
// until the empty line. An unterminated but valid prefix requests more bytes.
SniffResult SniffHttp(std::span<const uint8_t> data) {
    SniffResult result;
    const std::string_view request(
        unsafe::ptr_cast<const char>(data.data()), data.size());
    size_t line_end = request.find("\r\n");
    if (line_end == std::string_view::npos) {
        if (IsValidRequestLinePrefix(request)) {
            result.need_more = true;
            result.protocol = constants::protocol::kHttp;
        }
        return result;
    }
    if (!IsSupportedRequestLine(request.substr(0, line_end))) {
        return result;
    }

    std::optional<HostPortView> host;
    for (size_t position = line_end + 2;; position = line_end + 2) {
        line_end = request.find("\r\n", position);
        if (line_end == std::string_view::npos) {
            if (IsValidHeaderLinePrefix(request.substr(position))) {
                result.need_more = true;
                result.protocol = constants::protocol::kHttp;
            }
            return result;
        }
        const std::string_view line =
            request.substr(position, line_end - position);
        if (line.empty()) {
            if (host) {
                result.success = true;
                result.protocol = constants::protocol::kHttp;
                result.domain.assign(host->host);
                result.port = host->port;
            }
            return result;
        }
        // obs-fold is rejected (RFC 9112 §5.2).
        if (line.front() == ' ' || line.front() == '\t') return result;

        const size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0) {
            return result;
        }
        const std::string_view name = line.substr(0, colon);
        const std::string_view value = TrimOws(line.substr(colon + 1));
        if (!transport::internet::IsValidHttpHeaderName(name) ||
            !transport::internet::IsValidHttpHeaderValue(value)) {
            return result;
        }
        if (!transport::internet::EqualsAsciiCI(name, "host")) continue;
        // RFC 9112 §3.2: more than one Host field is a bad request.
        if (host) return result;
        host = ParseHostValue(value);
        if (!host) return result;
    }
}

