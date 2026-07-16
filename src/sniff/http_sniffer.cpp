#include "acppnode/sniff/sniffer.hpp"

#include "acppnode/common/unsafe.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/transport/internet/http_headers.hpp"

#include <algorithm>
#include <array>
#include <charconv>

namespace acpp {
namespace {

[[nodiscard]] bool EqualsAsciiCI(std::string_view lhs,
                                 std::string_view rhs) noexcept {
    return lhs.size() == rhs.size() &&
           std::ranges::equal(lhs, rhs, [](char left, char right) {
               auto lower = [](unsigned char value) {
                   return value >= 'A' && value <= 'Z'
                       ? static_cast<unsigned char>(value + ('a' - 'A'))
                       : value;
               };
               return lower(static_cast<unsigned char>(left)) ==
                      lower(static_cast<unsigned char>(right));
           });
}

[[nodiscard]] std::string_view TrimOws(std::string_view value) noexcept {
    while (!value.empty() &&
           (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() &&
           (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return value;
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

[[nodiscard]] bool IsSupportedRequestLine(std::string_view line) noexcept {
    const size_t first_space = line.find(' ');
    if (first_space == std::string_view::npos || first_space == 0) return false;
    const size_t second_space = line.find(' ', first_space + 1);
    if (second_space == std::string_view::npos ||
        second_space == first_space + 1 ||
        line.find(' ', second_space + 1) != std::string_view::npos) {
        return false;
    }

    static constexpr std::array<std::string_view, 9> kMethods{
        "GET", "POST", "PUT", "DELETE", "HEAD",
        "OPTIONS", "PATCH", "CONNECT", "TRACE"};
    const std::string_view method = line.substr(0, first_space);
    if (std::ranges::find(kMethods, method) == kMethods.end()) return false;

    const std::string_view target =
        line.substr(first_space + 1, second_space - first_space - 1);
    for (const unsigned char character : target) {
        if (character <= 0x20 || character == 0x7f) return false;
    }

    const std::string_view version = line.substr(second_space + 1);
    return version == "HTTP/1.0" || version == "HTTP/1.1";
}

}  // namespace

SniffResult HttpSniffer::Sniff(std::span<const uint8_t> data) {
    SniffResult result;
    auto host_port = ParseHttpHost(data);
    if (host_port) {
        result.success = true;
        result.protocol = constants::protocol::kHttp;
        result.domain.assign(host_port->host);
        result.port = host_port->port;
    }
    return result;
}

std::optional<HttpSniffer::HostPortView> HttpSniffer::ParseHttpHost(
    std::span<const uint8_t> data) {
    if (data.empty()) return std::nullopt;
    const std::string_view request(
        unsafe::ptr_cast<const char>(data.data()), data.size());
    const size_t header_end = request.find("\r\n\r\n");
    if (header_end == std::string_view::npos) return std::nullopt;

    const size_t request_line_end = request.find("\r\n");
    if (request_line_end == std::string_view::npos ||
        request_line_end > header_end ||
        !IsSupportedRequestLine(request.substr(0, request_line_end))) {
        return std::nullopt;
    }

    std::optional<HostPortView> host;
    size_t position = request_line_end + 2;
    while (position < header_end) {
        const size_t line_end = request.find("\r\n", position);
        if (line_end == std::string_view::npos || line_end > header_end) {
            return std::nullopt;
        }
        const std::string_view line =
            request.substr(position, line_end - position);
        if (line.empty() || line.front() == ' ' || line.front() == '\t') {
            return std::nullopt;
        }

        const size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0) {
            return std::nullopt;
        }
        const std::string_view name = line.substr(0, colon);
        const std::string_view value = TrimOws(line.substr(colon + 1));
        if (!transport::internet::IsValidHttpHeaderName(name) ||
            !transport::internet::IsValidHttpHeaderValue(value)) {
            return std::nullopt;
        }

        if (EqualsAsciiCI(name, "host")) {
            if (host || value.empty() ||
                !transport::internet::IsValidHttpAuthority(value)) {
                return std::nullopt;
            }

            HostPortView parsed;
            if (value.front() == '[') {
                const size_t close = value.find(']');
                if (close == std::string_view::npos || close == 1 ||
                    value.substr(1, close - 1).find(':') ==
                        std::string_view::npos) {
                    return std::nullopt;
                }
                parsed.host = value.substr(1, close - 1);
                const std::string_view suffix = value.substr(close + 1);
                if (!suffix.empty() &&
                    (suffix.front() != ':' ||
                     !ParsePort(suffix.substr(1), parsed.port))) {
                    return std::nullopt;
                }
            } else {
                if (value.find('[') != std::string_view::npos ||
                    value.find(']') != std::string_view::npos) {
                    return std::nullopt;
                }
                const size_t colon_position = value.find(':');
                if (colon_position == std::string_view::npos) {
                    parsed.host = value;
                } else {
                    if (value.rfind(':') != colon_position ||
                        colon_position == 0 ||
                        !ParsePort(
                            value.substr(colon_position + 1), parsed.port)) {
                        return std::nullopt;
                    }
                    parsed.host = value.substr(0, colon_position);
                }
            }
            if (parsed.host.empty()) return std::nullopt;
            host = parsed;
        }
        position = line_end + 2;
    }
    return host;
}

}  // namespace acpp
