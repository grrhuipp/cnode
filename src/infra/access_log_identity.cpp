#include "acppnode/infra/access_log_reporter.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <ranges>
#include <string>
#include <string_view>

namespace acpp::accesslog {

namespace {

std::string LowerCopy(std::string_view value) {
    std::string out(value);
    std::ranges::transform(out, out.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return out;
}

std::string TrimCopy(std::string_view value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
        value.remove_prefix(1);
    }
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
        value.remove_suffix(1);
    }
    return std::string(value);
}

}  // namespace

std::string NormalizePanelApiHost(std::string_view api_host) {
    const std::string trimmed = TrimCopy(api_host);
    const std::string_view value(trimmed);
    const size_t scheme_pos = value.find("://");
    if (scheme_pos == std::string_view::npos) {
        return {};
    }
    const std::string scheme = LowerCopy(value.substr(0, scheme_pos));
    if (scheme != "http" && scheme != "https") {
        return {};
    }

    std::string_view rest = value.substr(scheme_pos + 3);
    const size_t authority_end = rest.find_first_of("/?#");
    std::string_view authority = rest.substr(0, authority_end);
    std::string safe_path;
    if (authority_end != std::string_view::npos && rest[authority_end] == '/') {
        const std::string_view suffix = rest.substr(authority_end);
        const size_t path_end = suffix.find_first_of("?#");
        safe_path.assign(suffix.substr(0, path_end));
        while (safe_path.size() > 1 && safe_path.back() == '/') {
            safe_path.pop_back();
        }
        if (safe_path == "/") {
            safe_path.clear();
        }
    }
    if (authority.empty()) {
        return {};
    }
    if (const size_t at = authority.rfind('@'); at != std::string_view::npos) {
        authority.remove_prefix(at + 1);
    }
    if (authority.empty()) {
        return {};
    }

    std::string host;
    std::string port;
    bool ipv6 = false;
    if (authority.front() == '[') {
        const size_t close = authority.find(']');
        if (close == std::string_view::npos || close == 1) {
            return {};
        }
        ipv6 = true;
        host = LowerCopy(authority.substr(1, close - 1));
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') {
                return {};
            }
            port.assign(authority.substr(close + 2));
        }
    } else {
        const size_t first_colon = authority.find(':');
        const size_t last_colon = authority.rfind(':');
        if (first_colon != std::string_view::npos && first_colon != last_colon) {
            return {};
        }
        if (last_colon != std::string_view::npos) {
            host = LowerCopy(authority.substr(0, last_colon));
            port.assign(authority.substr(last_colon + 1));
        } else {
            host = LowerCopy(authority);
        }
    }
    if (host.empty()) {
        return {};
    }
    if (!port.empty()) {
        uint32_t parsed_port = 0;
        const auto parsed = std::from_chars(
            port.data(), port.data() + port.size(), parsed_port);
        if (parsed.ec != std::errc{} ||
            parsed.ptr != port.data() + port.size() ||
            parsed_port == 0 || parsed_port > 65535) {
            return {};
        }
        if ((scheme == "http" && parsed_port == 80) ||
            (scheme == "https" && parsed_port == 443)) {
            port.clear();
        }
    }

    std::string normalized = scheme + "://";
    if (ipv6) {
        normalized.push_back('[');
        normalized.append(host);
        normalized.push_back(']');
    } else {
        normalized.append(host);
    }
    if (!port.empty()) {
        normalized.push_back(':');
        normalized.append(port);
    }
    normalized.append(safe_path);
    return normalized;
}

std::filesystem::path ResolveSpoolPath(
    const std::filesystem::path& log_dir) {
    return log_dir.empty()
        ? std::filesystem::path("access-spool")
        : log_dir / "access-spool";
}

std::filesystem::path ResolveErrorSpoolPath(
    const std::filesystem::path& log_dir) {
    return log_dir.empty()
        ? std::filesystem::path("error-spool")
        : log_dir / "error-spool";
}

}  // namespace acpp::accesslog
