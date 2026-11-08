#include "transport/internet/outbound_bind.hpp"

#include "common/ip_utils.hpp"
#include "common/ip_address.hpp"
#include "core/constants.hpp"
#include "transport/internet/http_headers.hpp"

#include <asio/ip/network_v4.hpp>
#include <asio/ip/network_v6.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <functional>
#include <string>
#include <thread>

namespace {

uint64_t MixHash(uint64_t value) noexcept {
    value += 0x9e3779b97f4a7c15ull;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ull;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebull;
    return value ^ (value >> 31);
}

uint64_t IpKeyHash(std::string_view ip) noexcept {
    uint64_t value = 14695981039346656037ull;
    for (const unsigned char byte : ip) {
        value = (value ^ byte) * 1099511628211ull;
    }
    return MixHash(value);
}

uint64_t UserKeyHash(
    int64_t user_id,
    std::string_view user_email,
    std::string_view fallback_ip,
    std::string_view inbound_tag) noexcept {
    if (user_id <= 0 && user_email.empty()) {
        return IpKeyHash(fallback_ip);
    }
    uint64_t value = 14695981039346656037ull;
    for (const unsigned char byte : inbound_tag) {
        value = (value ^ byte) * 1099511628211ull;
    }
    value = (value ^ 0xffu) * 1099511628211ull;
    const uint64_t uid = user_id > 0 ? static_cast<uint64_t>(user_id) : 0;
    for (unsigned shift = 0; shift < 64; shift += 8) {
        value = (value ^ static_cast<unsigned char>(uid >> shift)) *
                1099511628211ull;
    }
    value = (value ^ 0xffu) * 1099511628211ull;
    for (const unsigned char byte : user_email) {
        value = (value ^ byte) * 1099511628211ull;
    }
    return MixHash(value);
}

uint64_t RandomIndex() noexcept {
    static thread_local uint64_t state =
        static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()) ^
        std::hash<std::thread::id>{}(std::this_thread::get_id()) ^
        0x9e3779b97f4a7c15ull;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return state * 2685821657736338717ull;
}

}  // namespace

OutboundBind OutboundBind::Auto() noexcept {
    OutboundBind bind;
    bind.mode_ = Mode::Auto;
    return bind;
}

std::optional<net::ip::address> OutboundBind::BindAddressFor(
    const tcp::endpoint* inbound_local, const net::ip::address& remote) const noexcept {
    if (mode_ == Mode::Explicit) {
        return explicit_address_;
    }
    if (mode_ != Mode::Auto || !inbound_local) {
        return std::nullopt;
    }
    // Same-in-same-out: reuse the inbound local address when it can source
    // a connection to `remote`.
    const auto local = iputil::NormalizeAddress(inbound_local->address());
    const auto normalized_remote = iputil::NormalizeAddress(remote);
    if (local.is_unspecified() || local.is_loopback() ||
        normalized_remote.is_unspecified() || normalized_remote.is_loopback() ||
        local.is_v4() != normalized_remote.is_v4()) {
        return std::nullopt;
    }
    if (local.is_v6() &&
        (local.to_v6().is_link_local() || normalized_remote.to_v6().is_link_local())) {
        return std::nullopt;
    }
    return local;
}

std::optional<OutboundBind> OutboundBind::Parse(std::string_view value) {
    OutboundBind bind;
    if (value.empty()) return bind;
    if (transport::internet::EqualsAsciiCI(value, constants::binding::kAuto)) return Auto();

    auto address = iputil::ParseLiteral(value);
    if (!address) return std::nullopt;
    *address = iputil::NormalizeAddress(*address);
    if (address->is_unspecified()) return bind;
    bind.mode_ = Mode::Explicit;
    bind.explicit_address_ = std::move(*address);
    return bind;
}

std::optional<OutboundBind> OutboundBind::ParseCandidates(
    std::span<const std::string_view> entries, ChoicePolicy policy) {
    if (entries.empty()) return std::nullopt;
    OutboundBind bind;
    bind.mode_ = Mode::Ordered;
    bind.policy_ = policy;
    std::vector<Entry> prepared;
    prepared.reserve(entries.size());
    for (const auto text : entries) {
        if (text.empty() || text.find('\0') != std::string_view::npos) return std::nullopt;
        Entry entry;
        const auto slash = text.find('/');
        auto address = iputil::ParseLiteral(text.substr(0, slash));
        if (!address) return std::nullopt;
        const auto normalized = iputil::NormalizeAddress(*address);
        if (slash != std::string_view::npos && address->is_v6() != normalized.is_v6()) {
            return std::nullopt;
        }
        *address = normalized;
        entry.is_v6 = address->is_v6();
        const unsigned int max_prefix = entry.is_v6 ? 128 : 32;
        unsigned int prefix = max_prefix;
        if (slash != std::string_view::npos) {
            const auto length = text.substr(slash + 1);
            if (length.empty() || (length.size() > 1 && length.front() == '0')) {
                return std::nullopt;
            }
            const auto [end, error] = std::from_chars(
                length.data(), length.data() + length.size(), prefix);
            if (error != std::errc{} || end != length.data() + length.size() ||
                prefix > max_prefix) return std::nullopt;
        }
        entry.prefix_length = static_cast<uint8_t>(prefix);
        entry.network_or_ip = slash == std::string_view::npos ? *address :
            entry.is_v6
                ? net::ip::address(net::ip::network_v6(
                    address->to_v6(), static_cast<unsigned short>(prefix)).network())
                : net::ip::address(net::ip::network_v4(
                    address->to_v4(), static_cast<unsigned short>(prefix)).network());
        if (entry.network_or_ip.is_unspecified()) return std::nullopt;
        prepared.push_back(std::move(entry));
    }
    bind.entries_ = std::make_shared<const std::vector<Entry>>(std::move(prepared));
    return bind;
}

OutboundBind::Selection OutboundBind::Select(
    const net::ip::address& remote,
    std::string_view client_ip,
    int64_t user_id,
    std::string_view user_email,
    std::string_view inbound_tag) const noexcept {
    if (mode_ == Mode::Explicit) return {.address = explicit_address_};
    if (mode_ != Mode::Ordered) return {};

    const auto normalized_remote = iputil::NormalizeAddress(remote);
    for (const auto& entry : *entries_) {
        if (entry.is_v6 != normalized_remote.is_v6()) continue;
        if (entry.prefix_length == (entry.is_v6 ? 128 : 32)) {
            return {.address = entry.network_or_ip};
        }
        const uint64_t key = policy_ == ChoicePolicy::Random
            ? RandomIndex()
            : policy_ == ChoicePolicy::UserHash
                ? UserKeyHash(user_id, user_email, client_ip, inbound_tag)
                : IpKeyHash(client_ip);
        if (!entry.is_v6) {
            const auto prefix = entry.prefix_length;
            const uint32_t mask = prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
            const uint32_t ip = (entry.network_or_ip.to_v4().to_uint() & mask) |
                (static_cast<uint32_t>(key) & ~mask);
            return {.address = net::ip::address_v4(ip)};
        }
        const auto v6 = entry.network_or_ip.to_v6();
        auto bytes = v6.to_bytes();
        const uint64_t high = key;
        const uint64_t low = policy_ == ChoicePolicy::Random ? RandomIndex() : MixHash(key);
        for (size_t i = 0; i < bytes.size(); ++i) {
            const unsigned bits = entry.prefix_length > i * 8
                ? std::min<unsigned>(8, entry.prefix_length - static_cast<unsigned>(i * 8))
                : 0;
            const uint8_t mask = bits == 0 ? 0 : static_cast<uint8_t>(0xffu << (8 - bits));
            const uint64_t word = i < 8 ? high : low;
            const unsigned shift = static_cast<unsigned>(i < 8 ? (7 - i) * 8 : (15 - i) * 8);
            const auto suffix = static_cast<uint8_t>(word >> shift);
            bytes[i] = (bytes[i] & mask) | (suffix & static_cast<uint8_t>(~mask));
        }
        return {.address = net::ip::address_v6(bytes, v6.scope_id())};
    }
    return {};
}

