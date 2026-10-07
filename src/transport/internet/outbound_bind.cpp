#include "acppnode/transport/internet/outbound_bind.hpp"

#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/ip_address.hpp"
#include "acppnode/core/constants.hpp"

#include <asio/ip/network_v4.hpp>
#include <asio/ip/network_v6.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <functional>
#include <string>
#include <thread>

namespace acpp {
namespace {

uint64_t SourceHash(std::string_view ip, uint16_t port) noexcept {
    uint64_t value = 14695981039346656037ull;
    for (unsigned char byte : ip) {
        value = (value ^ byte) * 1099511628211ull;
    }
    for (const unsigned char byte : {
             static_cast<unsigned char>(port >> 8),
             static_cast<unsigned char>(port & 0xff)}) {
        value = (value ^ byte) * 1099511628211ull;
    }
    return value;
}

uint64_t MixHash(uint64_t value) noexcept {
    value += 0x9e3779b97f4a7c15ull;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ull;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebull;
    return value ^ (value >> 31);
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

std::optional<OutboundBind> OutboundBind::Parse(std::string_view value) {
    OutboundBind bind;
    if (value.empty()) return bind;
    if (value == constants::binding::kAuto) return Auto();

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
        if (text.empty() || text.contains('\0')) return std::nullopt;
        Entry entry;
        const auto slash = text.find('/');
        auto address = iputil::ParseLiteral(text.substr(0, slash));
        if (!address) return std::nullopt;
        *address = iputil::NormalizeAddress(*address);
        if (address->is_unspecified() && slash == std::string_view::npos) return std::nullopt;
        entry.is_v6 = address->is_v6();
        const unsigned int max_prefix = entry.is_v6 ? 128 : 32;
        unsigned int prefix = max_prefix;
        if (slash != std::string_view::npos) {
            const auto length = text.substr(slash + 1);
            if (length.empty()) return std::nullopt;
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
        prepared.push_back(std::move(entry));
    }
    bind.entries_ = std::make_shared<const std::vector<Entry>>(std::move(prepared));
    return bind;
}

OutboundBind::Selection OutboundBind::Select(
    const net::ip::address& remote,
    std::string_view inbound_source_ip,
    uint16_t inbound_source_port) const noexcept {
    if (mode_ == Mode::Explicit) return {.address = explicit_address_};
    if (mode_ != Mode::Ordered) return {};

    for (const auto& entry : *entries_) {
        if (entry.is_v6 != remote.is_v6()) continue;
        if (entry.prefix_length == (entry.is_v6 ? 128 : 32)) {
            return {.address = entry.network_or_ip};
        }
        const uint64_t key = policy_ == ChoicePolicy::Random
            ? RandomIndex() : SourceHash(inbound_source_ip, inbound_source_port);
        if (!entry.is_v6) {
            const auto prefix = entry.prefix_length;
            const uint32_t mask = prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
            const uint32_t ip = (entry.network_or_ip.to_v4().to_uint() & mask) |
                (static_cast<uint32_t>(key) & ~mask);
            return {.address = net::ip::address_v4(ip)};
        }
        auto bytes = entry.network_or_ip.to_v6().to_bytes();
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
        return {.address = net::ip::address_v6(bytes)};
    }
    return {};
}

}  // namespace acpp
