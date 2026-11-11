#include "transport/internet/outbound_bind.hpp"

#include "common/ascii.hpp"
#include "common/hash.hpp"
#include "common/ip_utils.hpp"
#include "core/constants.hpp"


#include <algorithm>
#include <chrono>
#include <functional>
#include <thread>
#include <utility>

namespace transport::internet {

namespace {

uint64_t IpKeyHash(std::string_view ip) noexcept {
    return common::Mix64(common::Fnv1a64(ip));
}

uint64_t UserKeyHash(
    int64_t user_id,
    std::string_view user_email,
    std::string_view fallback_ip,
    std::string_view inbound_tag) noexcept {
    if (user_id <= 0 && user_email.empty()) {
        return IpKeyHash(fallback_ip);
    }
    uint64_t value = common::Fnv1a64Step(common::Fnv1a64(inbound_tag), 0xff);
    const uint64_t uid = user_id > 0 ? static_cast<uint64_t>(user_id) : 0;
    for (unsigned shift = 0; shift < 64; shift += 8) {
        value = common::Fnv1a64Step(value, static_cast<uint8_t>(uid >> shift));
    }
    return common::Mix64(common::Fnv1a64(user_email, common::Fnv1a64Step(value, 0xff)));
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
    if (common::EqualsAsciiCI(value, constants::binding::kAuto)) return Auto();

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
        const auto network = iputil::ParseNetwork(text);
        if (!network) return std::nullopt;
        Entry entry;
        entry.is_v6 = network->address.is_v6();
        entry.prefix_length = network->prefix_length;
        entry.network_or_ip = network->address;
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
        const uint64_t low = policy_ == ChoicePolicy::Random ? RandomIndex() : common::Mix64(key);
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

}  // namespace transport::internet
