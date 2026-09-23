#include "acppnode/transport/internet/outbound_bind.hpp"

#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/ip_address.hpp"
#include "acppnode/core/constants.hpp"

#include <asio/ip/network_v4.hpp>
#include <asio/ip/network_v6.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstring>
#include <functional>
#include <ranges>
#include <string>
#include <thread>

#ifdef _WIN32
#include <iphlpapi.h>
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#endif

namespace acpp {
namespace {

std::vector<net::ip::address> LocalInterfaceAddresses() {
    std::vector<net::ip::address> addresses;
    auto append = [&](const sockaddr* sock) {
        if (!sock) return;
        if (sock->sa_family == AF_INET) {
            net::ip::address_v4::bytes_type bytes{};
            std::memcpy(bytes.data(),
                        &reinterpret_cast<const sockaddr_in*>(sock)->sin_addr,
                        bytes.size());
            addresses.emplace_back(net::ip::address_v4(bytes));
        } else if (sock->sa_family == AF_INET6) {
            const auto* addr = reinterpret_cast<const sockaddr_in6*>(sock);
            net::ip::address_v6::bytes_type bytes{};
            std::memcpy(bytes.data(), &addr->sin6_addr, bytes.size());
            addresses.emplace_back(iputil::NormalizeAddress(
                net::ip::address_v6(bytes, addr->sin6_scope_id)));
        }
    };
#ifdef _WIN32
    ULONG length = 16 * 1024;
    std::vector<unsigned char> buffer(length);
    ULONG result = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3 && result == ERROR_BUFFER_OVERFLOW; ++attempt) {
        result = GetAdaptersAddresses(
            AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                           GAA_FLAG_SKIP_DNS_SERVER,
            nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &length);
        if (result == ERROR_BUFFER_OVERFLOW) buffer.resize(length);
    }
    if (result == NO_ERROR) {
        for (auto* adapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
             adapter; adapter = adapter->Next) {
            if (adapter->OperStatus != IfOperStatusUp) continue;
            for (auto* item = adapter->FirstUnicastAddress; item; item = item->Next) {
                if (item->DadState == IpDadStatePreferred) {
                    append(item->Address.lpSockaddr);
                }
            }
        }
    }
#else
    ifaddrs* interfaces = nullptr;
    if (getifaddrs(&interfaces) == 0) {
        for (auto* item = interfaces; item; item = item->ifa_next) {
            if ((item->ifa_flags & IFF_UP) != 0) append(item->ifa_addr);
        }
        freeifaddrs(interfaces);
    }
#endif
    std::ranges::sort(addresses, [](const auto& a, const auto& b) {
        return a.to_string() < b.to_string();
    });
    addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());
    return addresses;
}

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
    if (value.empty()) {
        return bind;
    }
    if (value == constants::binding::kAuto) {
        return Auto();
    }

    auto address = iputil::ParseLiteral(value);
    if (!address) {
        return std::nullopt;
    }
    *address = iputil::NormalizeAddress(*address);
    if (address->is_unspecified()) {
        return bind;
    }
    bind.mode_ = Mode::Explicit;
    bind.explicit_address_ = std::move(*address);
    return bind;
}

std::optional<OutboundBind> OutboundBind::ParseCandidates(
    std::span<const std::string_view> entries, ChoicePolicy policy) {
    const auto local_addresses = LocalInterfaceAddresses();
    return ParseCandidates(entries, local_addresses, policy);
}

std::optional<OutboundBind> OutboundBind::ParseCandidates(
    std::span<const std::string_view> entries,
    std::span<const net::ip::address> local_addresses,
    ChoicePolicy policy) {
    if (entries.empty()) return std::nullopt;
    OutboundBind bind;
    bind.mode_ = Mode::Ordered;
    bind.policy_ = policy;
    std::vector<Entry> prepared;
    prepared.reserve(entries.size());
    for (const auto text : entries) {
        if (text.empty() || text.contains('\0')) return std::nullopt;
        Entry entry;
        if (const auto slash = text.find('/'); slash != std::string_view::npos) {
            auto address = iputil::ParseLiteral(text.substr(0, slash));
            if (!address) return std::nullopt;
            *address = iputil::NormalizeAddress(*address);
            unsigned int prefix = 0;
            const auto length = text.substr(slash + 1);
            if (length.empty()) return std::nullopt;
            auto [end, error] = std::from_chars(
                length.data(), length.data() + length.size(), prefix);
            if (error != std::errc{} || end != length.data() + length.size() ||
                prefix > (address->is_v6() ? 128u : 32u)) return std::nullopt;
            entry.is_v6 = address->is_v6();
            for (const auto& local : local_addresses) {
                if (local.is_v6() != entry.is_v6 || local.is_unspecified()) continue;
                if (entry.is_v6 && address->to_v6().scope_id() != 0 &&
                    local.to_v6().scope_id() != address->to_v6().scope_id()) continue;
                if (entry.is_v6 ?
                    net::ip::network_v6(local.to_v6(), static_cast<unsigned short>(prefix)).network().to_bytes() ==
                        net::ip::network_v6(address->to_v6(), static_cast<unsigned short>(prefix)).network().to_bytes() :
                    net::ip::network_v4(local.to_v4(), static_cast<unsigned short>(prefix)).network() ==
                        net::ip::network_v4(address->to_v4(), static_cast<unsigned short>(prefix)).network()) {
                    entry.local_addresses.push_back(local);
                }
            }
        } else {
            auto address = iputil::ParseLiteral(text);
            if (!address) return std::nullopt;
            *address = iputil::NormalizeAddress(*address);
            if (address->is_unspecified()) return std::nullopt;
            entry.is_v6 = address->is_v6();
            if (std::ranges::find(local_addresses, *address) != local_addresses.end()) {
                entry.local_addresses.push_back(*address);
            }
        }
        std::ranges::sort(entry.local_addresses, [](const auto& a, const auto& b) {
            return a.to_string() < b.to_string();
        });
        entry.local_addresses.erase(
            std::unique(entry.local_addresses.begin(), entry.local_addresses.end()),
            entry.local_addresses.end());
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

    bool has_same_family = false;
    for (const auto& entry : *entries_) {
        if (entry.is_v6 != remote.is_v6()) continue;
        has_same_family = true;
        if (entry.local_addresses.empty()) continue;
        const size_t index = static_cast<size_t>(
            (policy_ == ChoicePolicy::Random
                ? RandomIndex()
                : SourceHash(inbound_source_ip, inbound_source_port)) %
            entry.local_addresses.size());
        return {.address = entry.local_addresses[index]};
    }
    return {.unavailable = has_same_family};
}

}  // namespace acpp
