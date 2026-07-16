#include "acppnode/sniff/sniffer.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/core/constants.hpp"

#include <algorithm>

namespace acpp {

TargetAddress SniffResult::ToTarget() const {
    return TargetAddress(domain, port);
}

std::string SniffResult::ToString() const {
    if (!success) return std::string(constants::state::kNone);
    std::string out;
    out.reserve(protocol.size() + 1 + domain.size() + (port > 0 ? 6 : 0));
    out.append(protocol);
    out.push_back(':');
    out.append(domain.data(), domain.size());
    if (port > 0) {
        out.push_back(':');
        out.append(std::to_string(port));
    }
    return out;
}

// ============================================================================
SniffResult BittorrentSniffer::Sniff(std::span<const uint8_t> data) {
    SniffResult result;
    static constexpr std::string_view kHandshake = "BitTorrent protocol";
    if (data.size() >= kHandshake.size() + 1 &&
        data[0] == static_cast<uint8_t>(kHandshake.size()) &&
        std::equal(kHandshake.begin(), kHandshake.end(), data.begin() + 1)) {
        result.success = true;
        result.protocol = constants::protocol::kBitTorrent;
    }
    return result;
}

// ============================================================================
// 复合嗅探：依次尝试 TLS → HTTP → BitTorrent，栈上构造，零堆分配
// ============================================================================
SniffResult Sniff(std::span<const uint8_t> data) {
    TlsSniffer tls;
    if (auto result = tls.Sniff(data); result.success) {
        return result;
    }

    HttpSniffer http;
    if (auto result = http.Sniff(data); result.success) {
        return result;
    }

    BittorrentSniffer bittorrent;
    if (auto result = bittorrent.Sniff(data); result.success) {
        return result;
    }

    return SniffResult{};
}

}  // namespace acpp
