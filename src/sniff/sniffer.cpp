#include "acppnode/sniff/sniffer.hpp"
#include "acppnode/core/constants.hpp"

#include <algorithm>

namespace acpp {

SniffResult SniffBittorrent(std::span<const uint8_t> data) {
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

SniffResult Sniffer::Sniff(std::span<const uint8_t> data, Network network) {
    if (network == Network::UDP) {
        return quic_.Sniff(data);
    }

    if (auto result = SniffTls(data); result.success) {
        return result;
    }
    if (auto result = SniffHttp(data); result.success) {
        return result;
    }
    return SniffBittorrent(data);
}

}  // namespace acpp
