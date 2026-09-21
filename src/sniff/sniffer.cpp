#include "acppnode/sniff/sniffer.hpp"
#include "acppnode/core/constants.hpp"

#include <algorithm>

namespace acpp {

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

SniffResult Sniff(std::span<const uint8_t> data) {
    return Sniff(data, Network::TCP);
}

SniffResult Sniff(std::span<const uint8_t> data, Network network) {
    if (network == Network::UDP) {
        return QuicSniffer{}.Sniff(data);
    }

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
