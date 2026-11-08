#include "sniff/sniffer.hpp"
#include "core/constants.hpp"

#include <algorithm>


SniffResult SniffBittorrent(std::span<const uint8_t> data) {
    SniffResult result;
    static constexpr std::string_view kHandshake = "BitTorrent protocol";
    if (data.empty() || data[0] != static_cast<uint8_t>(kHandshake.size())) {
        return result;
    }
    const size_t prefix_len = std::min(data.size() - 1, kHandshake.size());
    if (!std::equal(data.begin() + 1,
                    data.begin() + 1 + static_cast<std::ptrdiff_t>(prefix_len),
                    kHandshake.begin())) {
        return result;
    }
    result.protocol = constants::protocol::kBitTorrent;
    if (data.size() < kHandshake.size() + 1) {
        result.need_more = true;
    } else {
        result.success = true;
    }
    return result;
}

SniffResult Sniffer::Sniff(std::span<const uint8_t> data, Network network) {
    if (network == Network::UDP) {
        return quic_.Sniff(data);
    }

    if (auto result = SniffTls(data); result.success || result.need_more) {
        return result;
    }
    if (auto result = SniffHttp(data); result.success || result.need_more) {
        return result;
    }
    return SniffBittorrent(data);
}

