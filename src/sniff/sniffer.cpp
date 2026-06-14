#include "acppnode/sniff/sniffer.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/core/constants.hpp"

namespace acpp {

TargetAddress SniffResult::ToTarget() const {
    TargetAddress addr;
    addr.type = AddressType::Domain;
    addr.host.assign(domain.data(), domain.size());
    addr.port = port;
    return addr;
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
// 复合嗅探：依次尝试 TLS → HTTP，栈上构造，零堆分配
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

    return SniffResult{};
}

}  // namespace acpp
