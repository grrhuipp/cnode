#include "acppnode/sniff/sniffer.hpp"

namespace acpp {

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
