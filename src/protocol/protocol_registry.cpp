#include "acppnode/protocol/protocol_registry.hpp"

#include <ranges>

namespace acpp {

OutboundFactory& OutboundFactory::Instance() noexcept {
    static OutboundFactory instance;
    return instance;
}

void OutboundFactory::Register(std::string_view protocol, Creator creator) {
    creators_.insert_or_assign(std::string(protocol), std::move(creator));
}

std::unique_ptr<IOutbound> OutboundFactory::Create(
    const OutboundConfig& config,
    net::any_io_executor executor,
    IDnsService* dns,
    UDPSessionManager* udp_mgr,
    std::chrono::seconds dial_timeout) const {

    auto it = creators_.find(config.protocol);
    if (it == creators_.end()) {
        return nullptr;
    }
    return it->second(config, executor, dns, udp_mgr, dial_timeout);
}

bool OutboundFactory::Has(std::string_view protocol) const {
    // 透明比较器允许直接用 string_view，无需构造临时 string
    return creators_.contains(protocol);
}

std::vector<std::string> OutboundFactory::RegisteredProtocols() const {
    std::vector<std::string> result;
    result.reserve(creators_.size());
    for (const auto& name : creators_ | std::views::keys) {
        result.push_back(name);
    }
    return result;
}

}  // namespace acpp
