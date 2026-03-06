#pragma once

#include "acppnode/protocol/outbound.hpp"

namespace acpp {

// ============================================================================
// Blackhole 出站设置
// ============================================================================
struct BlackholeSettings {
    std::string response = "none";  // none / http
};

// ============================================================================
// Blackhole Outbound - 黑洞出站（丢弃所有连接）
// ============================================================================
class BlackholeOutbound final : public IOutbound {
public:
    BlackholeOutbound(const std::string& tag, const BlackholeSettings& settings);

    cobalt::task<std::expected<OutboundTransportTarget, ErrorCode>>
        ResolveTransportTarget(SessionContext& ctx) override;
    
    std::string Tag() const override { return tag_; }

private:
    std::string tag_;
    BlackholeSettings settings_;
};

// ============================================================================
// 创建 Blackhole Outbound 的工厂函数
// ============================================================================
std::unique_ptr<IOutbound> CreateBlackholeOutbound(
    const std::string& tag,
    const BlackholeSettings& settings = {});

}  // namespace acpp
