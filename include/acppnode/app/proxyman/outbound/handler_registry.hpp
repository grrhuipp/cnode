#pragma once

#include "acppnode/features/outbound/outbound.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/string_hash.hpp"

#include <memory>
#include <string_view>

namespace acpp {
class Outbound;
}

namespace acpp::proxyman::outbound {

// ============================================================================
// HandlerRegistry - per-Worker outbound handler registry
//
// 对齐 xray-core app/proxyman/outbound.Manager。它只在 Worker io_context 上
// 访问，不加锁；dispatcher 按 outbound tag 获取 handler。
// ============================================================================
class HandlerRegistry final : public features::outbound::HandlerLookup,
                              public memory::ThreadAllocated {
public:
    using HandlerPtr = features::outbound::HandlerLookup::HandlerPtr;

    HandlerRegistry();
    ~HandlerRegistry() noexcept override;

    HandlerRegistry(const HandlerRegistry&) = delete;
    HandlerRegistry& operator=(const HandlerRegistry&) = delete;

    [[nodiscard]] HandlerPtr GetHandler(std::string_view tag) noexcept override;

    // Mutations allocate tag/map/shared ownership and propagate failures.
    [[nodiscard]] HandlerPtr AddHandler(std::unique_ptr<Outbound> handler);
    [[nodiscard]] HandlerPtr ReplaceHandler(std::unique_ptr<Outbound> handler);
    void RemoveHandler(std::string_view tag);

private:
    using HandlerMap = memory::ThreadLocalUnorderedMap<
        memory::ThreadLocalString,
        std::shared_ptr<Outbound>,
        TransparentStringHash,
        TransparentStringEq>;

    HandlerMap handlers_;
};

}  // namespace acpp::proxyman::outbound
