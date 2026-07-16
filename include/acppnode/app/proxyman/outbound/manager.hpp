#pragma once

#include "acppnode/features/outbound/outbound.hpp"

#include <memory>
#include <string_view>

namespace acpp {
class Outbound;
}

namespace acpp::proxyman::outbound {

// ============================================================================
// Manager - per-Worker outbound handler manager
//
// 对齐 xray-core app/proxyman/outbound.Manager。它只在 Worker io_context 上
// 访问，不加锁；dispatcher 按 outbound tag 获取 handler。
// ============================================================================
class Manager final : public features::outbound::Manager {
public:
    using HandlerPtr = features::outbound::Manager::HandlerPtr;

    Manager();
    ~Manager() noexcept override;

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;

    [[nodiscard]] HandlerPtr GetHandler(std::string_view tag) noexcept override;

    // Mutations allocate tag/map/shared ownership and propagate failures.
    [[nodiscard]] HandlerPtr AddHandler(std::unique_ptr<Outbound> handler);
    [[nodiscard]] HandlerPtr ReplaceHandler(std::unique_ptr<Outbound> handler);
    void RemoveHandler(std::string_view tag);
    void Clear() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::proxyman::outbound
