#pragma once

#include "acppnode/features/outbound/outbound.hpp"

#include <memory>
#include <string_view>

namespace acpp::proxyman::outbound {

class Handler;

// ============================================================================
// Manager - per-Worker outbound handler manager
//
// 对齐 xray-core app/proxyman/outbound.Manager。它只在 Worker io_context 上
// 访问，不加锁；dispatcher 按 outbound tag 获取 handler。
// ============================================================================
class Manager final : public features::outbound::Manager {
public:
    Manager();
    ~Manager() noexcept override;

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;

    [[nodiscard]] features::outbound::Handler* GetHandler(std::string_view tag) noexcept override;
    [[nodiscard]] features::outbound::Handler* GetDefaultHandler() noexcept override;

    [[nodiscard]] Handler* AddHandler(std::unique_ptr<Handler> handler) noexcept;
    void RemoveHandler(std::string_view tag) noexcept;
    void Clear() noexcept;
    void DrainRetiredHandlers() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::proxyman::outbound
