#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/features/outbound/outbound.hpp"

#include <memory>
#include <string>
#include <string_view>

namespace acpp { class Outbound; }

namespace acpp::proxyman::outbound {

// Immutable handler-table snapshots serve requests. Mutation enters the bounded
// owner strand, builds a complete replacement, publishes it, then joins retired
// handlers. A selected const handler remains owned until its request completes.
class Manager final : public features::outbound::Manager {
public:
    using HandlerPtr = features::outbound::Manager::HandlerPtr;
    explicit Manager(net::any_io_executor executor);
    ~Manager() noexcept override;
    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;

    [[nodiscard]] HandlerPtr GetHandler(std::string_view tag) const noexcept override;
    [[nodiscard]] net::awaitable<HandlerPtr> AddHandler(std::unique_ptr<Outbound> handler);
    [[nodiscard]] net::awaitable<HandlerPtr> ReplaceHandler(std::unique_ptr<Outbound> handler);
    net::awaitable<void> RemoveHandler(std::string tag);
    net::awaitable<void> Clear();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace acpp::proxyman::outbound
