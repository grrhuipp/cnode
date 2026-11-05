#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/proxy/outbound.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace acpp {
class AwaitableTaskGroup;
namespace app::dns {
class DNS;
}
}  // namespace acpp

namespace acpp::proxyman::outbound {

class OutboundProtocolSettings {
public:
    virtual ~OutboundProtocolSettings() noexcept = default;
};

template <typename T>
struct TypedOutboundProtocolSettings final : OutboundProtocolSettings {
    explicit TypedOutboundProtocolSettings(T v) : value(std::move(v)) {}
    T value;
};

// Session-domain runtime handed to a handler: native reactor, DNS control client,
// dial timeout and resident task group. The latter joins before host teardown.
struct PreparedOutboundCreator {
    using CreateFn = std::unique_ptr<::acpp::Outbound> (*)(
        std::string_view tag,
        const std::shared_ptr<const OutboundProtocolSettings>& settings,
        ::acpp::net::io_context& io_context,
        ::acpp::app::dns::DNS& dns,
        std::chrono::seconds dial_timeout,
        ::acpp::AwaitableTaskGroup& tasks);
    using StatelessCreateFn = std::unique_ptr<::acpp::Outbound> (*)(
        std::string_view tag,
        ::acpp::net::io_context& io_context,
        ::acpp::app::dns::DNS& dns,
        std::chrono::seconds dial_timeout,
        ::acpp::AwaitableTaskGroup& tasks);

    std::shared_ptr<const OutboundProtocolSettings> settings;
    CreateFn create_fn = nullptr;
    StatelessCreateFn stateless_fn = nullptr;
    // Mutable protocol state that must survive individual inbound connections.
    // Such handlers live in a stable, joinable execution domain per tag.
    bool persistent_state = false;

    PreparedOutboundCreator() noexcept = default;

    PreparedOutboundCreator(StatelessCreateFn fn) noexcept
        : stateless_fn(fn) {}

    PreparedOutboundCreator(
        std::shared_ptr<const OutboundProtocolSettings> s,
        CreateFn fn) noexcept
        : settings(std::move(s))
        , create_fn(fn) {}

    [[nodiscard]] explicit operator bool() const noexcept {
        return create_fn != nullptr || stateless_fn != nullptr;
    }

    [[nodiscard]] std::unique_ptr<::acpp::Outbound> operator()(
        std::string_view tag,
        ::acpp::net::io_context& io_context,
        ::acpp::app::dns::DNS& dns,
        std::chrono::seconds dial_timeout,
        ::acpp::AwaitableTaskGroup& tasks) const {
        if (create_fn) {
            return create_fn(tag, settings, io_context, dns, dial_timeout, tasks);
        }
        return stateless_fn(tag, io_context, dns, dial_timeout, tasks);
    }
};

template <typename State, auto Fn>
[[nodiscard]] PreparedOutboundCreator MakePreparedOutboundCreator(
    State state, bool persistent_state = false) {
    using Decayed = std::decay_t<State>;
    using Holder = TypedOutboundProtocolSettings<Decayed>;
    auto creator = PreparedOutboundCreator{
        std::make_shared<const Holder>(std::move(state)),
        +[](std::string_view tag,
            const std::shared_ptr<const OutboundProtocolSettings>& base,
            ::acpp::net::io_context& io_context,
            ::acpp::app::dns::DNS& dns,
            std::chrono::seconds dial_timeout,
            ::acpp::AwaitableTaskGroup& tasks) -> std::unique_ptr<::acpp::Outbound> {
            const auto* holder = static_cast<const Holder*>(base.get());
            return Fn(tag, std::shared_ptr<const Decayed>(base, &holder->value),
                      io_context, dns, dial_timeout, tasks);
        }};
    creator.persistent_state = persistent_state;
    return creator;
}

struct PreparedOutboundConfig {
    std::string tag;
    std::string protocol;
    PreparedOutboundCreator create;
};
}  // namespace acpp::proxyman::outbound
