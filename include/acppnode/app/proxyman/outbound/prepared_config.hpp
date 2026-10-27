#pragma once

#include "acppnode/common/asio_types.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace acpp {
class Outbound;
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

struct PreparedOutboundCreator {
    using CreateFn = std::unique_ptr<::acpp::Outbound> (*)(
        std::string_view tag,
        const OutboundProtocolSettings* settings,
        ::acpp::net::io_context& io_context,
        ::acpp::app::dns::DNS& dns,
        std::chrono::seconds dial_timeout);
    using StatelessCreateFn = std::unique_ptr<::acpp::Outbound> (*)(
        std::string_view tag,
        ::acpp::net::io_context& io_context,
        ::acpp::app::dns::DNS& dns,
        std::chrono::seconds dial_timeout);

    std::shared_ptr<const OutboundProtocolSettings> settings;
    CreateFn create_fn = nullptr;
    StatelessCreateFn stateless_fn = nullptr;

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

    template <typename OutboundType = ::acpp::Outbound>
    [[nodiscard]] std::unique_ptr<OutboundType> operator()(
        std::string_view tag,
        ::acpp::net::io_context& io_context,
        ::acpp::app::dns::DNS& dns,
        std::chrono::seconds dial_timeout) const {
        if (create_fn) {
            return create_fn(tag, settings.get(), io_context, dns, dial_timeout);
        }
        return stateless_fn(tag, io_context, dns, dial_timeout);
    }
};

template <typename State, auto Fn>
[[nodiscard]] PreparedOutboundCreator MakePreparedOutboundCreator(State state) {
    using Decayed = std::decay_t<State>;
    using Holder = TypedOutboundProtocolSettings<Decayed>;
    return PreparedOutboundCreator{
        std::make_shared<const Holder>(std::move(state)),
        +[](std::string_view tag,
            const OutboundProtocolSettings* base,
            ::acpp::net::io_context& io_context,
            ::acpp::app::dns::DNS& dns,
            std::chrono::seconds dial_timeout) -> std::unique_ptr<::acpp::Outbound> {
            const auto* holder = static_cast<const Holder*>(base);
            return Fn(tag, holder->value, io_context, dns, dial_timeout);
        }};
}

struct PreparedOutboundConfig {
    std::string tag;
    std::string protocol;
    PreparedOutboundCreator create;
};
}  // namespace acpp::proxyman::outbound
