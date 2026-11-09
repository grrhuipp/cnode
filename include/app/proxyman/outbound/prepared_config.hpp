#pragma once

#include "common/asio_types.hpp"
#include "proxy/outbound.hpp"
#include "transport/internet/outbound_sender.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

class AwaitableTaskGroup;

namespace proxyman::outbound {

class OutboundProtocolSettings {
public:
    virtual ~OutboundProtocolSettings() noexcept = default;
};

template <typename T>
struct TypedOutboundProtocolSettings final : OutboundProtocolSettings {
    explicit TypedOutboundProtocolSettings(T v) : value(std::move(v)) {}
    T value;
};

// Constructs the protocol instance for one executing domain: its native reactor
// and resident task group (joined before the domain's teardown). Dialing goes
// through the owning Handler's OutboundDialer, never through creator state.
struct PreparedOutboundCreator {
    using CreateFn = std::unique_ptr<::Outbound> (*)(
        std::string_view tag,
        const std::shared_ptr<const OutboundProtocolSettings>& settings,
        ::net::io_context& io_context,
        ::AwaitableTaskGroup& tasks);

    std::shared_ptr<const OutboundProtocolSettings> settings;
    CreateFn create_fn = nullptr;

    PreparedOutboundCreator() noexcept = default;

    PreparedOutboundCreator(
        std::shared_ptr<const OutboundProtocolSettings> s,
        CreateFn fn) noexcept
        : settings(std::move(s))
        , create_fn(fn) {}

    [[nodiscard]] explicit operator bool() const noexcept {
        return create_fn != nullptr;
    }

    [[nodiscard]] std::unique_ptr<::Outbound> operator()(
        std::string_view tag,
        ::net::io_context& io_context,
        ::AwaitableTaskGroup& tasks) const {
        return create_fn(tag, settings, io_context, tasks);
    }
};

template <typename State, auto Fn>
[[nodiscard]] PreparedOutboundCreator MakePreparedOutboundCreator(State state) {
    using Decayed = std::decay_t<State>;
    using Holder = TypedOutboundProtocolSettings<Decayed>;
    return PreparedOutboundCreator{
        std::make_shared<const Holder>(std::move(state)),
        +[](std::string_view tag,
            const std::shared_ptr<const OutboundProtocolSettings>& base,
            ::net::io_context& io_context,
            ::AwaitableTaskGroup& tasks) -> std::unique_ptr<::Outbound> {
            const auto* holder = static_cast<const Holder*>(base.get());
            return Fn(tag, std::shared_ptr<const Decayed>(base, &holder->value),
                      io_context, tasks);
        }};
}

// Xray core.OutboundHandlerConfig after preparation: tag, sender settings and
// the protocol constructor. Immutable once published.
struct PreparedOutboundConfig {
    std::string tag;
    std::string protocol;
    OutboundSenderSettings sender;
    PreparedOutboundCreator create;
};
}  // namespace proxyman::outbound
