#pragma once

#include "app/relay.hpp"
#include "common/asio_types.hpp"
#include "common/hash.hpp"
#include "infra/config_types.hpp"
#include "proxy/outbound.hpp"
#include "transport/outbound_target_builder.hpp"
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>
#include <unordered_map>
namespace common {

class AwaitableTaskGroup;

}  // namespace common
namespace app {

class DNS;

class OutboundProtocolSettings {
public:
    virtual ~OutboundProtocolSettings() noexcept = default;
};

template <typename T>
struct TypedOutboundProtocolSettings final : OutboundProtocolSettings {
    explicit TypedOutboundProtocolSettings(T v) : value(std::move(v)) {}
    T value;
};

// Constructs the protocol instance for one Worker: its native reactor and
// resident task group (joined before the Worker's teardown). Dialing goes
// through the owning Handler's OutboundDialer, never through creator state.
struct PreparedOutboundCreator {
    using CreateFn = std::unique_ptr<::proxy::Outbound> (*)(
        std::string_view tag,
        const std::shared_ptr<const OutboundProtocolSettings>& settings,
        ::net::io_context& io_context,
        ::common::AwaitableTaskGroup& tasks);

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

    [[nodiscard]] std::unique_ptr<::proxy::Outbound> operator()(
        std::string_view tag,
        ::net::io_context& io_context,
        ::common::AwaitableTaskGroup& tasks) const {
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
            ::common::AwaitableTaskGroup& tasks) -> std::unique_ptr<::proxy::Outbound> {
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
    transport::OutboundSenderSettings sender;
    PreparedOutboundCreator create;
};
// What a protocol contributes to its Handler: the protocol constructor and the
// sender settings with its stream defaults applied. The top-level sendThrough
// of the source config overrides the protocol's default bind.
struct PreparedOutboundProxy {
    PreparedOutboundCreator create;
    transport::OutboundSenderSettings sender;
};

// Cold-path registration API. Proxyman receives an already normalized
// source config and produces an immutable prepared handler constructor.
void RegisterProxy(
    std::string_view protocol,
    std::optional<PreparedOutboundProxy> (*)(
        const infra::OutboundSourceConfig& config));

[[nodiscard]] std::optional<PreparedOutboundConfig> PrepareOutboundConfig(
    const infra::OutboundSourceConfig& config);

// Prepared configs are runtime invariants. Construction failures throw;
// callers must not continue with a partially installed outbound handler.
// `tasks` must outlive the protocol instance and join everything it starts.
[[nodiscard]] std::unique_ptr<::proxy::Outbound> NewProxy(
    const PreparedOutboundConfig& config,
    ::net::io_context& io_context,
    ::common::AwaitableTaskGroup& tasks);

// ============================================================================
// Handler - Xray app/proxyman/outbound.Handler
//
// One concrete handler per outbound tag per Worker. It owns the prepared
// configuration (sender settings), the tag's OutboundDialer and the protocol
// instance.
// ============================================================================
class OutboundHandler final {
public:
    // The protocol instance and dialer live in the owning Worker (reactor, DNS
    // client and resident task group outlive the handler).
    OutboundHandler(PreparedOutboundConfig config, net::io_context& io_context,
                    app::DNS& dns, std::chrono::seconds dial_timeout,
                    common::AwaitableTaskGroup& tasks);
    ~OutboundHandler();
    OutboundHandler(const OutboundHandler&) = delete;
    OutboundHandler& operator=(const OutboundHandler&) = delete;

    [[nodiscard]] std::string_view Tag() const noexcept { return config_.tag; }

    // The caller keeps this handler alive until the returned awaitable completes.
    [[nodiscard]] net::awaitable<proxy::OutboundProcessResult> Dispatch(
        common::Context& ctx,
        transport::Link inbound,
        const infra::TimeoutsConfig& timeouts,
        app::StatsShard& stats,
        const app::RelayConfig& relay_config,
        common::MultiBufferBatch&& first_payload);

private:
    // Destroyed in reverse order: the protocol instance before the dialer,
    // the dialer before the sender settings it borrows from config_.
    const PreparedOutboundConfig config_;
    transport::OutboundDialer dialer_;
    std::unique_ptr<::proxy::Outbound> proxy_;
};

using OutboundHandlerPtr = std::shared_ptr<OutboundHandler>;

// ============================================================================
// HandlerRegistry - Xray app/proxyman/outbound.Manager，每个 Worker 一份
//
// 分发层唯一的出站查找入口，按 tag 持有已实例化的 Handler。发布只走冷路径：
// 构造、Replace、Remove 在所属 Worker 上预先构造或撤销 Handler；请求路径只做
// 一次哈希查找，不构造、不比较代次。返回的句柄让在途请求在 tag 被替换或删除
// 后继续持有原 Handler 直至请求结束。所有成员只在所属 Worker 线程调用。
// ============================================================================
class OutboundHandlerRegistry final {
public:
    // 任一配置非法、tag 重复或协议构造失败都直接抛出，不留下部分发布。
    OutboundHandlerRegistry(const std::vector<PreparedOutboundConfig>& configurations,
                            net::io_context& io_context, app::DNS& dns,
                            std::chrono::seconds dial_timeout, common::AwaitableTaskGroup& tasks);
    ~OutboundHandlerRegistry();
    OutboundHandlerRegistry(const OutboundHandlerRegistry&) = delete;
    OutboundHandlerRegistry& operator=(const OutboundHandlerRegistry&) = delete;

    [[nodiscard]] std::shared_ptr<OutboundHandler> GetHandler(std::string_view tag) const noexcept;

    // 事务性：新 Handler 构造并入表成功后才替换同 tag 项，失败保留原发布。
    void Replace(const PreparedOutboundConfig& configuration);
    void Remove(std::string_view tag);

private:
    [[nodiscard]] std::shared_ptr<OutboundHandler> Instantiate(
        const PreparedOutboundConfig& configuration) const;

    net::io_context& io_context_;
    app::DNS& dns_;
    const std::chrono::seconds dial_timeout_;
    common::AwaitableTaskGroup& tasks_;
    std::unordered_map<std::string, std::shared_ptr<OutboundHandler>,
                       common::TransparentStringHash, common::TransparentStringEq>
        handlers_;
};

}  // namespace app
