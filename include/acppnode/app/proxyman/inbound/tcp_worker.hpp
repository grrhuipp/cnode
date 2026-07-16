#pragma once

#include "acppnode/common/asio_types.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp::proxyman::inbound {

// ============================================================================
// TcpWorker - per-Worker TCP inbound listener worker
//
// 对齐 xray-core app/proxyman/inbound tcpWorker 的资源职责：保存该 tag 下
// 已启动的 listener hub/acceptor，并提供 Start/Close/Port/Tag 风格入口。
// cnode 仍由 Worker 负责 SO_REUSEPORT bind 和 AcceptLoop 调度，避免在
// accept 热路径引入额外动态分派。
// ============================================================================
class TcpWorker final {
public:
    explicit TcpWorker(std::string tag);
    ~TcpWorker() noexcept;

    TcpWorker(const TcpWorker&) = delete;
    TcpWorker& operator=(const TcpWorker&) = delete;
    TcpWorker(TcpWorker&&) noexcept;
    TcpWorker& operator=(TcpWorker&&) noexcept;

    [[nodiscard]] std::string_view Tag() const noexcept;

    void Close() noexcept;

    // listener_key is unique for the lifetime of its AcceptLoop. Duplicate
    // creation is rejected instead of replacing the object at a stable address.
    [[nodiscard]] tcp::acceptor* CreateAcceptor(std::string listener_key,
                                                net::io_context& io_context);
    [[nodiscard]] tcp::acceptor* FindAcceptor(const std::string& listener_key) noexcept;
    [[nodiscard]] const tcp::acceptor* FindAcceptor(const std::string& listener_key) const noexcept;
    [[nodiscard]] std::vector<std::string> ListenerKeys() const;
    void CloseAcceptor(const std::string& listener_key) noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::proxyman::inbound
