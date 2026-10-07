#pragma once

#include "acppnode/common/asio_types.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp::worker_detail {

// Worker-private owner for one inbound tag's TCP acceptors.
class TcpListenerOwner final {
public:
    // Handles remain Worker-local; accept loops retain them only until a
    // close/cancel completion has resumed and observed owner-map retirement.
    using AcceptorPtr = std::shared_ptr<tcp::acceptor>;

    explicit TcpListenerOwner(std::string tag);
    ~TcpListenerOwner() noexcept;

    TcpListenerOwner(const TcpListenerOwner&) = delete;
    TcpListenerOwner& operator=(const TcpListenerOwner&) = delete;
    TcpListenerOwner(TcpListenerOwner&&) noexcept;
    TcpListenerOwner& operator=(TcpListenerOwner&&) noexcept;

    [[nodiscard]] std::string_view Tag() const noexcept;

    void Close() noexcept;

    // listener_key is unique for the lifetime of its AcceptLoop. Duplicate
    // creation is rejected instead of replacing the object at a stable address.
    [[nodiscard]] AcceptorPtr CreateAcceptor(std::string listener_key,
                                             net::io_context& io_context);
    [[nodiscard]] AcceptorPtr FindAcceptor(
        const std::string& listener_key) noexcept;
    [[nodiscard]] std::shared_ptr<const tcp::acceptor> FindAcceptor(
        const std::string& listener_key) const noexcept;
    [[nodiscard]] bool OwnsAcceptor(
        const std::string& listener_key,
        const tcp::acceptor* acceptor) const noexcept;
    [[nodiscard]] std::vector<std::string> ListenerKeys() const;
    void CloseAcceptor(const std::string& listener_key) noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::worker_detail
