#pragma once

#include "common/asio_types.hpp"
#include <memory>
#include <string_view>

namespace transport {
// Cold-path lifecycle boundary. Requests remain owned by the concrete listener.
class QuicListener {
public:
    using SocketPtr = std::shared_ptr<udp::socket>;
    virtual ~QuicListener() noexcept = default;
    [[nodiscard]] virtual SocketPtr MakeSocket() = 0;
    [[nodiscard]] virtual SocketPtr AttachSocket(std::string_view key, SocketPtr socket) = 0;
    virtual void Start() = 0;
    virtual void RequestStop() noexcept = 0;
    virtual net::awaitable<void> AsyncJoin() = 0;
};
} // namespace transport
