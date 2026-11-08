#pragma once

#include "common/asio_types.hpp"
#include "common/allocator.hpp"
#include "common/string_hash.hpp"

#include <memory>
#include <string_view>

namespace worker_detail {

// Worker-private owner for one inbound tag's TCP acceptors.
class TcpListenerOwner final : public memory::ThreadAllocated {
public:
    // Handles remain Worker-local; accept loops retain them only until a
    // close/cancel completion has resumed and observed owner-map retirement.
    using AcceptorPtr = std::shared_ptr<tcp::acceptor>;

    TcpListenerOwner() = default;
    ~TcpListenerOwner() noexcept;

    TcpListenerOwner(const TcpListenerOwner&) = delete;
    TcpListenerOwner& operator=(const TcpListenerOwner&) = delete;

    void Close() noexcept;

    // listener_key is unique for the lifetime of its AcceptLoop. Duplicate
    // creation is rejected instead of replacing the object at a stable address.
    [[nodiscard]] AcceptorPtr CreateAcceptor(std::string_view listener_key,
                                             net::io_context& io_context);
    [[nodiscard]] bool OwnsAcceptor(
        std::string_view listener_key,
        const tcp::acceptor* acceptor) const noexcept;
    void CloseAcceptor(std::string_view listener_key) noexcept;

private:
    memory::ThreadLocalUnorderedMap<memory::ThreadLocalString, AcceptorPtr,
                                   TransparentStringHash, TransparentStringEq> acceptors_;
};

}  // namespace worker_detail
