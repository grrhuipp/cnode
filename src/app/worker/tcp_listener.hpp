#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/container_util.hpp"
#include "common/string_hash.hpp"

#include <memory>
#include <string_view>
#include <utility>

namespace worker_detail {

// Worker-private owner for one inbound tag's TCP acceptors.
class TcpListenerOwner final : public memory::ThreadAllocated {
public:
    // Handles remain Worker-local; accept loops retain them only until a
    // close/cancel completion has resumed and observed owner-map retirement.
    using AcceptorPtr = std::shared_ptr<tcp::acceptor>;

    TcpListenerOwner() = default;
    ~TcpListenerOwner() noexcept { Close(); }

    TcpListenerOwner(const TcpListenerOwner&) = delete;
    TcpListenerOwner& operator=(const TcpListenerOwner&) = delete;

    void Close() noexcept {
        while (!acceptors_.empty()) {
            CloseAcceptor(acceptors_.begin()->first);
        }
    }

    // listener_key is unique for the lifetime of its AcceptLoop. Duplicate
    // creation is rejected instead of replacing the object at a stable address.
    [[nodiscard]] AcceptorPtr CreateAcceptor(std::string_view listener_key,
                                             net::io_context& io_context) {
        if (acceptors_.contains(listener_key)) return nullptr;
        auto acceptor = memory::AllocateShared<tcp::acceptor>(io_context);
        acceptors_.try_emplace(memory::ThreadLocalString(listener_key), acceptor);
        return acceptor;
    }

    [[nodiscard]] bool OwnsAcceptor(
        std::string_view listener_key,
        const tcp::acceptor* acceptor) const noexcept {
        const auto it = acceptors_.find(listener_key);
        return acceptor && it != acceptors_.end() && it->second.get() == acceptor;
    }

    void CloseAcceptor(std::string_view listener_key) noexcept {
        auto it = acceptors_.find(listener_key);
        if (it == acceptors_.end()) {
            return;
        }

        auto acceptor = std::move(it->second);
        acceptors_.erase(it);
        MaybeShrinkHashContainer(acceptors_, 8);

        IoErrorCode ec;
        acceptor->close(ec);
    }

private:
    memory::ThreadLocalUnorderedMap<memory::ThreadLocalString, AcceptorPtr,
                                   TransparentStringHash, TransparentStringEq> acceptors_;
};

}  // namespace worker_detail
