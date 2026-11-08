#include "tcp_listener.hpp"

#include "common/allocator.hpp"
#include "common/container_util.hpp"

namespace worker_detail {

TcpListenerOwner::~TcpListenerOwner() noexcept { Close(); }

void TcpListenerOwner::Close() noexcept {
    while (!acceptors_.empty()) {
        CloseAcceptor(acceptors_.begin()->first);
    }
}

TcpListenerOwner::AcceptorPtr TcpListenerOwner::CreateAcceptor(
    std::string_view listener_key,
    net::io_context& io_context) {
    if (acceptors_.contains(listener_key)) return nullptr;
    auto acceptor = memory::AllocateShared<tcp::acceptor>(io_context);
    acceptors_.try_emplace(memory::ThreadLocalString(listener_key), acceptor);
    return acceptor;
}


bool TcpListenerOwner::OwnsAcceptor(
    std::string_view listener_key,
    const tcp::acceptor* acceptor) const noexcept {
    const auto it = acceptors_.find(listener_key);
    return acceptor && it != acceptors_.end() && it->second.get() == acceptor;
}


void TcpListenerOwner::CloseAcceptor(std::string_view listener_key) noexcept {
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

}  // namespace worker_detail
