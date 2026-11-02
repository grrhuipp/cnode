#include "tcp_listener.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"

namespace acpp::worker_detail {

struct TcpListenerOwner::Impl {
    explicit Impl(std::string tag)
        : tag(std::move(tag)) {}

    std::string tag;
    memory::ThreadLocalUnorderedMap<std::string, TcpListenerOwner::AcceptorPtr> acceptors;
};

TcpListenerOwner::TcpListenerOwner(std::string tag)
    : impl_(std::make_unique<Impl>(std::move(tag))) {}

TcpListenerOwner::~TcpListenerOwner() noexcept = default;
TcpListenerOwner::TcpListenerOwner(TcpListenerOwner&&) noexcept = default;
TcpListenerOwner& TcpListenerOwner::operator=(TcpListenerOwner&&) noexcept = default;

std::string_view TcpListenerOwner::Tag() const noexcept {
    return impl_->tag;
}

void TcpListenerOwner::Close() noexcept {
    while (!impl_->acceptors.empty()) {
        CloseAcceptor(impl_->acceptors.begin()->first);
    }
}

TcpListenerOwner::AcceptorPtr TcpListenerOwner::CreateAcceptor(
    std::string listener_key,
    net::io_context& io_context) {
    auto acceptor = std::make_shared<tcp::acceptor>(io_context);
    auto [it, inserted] = impl_->acceptors.try_emplace(
        std::move(listener_key), acceptor);
    return inserted ? std::move(acceptor) : nullptr;
}

TcpListenerOwner::AcceptorPtr TcpListenerOwner::FindAcceptor(
    const std::string& listener_key) noexcept {
    auto it = impl_->acceptors.find(listener_key);
    return it == impl_->acceptors.end() ? nullptr : it->second;
}

std::shared_ptr<const tcp::acceptor> TcpListenerOwner::FindAcceptor(
    const std::string& listener_key) const noexcept {
    auto it = impl_->acceptors.find(listener_key);
    return it == impl_->acceptors.end() ? nullptr : it->second;
}

bool TcpListenerOwner::OwnsAcceptor(
    const std::string& listener_key,
    const tcp::acceptor* acceptor) const noexcept {
    auto it = impl_->acceptors.find(listener_key);
    return acceptor && it != impl_->acceptors.end() &&
        it->second.get() == acceptor;
}

std::vector<std::string> TcpListenerOwner::ListenerKeys() const {
    std::vector<std::string> keys;
    keys.reserve(impl_->acceptors.size());
    for (const auto& [listener_key, acceptor] : impl_->acceptors) {
        (void)acceptor;
        keys.push_back(listener_key);
    }
    return keys;
}

void TcpListenerOwner::CloseAcceptor(const std::string& listener_key) noexcept {
    auto it = impl_->acceptors.find(listener_key);
    if (it == impl_->acceptors.end()) {
        return;
    }

    auto acceptor = std::move(it->second);
    impl_->acceptors.erase(it);
    MaybeShrinkHashContainer(impl_->acceptors, 8);

    IoErrorCode ec;
    acceptor->close(ec);
}

}  // namespace acpp::worker_detail
