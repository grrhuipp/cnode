#include "acppnode/app/proxyman/inbound/tcp_worker.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"

namespace acpp::proxyman::inbound {

struct TcpWorker::Impl {
    explicit Impl(std::string tag)
        : tag(std::move(tag)) {}

    std::string tag;
    memory::ThreadLocalUnorderedMap<std::string, tcp::acceptor> acceptors;
};

TcpWorker::TcpWorker(std::string tag)
    : impl_(std::make_unique<Impl>(std::move(tag))) {}

TcpWorker::~TcpWorker() noexcept = default;
TcpWorker::TcpWorker(TcpWorker&&) noexcept = default;
TcpWorker& TcpWorker::operator=(TcpWorker&&) noexcept = default;

std::string_view TcpWorker::Tag() const noexcept {
    return impl_->tag;
}

void TcpWorker::Close() noexcept {
    while (!impl_->acceptors.empty()) {
        CloseAcceptor(impl_->acceptors.begin()->first);
    }
}

tcp::acceptor* TcpWorker::CreateAcceptor(std::string listener_key,
                                         net::io_context& io_context) {
    auto [it, inserted] = impl_->acceptors.try_emplace(
        std::move(listener_key), io_context);
    return inserted ? &it->second : nullptr;
}

tcp::acceptor* TcpWorker::FindAcceptor(const std::string& listener_key) noexcept {
    auto it = impl_->acceptors.find(listener_key);
    return it == impl_->acceptors.end() ? nullptr : &it->second;
}

const tcp::acceptor* TcpWorker::FindAcceptor(const std::string& listener_key) const noexcept {
    auto it = impl_->acceptors.find(listener_key);
    return it == impl_->acceptors.end() ? nullptr : &it->second;
}

std::vector<std::string> TcpWorker::ListenerKeys() const {
    std::vector<std::string> keys;
    keys.reserve(impl_->acceptors.size());
    for (const auto& [listener_key, acceptor] : impl_->acceptors) {
        (void)acceptor;
        keys.push_back(listener_key);
    }
    return keys;
}

void TcpWorker::CloseAcceptor(const std::string& listener_key) noexcept {
    auto it = impl_->acceptors.find(listener_key);
    if (it == impl_->acceptors.end()) {
        return;
    }

    IoErrorCode ec;
    it->second.close(ec);
    impl_->acceptors.erase(it);
    MaybeShrinkHashContainer(impl_->acceptors, 8);
}

}  // namespace acpp::proxyman::inbound
