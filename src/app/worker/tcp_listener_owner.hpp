#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/hash_container_shrink.hpp"
#include "common/string_hash.hpp"

#include <memory>
#include <string_view>
#include <utility>
#include <string>
#include <unordered_map>

namespace app::worker_detail {

// Worker 私有：一个入站 tag 的全部 TCP acceptor 的唯一 owner。
class TcpListenerOwner final {
public:
    // 句柄只在本 Worker 内流转；accept 循环仅在 close/cancel 完成恢复并观察到
    // owner 表已摘除之前保留它。
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

    // listener_key 在其 AcceptLoop 生命周期内唯一；重复创建直接拒绝，
    // 不替换已在稳定地址上运行的对象。
    [[nodiscard]] AcceptorPtr CreateAcceptor(std::string_view listener_key,
                                             net::io_context& io_context) {
        if (acceptors_.contains(listener_key)) return nullptr;
        auto acceptor = std::make_shared<tcp::acceptor>(io_context);
        acceptors_.try_emplace(std::pmr::string(listener_key, memory::process_resource()), acceptor);
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
        common::MaybeShrinkHashContainer(acceptors_, 8);

        IoErrorCode ec;
        acceptor->close(ec);
    }

private:
    std::pmr::unordered_map<std::pmr::string, AcceptorPtr,
                            common::TransparentStringHash, common::TransparentStringEq>
        acceptors_{memory::process_resource()};
};

}  // namespace app::worker_detail
