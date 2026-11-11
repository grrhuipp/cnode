#pragma once

#include "app/worker/udp_ingress.hpp"

#include <map>
#include <string>
#include <string_view>

// 名称仅用于组织测试场景；生产入口只接收地址稳定的 socket 状态。
class UdpSocketFixtures final {
public:
    using Ingress = app::worker_detail::UdpIngress;
    explicit UdpSocketFixtures(net::io_context& io) : io_(io) {}

    Ingress::SocketStatePtr Get(Ingress& ingress, std::string_view name) {
        auto& state = states_[{&ingress, std::string(name)}];
        if (!state || !ingress.OwnsSocket(*state))
            state = ingress.AttachSocket(Ingress::MakeSocket(io_));
        return state;
    }
    Ingress::SocketPtr Attach(Ingress& ingress, std::string_view name,
                              Ingress::SocketPtr socket) {
        auto& state = states_[{&ingress, std::string(name)}];
        if (state && ingress.OwnsSocket(*state)) return nullptr;
        state = ingress.AttachSocket(std::move(socket));
        return state ? state->socket : nullptr;
    }
    Ingress::SocketStatePtr Find(Ingress& ingress, const udp::socket* socket) const {
        for (const auto& [key, state] : states_) {
            if (key.first == &ingress && state && state->socket.get() == socket) return state;
        }
        return nullptr;
    }
    Ingress::SocketPtr Find(Ingress& ingress, std::string_view name) const {
        const auto found = states_.find({&ingress, std::string(name)});
        return found == states_.end() || !found->second || !ingress.OwnsSocket(*found->second)
            ? nullptr : found->second->socket;
    }
    bool Owns(Ingress& ingress, std::string_view name, const udp::socket* socket) const {
        const auto found = Find(ingress, name);
        return found && found.get() == socket;
    }
private:
    net::io_context& io_;
    std::map<std::pair<Ingress*, std::string>, Ingress::SocketStatePtr> states_;
};
