#pragma once

#include "app/proxyman/inbound/user_store.hpp"
#include "client.hpp"
#include "server.hpp"
#include "shadowsocks_crypto.hpp"
#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace ss_identity_test {
using namespace proxyman::inbound;
inline constexpr std::string_view kTag = "ss-identity-fixture";

inline void Require(bool condition) {
    if (!condition) throw std::runtime_error("SS identity fixture contract failed");
}

// Only the transport is in memory: both ends use the production SS2022 codec.
class Wire final : public AsyncStream {
public:
    std::vector<uint8_t> bytes;
    size_t offset = 0;
    net::awaitable<size_t> AsyncRead(net::mutable_buffer out) override {
        const size_t count = std::min(out.size(), bytes.size() - offset);
        if (count) std::memcpy(out.data(), bytes.data() + offset, count);
        offset += count;
        co_return count;
    }
    net::awaitable<size_t> AsyncWrite(net::const_buffer in) override {
        const auto* first = static_cast<const uint8_t*>(in.data());
        bytes.insert(bytes.end(), first, first + in.size());
        co_return in.size();
    }
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        co_return buf::MultiBuffer{};
    }
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer input) override {
        for (const auto* buffer : input) {
            const auto data = buffer->Bytes();
            bytes.insert(bytes.end(), data.begin(), data.end());
        }
        co_return;
    }
    void ShutdownWrite() override {}
    void Cancel() noexcept override { NotifyCancellation(); }
    void Close() override { NotifyClosed(); }
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return true; }
};

inline PreparedShadowsocksUsers Users(size_t count, const ss::SsCipherInfo& cipher,
                                      size_t groups = 1) {
    PreparedShadowsocksUsers users;
    users.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        PreparedShadowsocksUser user;
        user.key_size = cipher.key_size;
        user.salt_size = cipher.salt_size;
        user.derived_key.size = cipher.key_size;
        user.derived_key.bytes.fill(0x31);
        for (size_t byte = 0; byte < sizeof(i); ++byte)
            user.derived_key.bytes[byte] = static_cast<uint8_t>((i + 1) >> (byte * 8));
        if (groups) {
            user.identity_key.size = cipher.key_size;
            user.identity_key.bytes.fill(0xa7);
            const size_t group = i % groups;
            for (size_t byte = 0; byte < sizeof(group); ++byte)
                user.identity_key.bytes[byte] = static_cast<uint8_t>(group >> (byte * 8));
        }
        Require(ss::Hash2022Psk(user.derived_key.span(), user.psk_hash));
        user.profile.user_id = static_cast<int>(i + 1);
        users.push_back(std::move(user));
    }
    return users;
}

inline void Install(const PreparedShadowsocksUsers& users) {
    UserStore::InstallWorkerView(UserStore::PrepareWorkerView(
        UserStore::PrepareUsers(kTag, UserSet{users})));
}

inline net::awaitable<void> PrepareWire(Wire& wire, const PreparedShadowsocksUser& user,
                                        const ss::SsCipherInfo& cipher) {
    ss::KeyBytes key;
    Require(key.assign(user.derived_key.span()));
    std::vector<ss::KeyBytes> chain;
    if (!user.identity_key.empty()) {
        ss::KeyBytes identity;
        Require(identity.assign(user.identity_key.span()));
        chain.push_back(identity);
        chain.push_back(key);
    }
    auto request = co_await ss::WriteTCPRequest(
        TargetAddress("127.0.0.1", 443), cipher, key, chain, wire);
    Require(bool(request));
    buf::MultiBuffer payload;
    const std::array<uint8_t, 3> data{0x17, 0x29, 0x41};
    Require(buf::AppendSpanToMultiBuffer(data, payload));
    co_await request->request_writer->WriteMultiBuffer(std::move(payload));
}

inline void Prepare(net::io_context& io, Wire& wire, const PreparedShadowsocksUser& user,
                    const ss::SsCipherInfo& cipher) {
    io.restart();
    auto done = net::co_spawn(io, PrepareWire(wire, user, cipher), net::use_future);
    io.run();
    done.get();
}

inline auto Authenticate(net::io_context& io, Wire& wire, const ss::SsCipherInfo& cipher,
                         size_t& hint) {
    wire.offset = 0;
    io.restart();
    auto done = net::co_spawn(io, ss::ReadTCPSession(wire, cipher, kTag, hint), net::use_future);
    io.run();
    return done.get();
}
} // namespace ss_identity_test
