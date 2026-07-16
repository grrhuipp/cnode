#include "ss_udp.hpp"
#include "acppnode/common/buf/contiguous_buffer_view.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>

namespace {

using namespace acpp;

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

std::vector<uint8_t> Flatten(const buf::MultiBuffer& payload) {
    std::vector<uint8_t> out;
    out.reserve(buf::TotalLen(payload));
    for (const buf::Buffer* buffer : payload) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }
        const auto bytes = buffer->Bytes();
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}

buf::MultiBuffer MakePayload(const std::vector<uint8_t>& source,
                             const TargetAddress& target) {
    buf::MultiBuffer payload;
    Check(buf::AppendSpanToMultiBuffer(source, payload),
          "failed to allocate Shadowsocks UDP test payload");
    for (buf::Buffer* buffer : payload) {
        if (buffer && !buffer->IsEmpty()) {
            buffer->SetUDP(target);
        }
    }
    return payload;
}

void CheckClassic(const TargetAddress& target,
                  const std::vector<uint8_t>& source,
                  std::span<const uint8_t> payload) {
    const ss::SsCipherInfo cipher{
        ss::SsCipherType::AES_128_GCM, 16, 16};
    const ss::KeyBytes key = ss::DeriveKey("udp-datagram-test", cipher.key_size);
    const size_t encoded_size = ss::EncodeUdpPacketTo(
        target, payload.data(), payload.size(), key.span(),
        cipher.type, cipher.key_size, cipher.salt_size, nullptr, 0);
    Check(encoded_size > source.size(),
          "classic Shadowsocks UDP size calculation failed");
    std::vector<uint8_t> encoded(encoded_size);
    Check(ss::EncodeUdpPacketTo(
              target, payload.data(), payload.size(), key.span(),
              cipher.type, cipher.key_size, cipher.salt_size,
              encoded.data(), encoded.size()) == encoded.size(),
          "classic Shadowsocks UDP encoding failed");

    auto decoded = ss::DecodeUdpPacketWithKey(
        encoded.data(), encoded.size(), key.span(),
        cipher.type, cipher.key_size, cipher.salt_size);
    Check(decoded && decoded->target.SameEndpoint(target) &&
          Flatten(decoded->payload) == source,
          "classic Shadowsocks split one MultiBuffer datagram");
}

void Check2022(const TargetAddress& target,
               const std::vector<uint8_t>& source,
               std::span<const uint8_t> payload) {
    const ss::SsCipherInfo cipher{
        ss::SsCipherType::AES_128_GCM_2022, 16, 16};
    ss::KeyBytes key;
    std::array<uint8_t, 16> key_bytes{};
    for (size_t i = 0; i < key_bytes.size(); ++i) {
        key_bytes[i] = static_cast<uint8_t>(i + 1);
    }
    Check(key.assign(key_bytes), "failed to initialize Shadowsocks 2022 key");

    ss::Ss2022UdpSessionState encoder;
    Check(ss::Init2022UdpSessionState(encoder, cipher, key),
          "failed to initialize Shadowsocks 2022 UDP state");
    const size_t encoded_size = ss::Encode2022UdpRequestPacketTo(
        target, payload.data(), payload.size(), encoder, {}, nullptr, 0);
    Check(encoded_size > source.size(),
          "Shadowsocks 2022 UDP size calculation failed");
    Check(encoder.next_packet_id == 0,
          "Shadowsocks 2022 size calculation advanced packet state");
    std::vector<uint8_t> encoded(encoded_size);
    Check(ss::Encode2022UdpRequestPacketTo(
              target, payload.data(), payload.size(), encoder, {},
              encoded.data(), encoded.size()) == encoded.size(),
          "Shadowsocks 2022 UDP encoding failed");
    Check(encoder.next_packet_id == 1,
          "Shadowsocks 2022 request did not advance packet state once");

    auto user_list = std::make_shared<
        proxyman::inbound::UserStore::ShadowsocksUserList>();
    proxyman::inbound::UserStore::ShadowsocksCredential user;
    Check(user.derived_key.assign(key.span()),
          "failed to initialize Shadowsocks 2022 decode user");
    user.cipher_type =
        proxyman::inbound::PreparedAeadCipher::AES_128_GCM_2022;
    user.key_size = cipher.key_size;
    user.salt_size = cipher.salt_size;
    user_list->push_back(std::move(user));
    const proxyman::inbound::UserStore::ShadowsocksUsersView users{user_list};
    auto decoded = ss::DecodeUdpPacket(
        encoded.data(), encoded.size(), users,
        cipher.type, cipher.key_size, cipher.salt_size);
    Check(decoded && decoded->target.SameEndpoint(target) &&
          Flatten(decoded->payload) == source,
          "Shadowsocks 2022 split one MultiBuffer datagram");
}

}  // namespace

int main() {
    const TargetAddress target("1.1.1.1", 53);
    const std::vector<uint8_t> source(buf::Buffer::kSize + 257, 0x6d);
    const buf::MultiBuffer fragmented = MakePayload(source, target);
    const buf::ContiguousBufferView payload(fragmented);
    Check(payload.Bytes().size() == source.size() &&
          std::equal(payload.Bytes().begin(), payload.Bytes().end(), source.begin()),
          "Shadowsocks UDP payload coalescing mismatch");

    CheckClassic(target, source, payload.Bytes());
    Check2022(target, source, payload.Bytes());
    return 0;
}
