#pragma once

#include "common/initial_payload.hpp"
#include "common/target_address.hpp"
#include "shadowsocks_crypto.hpp"
#include "shadowsocks_protocol.hpp"
#include "stream_crypto.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"

#include <tl/expected.hpp>
#include <array>
#include <cstring>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>

namespace ss {

class ResponseBodyWriter final : public transport::MultiBufferWriter {
public:
    ResponseBodyWriter(const proxyman::inbound::UserStore::ShadowsocksCredential& user,
                       const SsCipherInfo& cipher_info,
                       const KeyBytes& request_salt,
                       AsyncStream& stream)
        : cipher_type_(cipher_info.type)
        , key_size_(cipher_info.key_size)
        , salt_size_(cipher_info.salt_size)
        , request_salt_(request_salt)
        , is_2022_(Is2022Cipher(cipher_info.type))
        , stream_(&stream) {
        if (user.derived_key.size <= master_key_.size()) {
            std::memcpy(master_key_.data(), user.derived_key.data(), user.derived_key.size);
        } else {
            key_size_ = 0;
        }
    }

    ~ResponseBodyWriter() override {
        ClearHandshakeKeys();
    }

    ResponseBodyWriter(const ResponseBodyWriter&) = delete;
    ResponseBodyWriter& operator=(const ResponseBodyWriter&) = delete;

    ResponseBodyWriter(ResponseBodyWriter&& other) noexcept
        : cipher_type_(other.cipher_type_)
        , key_size_(other.key_size_)
        , salt_size_(other.salt_size_)
        , master_key_(other.master_key_)
        , request_salt_(other.request_salt_)
        , write_cipher_(std::move(other.write_cipher_))
        , pending_prefix_(std::move(other.pending_prefix_))
        , write_nonce_(other.write_nonce_)
        , write_init_(other.write_init_)
        , write_finished_(other.write_finished_)
        , is_2022_(other.is_2022_)
        , skip_first_bytes_(other.skip_first_bytes_)
        , stream_(std::exchange(other.stream_, nullptr)) {
        other.ClearHandshakeKeys();
    }

    ResponseBodyWriter& operator=(ResponseBodyWriter&& other) noexcept {
        if (this != &other) {
            ClearHandshakeKeys();
            cipher_type_ = other.cipher_type_;
            key_size_ = other.key_size_;
            salt_size_ = other.salt_size_;
            master_key_ = other.master_key_;
            request_salt_ = other.request_salt_;
            write_cipher_ = std::move(other.write_cipher_);
            pending_prefix_ = std::move(other.pending_prefix_);
            write_nonce_ = other.write_nonce_;
            write_init_ = other.write_init_;
            write_finished_ = other.write_finished_;
            is_2022_ = other.is_2022_;
            skip_first_bytes_ = other.skip_first_bytes_;
            stream_ = std::exchange(other.stream_, nullptr);
            other.ClearHandshakeKeys();
        }
        return *this;
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;

    bool WriteShutdownClosesLink() const noexcept override {
        return stream_ && stream_->WriteShutdownClosesLink();
    }

private:
    void ClearHandshakeKeys() noexcept {
        ::SecureZeroMemory(master_key_.data(), master_key_.size());
        ::SecureZeroMemory(request_salt_.bytes.data(), request_salt_.bytes.size());
        request_salt_.size = 0;
    }

    void Finish();
    void Retire();

    template <typename BufferRange>
    net::awaitable<void> WriteEncrypted(BufferRange& buffers, bool clear_after_encrypt);

    net::awaitable<void> FlushPendingAndWrite(AsyncStream& stream, buf::MultiBuffer out_mb);

    static bool InitResponseCipher(ResponseBodyWriter& state);
    static bool InitResponseCipher2022(ResponseBodyWriter& state,
                                       std::span<const uint8_t> first_payload);

    SsCipherType cipher_type_;
    size_t key_size_;
    size_t salt_size_;
    std::array<uint8_t, 32> master_key_{};
    KeyBytes request_salt_;
    std::optional<SsAeadCipher> write_cipher_;
    buf::MultiBuffer pending_prefix_;
    uint64_t write_nonce_ = 0;
    bool write_init_ = false;
    bool write_finished_ = false;
    bool is_2022_ = false;
    size_t skip_first_bytes_ = 0;
    AsyncStream* stream_ = nullptr;
};

struct ReadTCPSessionResult {
    std::shared_ptr<const proxyman::inbound::UserStore::ShadowsocksCredential> user;
    TargetAddress target;
    std::optional<ForwardedMetadata> forwarded;
    InitialPayload initial_payload;
    std::optional<detail::BodyReader> body_reader;
    KeyBytes request_salt;
};

// xray-core proxy/shadowsocks/server.go 对应的服务器端握手与 body reader/writer 入口。
[[nodiscard]] net::awaitable<tl::expected<ReadTCPSessionResult, ErrorCode>>
ReadTCPSession(AsyncStream& stream,
               const SsCipherInfo& cipher_info,
               std::string_view tag,
               size_t& last_matched_index);

[[nodiscard]] tl::expected<ResponseBodyWriter, ErrorCode>
WriteTCPResponse(const proxyman::inbound::UserStore::ShadowsocksCredential& user,
                 const SsCipherInfo& cipher_info,
                 const KeyBytes& request_salt,
                 AsyncStream& stream);
}  // namespace ss
