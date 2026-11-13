#pragma once

#include "proxy/shadowsocks/shadowsocks_protocol.hpp"
#include "common/initial_payload.hpp"
#include "common/target_address.hpp"

namespace proxy {
class SsStreamWriter final : public transport::MultiBufferWriter {
public:
    SsStreamWriter(const app::UserStore::ShadowsocksCredential& user,
                       const SsCipherInfo& cipher_info,
                       const KeyBytes& request_salt,
                       transport::AsyncStream& stream)
        : cipher_type_(cipher_info.type)
        , key_size_(cipher_info.key_size == cipher_info.salt_size &&
                    cipher_info.key_size <= KeyBytes::kMaxSize &&
                    user.derived_key.size <= KeyBytes::kMaxSize
                        ? static_cast<uint8_t>(cipher_info.key_size)
                        : uint8_t{0})
        , pending_handshake_(std::in_place)
        , stream_(&stream) {
        pending_handshake_->request_salt = request_salt;
        if (key_size_ != 0) {
            std::memcpy(pending_handshake_->master_key.data(),
                        user.derived_key.data(),
                        user.derived_key.size);
        }
    }

    ~SsStreamWriter() override {
        ClearHandshakeKeys();
    }

    SsStreamWriter(SsAeadCipher cipher, uint64_t nonce, transport::AsyncStream& stream)
        : cipher_type_(SsCipherType::AES_128_GCM), write_cipher_(std::move(cipher)),
          write_nonce_(nonce), write_init_(true), stream_(&stream) {}

    SsStreamWriter(const SsStreamWriter&) = delete;
    SsStreamWriter& operator=(const SsStreamWriter&) = delete;

    SsStreamWriter(SsStreamWriter&& other) noexcept
        : cipher_type_(other.cipher_type_)
        , key_size_(other.key_size_)
        , pending_handshake_(std::move(other.pending_handshake_))
        , write_cipher_(std::move(other.write_cipher_))
        , pending_prefix_(std::move(other.pending_prefix_))
        , write_nonce_(other.write_nonce_)
        , write_init_(other.write_init_)
        , write_finished_(other.write_finished_)
        , skip_first_bytes_(other.skip_first_bytes_)
        , stream_(std::exchange(other.stream_, nullptr)) {
        other.ClearHandshakeKeys();
    }

    SsStreamWriter& operator=(SsStreamWriter&& other) noexcept {
        if (this != &other) {
            ClearHandshakeKeys();
            cipher_type_ = other.cipher_type_;
            key_size_ = other.key_size_;
            pending_handshake_ = std::move(other.pending_handshake_);
            write_cipher_ = std::move(other.write_cipher_);
            pending_prefix_ = std::move(other.pending_prefix_);
            write_nonce_ = other.write_nonce_;
            write_init_ = other.write_init_;
            write_finished_ = other.write_finished_;
            skip_first_bytes_ = other.skip_first_bytes_;
            stream_ = std::exchange(other.stream_, nullptr);
            other.ClearHandshakeKeys();
        }
        return *this;
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;

    bool WriteShutdownClosesLink() const noexcept override {
        return stream_ && stream_->WriteShutdownClosesLink();
    }

private:
    struct PendingHandshake {
        std::array<uint8_t, 32> master_key{};
        KeyBytes request_salt;

        PendingHandshake() = default;
        PendingHandshake(const PendingHandshake&) = default;
        PendingHandshake& operator=(const PendingHandshake&) = default;
        PendingHandshake(PendingHandshake&&) noexcept = default;
        PendingHandshake& operator=(PendingHandshake&&) noexcept = default;
        ~PendingHandshake() noexcept {
            OPENSSL_cleanse(master_key.data(), master_key.size());
        }
    };

    void ClearHandshakeKeys() noexcept {
        if (pending_handshake_) {
            OPENSSL_cleanse(pending_handshake_->master_key.data(),
                               pending_handshake_->master_key.size());
            OPENSSL_cleanse(pending_handshake_->request_salt.bytes.data(),
                               pending_handshake_->request_salt.bytes.size());
            pending_handshake_.reset();
        }
    }

    void Finish();
    void Retire();

    // By value: the range must stay in this frame until the write completes.
    template <typename BufferRange>
    net::awaitable<void> WriteEncrypted(BufferRange buffers);

    net::awaitable<void> FlushPendingAndWrite(transport::AsyncStream& stream, common::MultiBuffer out_mb);

    bool InitResponseCipher();

    template <typename BufferRange>
    bool InitResponseCipher2022(const BufferRange& buffers);

    template <typename BufferRange>
    bool AppendFirstResponsePayload(const BufferRange& buffers, size_t want);

    SsCipherType cipher_type_;
    uint8_t key_size_ = 0;
    std::optional<PendingHandshake> pending_handshake_;
    std::optional<SsAeadCipher> write_cipher_;
    common::MultiBuffer pending_prefix_;
    uint64_t write_nonce_ = 0;
    bool write_init_ = false;
    bool write_finished_ = false;
    size_t skip_first_bytes_ = 0;
    transport::AsyncStream* stream_ = nullptr;
};

struct ReadTCPSessionResult {
    std::shared_ptr<const app::UserStore::ShadowsocksCredential> user;
    common::TargetAddress target;
    std::optional<common::ForwardedMetadata> forwarded;
    common::InitialPayload initial_payload;
    std::optional<BodyReader> body_reader;
    KeyBytes request_salt;
};

// xray-core proxy/shadowsocks/server.go 对应的服务器端握手与 body reader/writer 入口。
[[nodiscard]] net::awaitable<tl::expected<ReadTCPSessionResult, common::ErrorCode>>
ReadTCPSession(transport::AsyncStream& stream,
               const SsCipherInfo& cipher_info,
               std::string_view tag,
               size_t& last_matched_index);

[[nodiscard]] tl::expected<SsStreamWriter, common::ErrorCode>
WriteTCPResponse(const app::UserStore::ShadowsocksCredential& user,
                 const SsCipherInfo& cipher_info,
                 const KeyBytes& request_salt,
                 transport::AsyncStream& stream);
struct WriteTCPRequestResult {
    SsStreamWriter request_writer;
    KeyBytes request_salt;
};

// xray-core proxy/shadowsocks/client.go 对应的客户端握手与 reader/writer 入口。
[[nodiscard]] net::awaitable<tl::expected<WriteTCPRequestResult, common::ErrorCode>>
WriteTCPRequest(const common::TargetAddress& target,
                const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                std::span<const KeyBytes> psk_chain,
                transport::AsyncStream& stream,
                common::ForwardedMetadataView forwarded = {});

// 2022 固定响应头可携带首段载荷；它在 reader 之前交付，reader 只负责后续记录。
struct ReadTCPResponseResult {
    BodyReader reader;
    common::MultiBuffer initial_payload;
};

[[nodiscard]] net::awaitable<tl::expected<ReadTCPResponseResult, common::ErrorCode>>
ReadTCPResponse(const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                const KeyBytes& request_salt,
                transport::AsyncStream& stream);
}  // namespace proxy
