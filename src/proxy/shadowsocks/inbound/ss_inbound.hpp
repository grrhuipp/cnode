#pragma once

#include "proxy/inbound.hpp"
#include "common/allocator.hpp"
#include "common/initial_payload.hpp"
#include "../ss_udp.hpp"
#include "common/sharded_user_stats.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"

#include <array>
#include <cstring>
#include <memory>
#include <optional>
#include <string_view>
#include <tl/expected.hpp>
#include <utility>

struct StatsShard;

namespace ss {

class ResponseBodyWriter final : public transport::MultiBufferWriter {
public:
    ResponseBodyWriter(const proxyman::inbound::UserStore::ShadowsocksCredential& user,
                       const SsCipherInfo& cipher_info,
                       const KeyBytes& request_salt,
                       AsyncStream& stream)
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

    ~ResponseBodyWriter() override {
        ClearHandshakeKeys();
    }

    ResponseBodyWriter(const ResponseBodyWriter&) = delete;
    ResponseBodyWriter& operator=(const ResponseBodyWriter&) = delete;

    ResponseBodyWriter(ResponseBodyWriter&& other) noexcept
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

    ResponseBodyWriter& operator=(ResponseBodyWriter&& other) noexcept {
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

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
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
            ::SecureZeroMemory(master_key.data(), master_key.size());
        }
    };

    void ClearHandshakeKeys() noexcept {
        if (pending_handshake_) {
            ::SecureZeroMemory(pending_handshake_->master_key.data(),
                               pending_handshake_->master_key.size());
            ::SecureZeroMemory(pending_handshake_->request_salt.bytes.data(),
                               pending_handshake_->request_salt.bytes.size());
            pending_handshake_.reset();
        }
    }

    void Finish();
    void Retire();

    template <typename BufferRange>
    net::awaitable<void> WriteEncrypted(BufferRange& buffers, bool clear_after_encrypt);

    net::awaitable<void> FlushPendingAndWrite(AsyncStream& stream, buf::MultiBuffer out_mb);

    static bool InitResponseCipher(ResponseBodyWriter& state);

    template <typename BufferRange>
    static bool InitResponseCipher2022(ResponseBodyWriter& state,
                                       const BufferRange& buffers,
                                       size_t& first_payload_len);

    SsCipherType cipher_type_;
    uint8_t key_size_ = 0;
    std::optional<PendingHandshake> pending_handshake_;
    std::optional<SsAeadCipher> write_cipher_;
    buf::MultiBuffer pending_prefix_;
    uint64_t write_nonce_ = 0;
    bool write_init_ = false;
    bool write_finished_ = false;
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

namespace proxy::shadowsocks::inbound {

class Handler final : public ::Inbound {
public:
    Handler(::UserOnlineTracker& validator,
            ::StatsShard& stats,
            ::ConnectionLimiter* limiter,
            ::ss::SsCipherInfo cipher_info);

    // 解析首包：读 salt + 首 chunk，尝试所有用户密钥，解析 SOCKS5 地址
    ::net::awaitable<::RelayResult> Process(
        std::unique_ptr<::AsyncStream> stream,
        ::routing::Dispatcher& dispatcher,
        const ::proxyman::inbound::ReceiverSettings& receiver,
        ::net::io_context& io_context,
        ::session::Context& ctx,
        const ::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

    // 对应 xray-core proxy/shadowsocks/server.go 的 handleUDPPayload 解码路径。
    [[nodiscard]] tl::expected<
        ::InboundDatagramResult,
        ::ErrorCode> Process(
        const ::InboundDatagramRequest& request) override;

    [[nodiscard]] tl::expected<
        std::shared_ptr<::InboundDatagramResponse>, ::ErrorCode>
    CreateDatagramResponse(const ::InboundDatagramResult& decoded) override;

private:
    ::UserOnlineTracker& validator_;
    ::StatsShard& stats_;
    ::ConnectionLimiter* limiter_;
    ::ss::SsCipherInfo cipher_info_;
    ::ss::Ss2022UdpReplayCache udp_replay_cache_;
    // 上次匹配成功的用户索引，用于优先尝试（大概率命中同一活跃用户）
    size_t last_matched_index_ = 0;
};

}  // namespace proxy::shadowsocks::inbound
