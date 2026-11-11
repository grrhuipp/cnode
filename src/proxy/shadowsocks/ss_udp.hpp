#pragma once

#include "../outbound_stream_endpoint.hpp"
#include "../uot/uot.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "common/allocator.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/initial_payload.hpp"
#include "common/sharded_user_stats.hpp"
#include "common/target_address.hpp"
#include "common/unsafe.hpp"
#include "infra/json.hpp"
#include "proxy/inbound.hpp"
#include "proxy/outbound.hpp"
#include "shadowsocks_protocol.hpp"
#include "transport/async_stream.hpp"
#include "transport/internet/outbound_target_builder.hpp"
#include "transport/link.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tl/expected.hpp>
#include <utility>
#include <vector>

struct StatsShard;
namespace ss {

class Ss2022UdpReplayWindow {
public:
    static constexpr size_t kWindowBits = 2048;

    [[nodiscard]] bool Accept(uint64_t packet_id) noexcept;

private:
    static constexpr size_t kWordBits = 64;
    static constexpr size_t kWordCount = kWindowBits / kWordBits;

    void Advance(size_t distance) noexcept;

    std::array<uint64_t, kWordCount> seen_{};
    uint64_t highest_ = 0;
    bool initialized_ = false;
};

// Worker-local cache, scoped by authenticated credential and protocol session ID.
// Rejects new sessions when full instead of reopening a protected replay window.
class Ss2022UdpReplayCache {
public:
    static constexpr size_t kMaxSessions = 16384;
    static constexpr auto kRetention = std::chrono::seconds(65);

    Ss2022UdpReplayCache() = default;
    Ss2022UdpReplayCache(const Ss2022UdpReplayCache&) = delete;
    Ss2022UdpReplayCache& operator=(const Ss2022UdpReplayCache&) = delete;
    Ss2022UdpReplayCache(Ss2022UdpReplayCache&&) = default;
    Ss2022UdpReplayCache& operator=(Ss2022UdpReplayCache&&) = default;

    [[nodiscard]] bool Accept(
        std::span<const uint8_t> authenticated_key,
        std::span<const uint8_t, 8> session_id,
        uint64_t packet_id,
        std::chrono::steady_clock::time_point now =
            std::chrono::steady_clock::now());

    [[nodiscard]] size_t Size() const noexcept { return sessions_.size(); }

private:
    struct SessionKey {
        KeyBytes credential;
        uint64_t session_id = 0;

        [[nodiscard]] bool operator==(const SessionKey& other) const noexcept {
            return session_id == other.session_id &&
                credential.size == other.credential.size &&
                ::ConstantTimeEqual(credential.bytes.data(),
                                          other.credential.bytes.data(),
                                          credential.size);
        }
    };
    struct SessionKeyHash {
        [[nodiscard]] size_t operator()(const SessionKey& key) const noexcept;
    };

    struct Session {
        Ss2022UdpReplayWindow window;
        std::chrono::steady_clock::time_point last_seen;
    };

    void PruneExpired(std::chrono::steady_clock::time_point now);

    memory::UnorderedMap<SessionKey, Session, SessionKeyHash> sessions_;
};

// The sole SS2022 path/replay authority, retained by the ingress directory
// even after the live relay ends. The local index only borrows this object.
class Ss2022UdpAssociation final : public InboundDatagramAssociation {
public:
    Ss2022UdpAssociation() noexcept : InboundDatagramAssociation(Policy()) {}
    [[nodiscard]] static const InboundDatagramAssociationPolicy& Policy() noexcept;
    [[nodiscard]] bool Check(
        uint64_t packet_id, uint32_t worker, const udp::endpoint& endpoint,
        InboundDatagramCheck check, Clock::time_point now = Clock::now()) noexcept override;

private:
    Ss2022UdpReplayWindow replay_;
    std::optional<uint64_t> path_packet_id_;
    uint32_t path_worker_ = 0;
    udp::endpoint path_endpoint_;
};

// ============================================================================
// SS AEAD UDP 数据报格式（Xray/shadowsocks-go 兼容）
//
// 客户端 → 服务端:
//   [salt(salt_size)] + AEAD_encrypt(nonce=0, [SOCKS5_addr][payload]) + tag(16)
//
// 服务端 → 客户端:
//   [new_random_salt(salt_size)] + AEAD_encrypt(nonce=0, [SOCKS5_addr][payload]) + tag(16)
//
// 与 TCP 的区别:
//   - 每个数据报独立加密（不共享 nonce 计数器）
//   - nonce 固定为全零（salt 已提供唯一性）
//   - 无 chunk 分帧（整包一次性 AEAD）
// ============================================================================

struct Ss2022UdpTxState {
    SsCipherInfo cipher_info{};
    KeyBytes key;
    std::array<uint8_t, 8> client_session_id{};
    std::array<uint8_t, 8> server_session_id{};
    uint64_t next_packet_id = 0;

    Ss2022UdpTxState() = default;
    Ss2022UdpTxState(const Ss2022UdpTxState&) = default;
    Ss2022UdpTxState& operator=(const Ss2022UdpTxState&) = default;
    Ss2022UdpTxState(Ss2022UdpTxState&&) noexcept = default;
    Ss2022UdpTxState& operator=(Ss2022UdpTxState&&) noexcept = default;

    void Clear() noexcept {
        ::SecureZeroMemory(key.bytes.data(), key.bytes.size());
        key.size = 0;
        ::SecureZeroMemory(client_session_id.data(), client_session_id.size());
        ::SecureZeroMemory(server_session_id.data(), server_session_id.size());
        next_packet_id = 0;
    }

    ~Ss2022UdpTxState() noexcept {
        Clear();
    }
};

struct Ss2022UdpSessionState : Ss2022UdpTxState {
    Ss2022UdpReplayCache receive_replay_cache;
};

// SS UDP 解码结果
struct SsUdpDecodeResult {
    TargetAddress        target;       // 解析出的 SOCKS5 目标地址
    buf::MultiBuffer     payload;      // 解密后的 payload Buffer 所有权
    std::optional<ForwardedMetadata> forwarded;
    std::optional<uint64_t> session_id;
    // SS2022 authenticated metadata, available before replay acceptance.
    std::optional<uint64_t> packet_id;
    KeyBytes             session_owner;
    size_t               user_index = 0;   // 匹配用户在 users 列表中的下标
};

// ============================================================================
// DecodeUdpPacket — 解码 SS AEAD UDP 数据报
//
// users must be an immutable UserStore snapshot. SS2022 AES identity users
// share header decoding per identity-key group, then binary-search PSK hashes;
// every matching candidate still requires full AEAD authentication.
// Nonidentity users retain linear authentication in snapshot order.
//
// 最小包长: salt_size + 1(ATYP) + 1(域名长度或4字节IP) + 2(port) + kTagSize
// 返回 nullopt: 包过短 / 所有用户均不匹配
// deferred_replay authenticates SS2022 without reading or mutating replay_cache;
// the caller must commit packet_id in the full session_owner/session_id namespace.
// Classic AEAD behavior is unchanged.
// ============================================================================
[[nodiscard]] std::optional<SsUdpDecodeResult> DecodeUdpPacket(
    const uint8_t*               datagram,
    size_t                       datagram_len,
    const proxyman::inbound::UserStore::ShadowsocksUsersView& users,
    SsCipherType                 cipher_type,
    size_t                       key_size,
    size_t                       salt_size,
    Ss2022UdpReplayCache&        replay_cache,
    bool                         deferred_replay);

// ============================================================================
// EncodeUdpPacket — 编码 SS AEAD UDP 回包
//
// 生成随机 salt，HKDF 派生子密钥，整包 AEAD 加密。
// 返回:
//   - 缓冲足够：写入 [salt] + [AEAD(SOCKS5_addr + payload)] + [tag]，返回实际长度
//   - output 为空或缓冲不足：不写入，返回所需总长度
//   - 编码失败：返回 0
// ============================================================================
[[nodiscard]] size_t EncodeUdpPacketTo(
    const TargetAddress&        target,
    const uint8_t*              payload,
    size_t                      payload_len,
    std::span<const uint8_t>    master_key,
    SsCipherType                cipher_type,
    size_t                      key_size,
    size_t                      salt_size,
    uint8_t*                    output,
    size_t                      output_size,
    ForwardedMetadataView       forwarded = {});

[[nodiscard]] std::optional<SsUdpDecodeResult> DecodeUdpPacketWithKey(
    const uint8_t* datagram,
    size_t datagram_len,
    std::span<const uint8_t> master_key,
    SsCipherType cipher_type,
    size_t key_size,
    size_t salt_size);

[[nodiscard]] bool Init2022UdpSessionState(
    Ss2022UdpSessionState& state,
    const SsCipherInfo& cipher_info,
    const KeyBytes& key);

[[nodiscard]] size_t Encode2022UdpRequestPacketTo(
    const TargetAddress& target,
    const uint8_t* payload,
    size_t payload_len,
    Ss2022UdpTxState& state,
    std::span<const KeyBytes> psk_chain,
    uint8_t* output,
    size_t output_size,
    ForwardedMetadataView forwarded = {});

[[nodiscard]] size_t Encode2022UdpResponsePacketTo(
    const TargetAddress& target,
    const uint8_t* payload,
    size_t payload_len,
    Ss2022UdpTxState& state,
    uint8_t* output,
    size_t output_size);

[[nodiscard]] std::optional<SsUdpDecodeResult> Decode2022UdpResponsePacket(
    const uint8_t* datagram,
    size_t datagram_len,
    Ss2022UdpSessionState& state);

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

    // By value: the range must stay in this frame until the write completes.
    template <typename BufferRange>
    net::awaitable<void> WriteEncrypted(BufferRange buffers);

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

class RequestBodyWriter final : public transport::MultiBufferWriter {
public:
    RequestBodyWriter(SsAeadCipher write_cipher,
                      uint64_t write_nonce,
                      AsyncStream& stream)
        : write_cipher_(std::move(write_cipher))
        , write_nonce_(write_nonce)
        , stream_(&stream) {}

    RequestBodyWriter(const RequestBodyWriter&) = delete;
    RequestBodyWriter& operator=(const RequestBodyWriter&) = delete;
    RequestBodyWriter(RequestBodyWriter&&) noexcept = default;
    RequestBodyWriter& operator=(RequestBodyWriter&&) noexcept = default;

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;
    bool WriteShutdownClosesLink() const noexcept override {
        return stream_ && stream_->WriteShutdownClosesLink();
    }

private:
    void Finish() {
        write_finished_ = true;
        write_cipher_.reset();
    }

    void Retire() {
        auto* stream = std::exchange(stream_, nullptr);
        write_cipher_.reset();
        if (stream) stream->CloseAbortive();
    }

    template <typename BufferRange>
    net::awaitable<void> WriteEncrypted(BufferRange buffers);

    std::optional<SsAeadCipher> write_cipher_;
    uint64_t write_nonce_ = 0;
    bool write_finished_ = false;
    AsyncStream* stream_ = nullptr;
};

struct WriteTCPRequestResult {
    RequestBodyWriter request_writer;
    KeyBytes request_salt;
};

// xray-core proxy/shadowsocks/client.go 对应的客户端握手与 reader/writer 入口。
[[nodiscard]] net::awaitable<tl::expected<WriteTCPRequestResult, ErrorCode>>
WriteTCPRequest(const TargetAddress& target,
                const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                std::span<const KeyBytes> psk_chain,
                AsyncStream& stream,
                ForwardedMetadataView forwarded = {});

// 2022 固定响应头可携带首段载荷；它在 reader 之前交付，reader 只负责后续记录。
struct ReadTCPResponseResult {
    detail::BodyReader reader;
    buf::MultiBuffer initial_payload;
};

[[nodiscard]] net::awaitable<tl::expected<ReadTCPResponseResult, ErrorCode>>
ReadTCPResponse(const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
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

// ============================================================================
// SS Outbound 配置
// ============================================================================
struct SsOutboundConfig {
    OutboundServer server;
    std::optional<proxy::uot::Version> uot_version;
};

// ============================================================================
// SsOutbound — 出站编排（握手、初始 payload、relay、收尾）
// 协议加密状态由 shadowsocks_protocol.cpp 承担。
// ============================================================================
namespace proxy::shadowsocks::outbound {

// One authenticated UDP association, with a fixed proxy next hop. The inner
// packet target is encoded as supplied; only the server name is resolved here.
class UdpRequest final : public ::proxy::OutboundDatagramEndpointBase {
public:
    UdpRequest(net::io_context& io, app::dns::DNS& dns,
               const net::ip::address& bind_address, TargetAddress server,
               const ss::SsCipherInfo& cipher_info, const ss::KeyBytes& master_key,
               std::span<const ss::KeyBytes> psk_chain,
               ForwardedMetadataView forwarded = {})
        : OutboundDatagramEndpointBase(io, bind_address), dns_(dns), server_(std::move(server)),
          cipher_info_(cipher_info), master_key_(master_key), psk_chain_(psk_chain) {
        forwarded_ = ForwardedMetadata::FromView(forwarded);
        if (ss::Is2022Cipher(cipher_info_.type)) {
            ss2022_state_.emplace();
            if (!ss::Init2022UdpSessionState(*ss2022_state_, cipher_info_, master_key_))
                throw transport::LinkError(ErrorCode::INTERNAL);
        }
        if (server_.resolved_addr) {
            if (server_.resolved_addr->is_v6() != socket_.IsIPv6())
                throw transport::LinkError(ErrorCode::SOCKET_BIND_FAILED);
            server_endpoint_.emplace(*server_.resolved_addr, server_.port);
        }
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        // Keep one absolute read budget across unauthenticated or wrong-source
        // packets. Only an authenticated payload is valid receive activity.
        auto read = socket_.StartRead();
        while (true) {
            auto packet = co_await read.Receive();
            if (!server_endpoint_ || packet.source != *server_endpoint_) continue;
            const buf::ContiguousBufferView view(packet.payload);
            const auto bytes = view.Bytes();
            auto decoded = ss2022_state_
                ? ss::Decode2022UdpResponsePacket(bytes.data(), bytes.size(), *ss2022_state_)
                : ss::DecodeUdpPacketWithKey(bytes.data(), bytes.size(), master_key_.span(),
                    cipher_info_.type, cipher_info_.key_size, cipher_info_.salt_size);
            if (!decoded) continue;
            if (!decoded->target.IsValid()) continue;
            socket_.TouchActivity();
            co_return std::move(decoded->payload);
        }
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) override {
        const auto datagram = buf::InspectUdpDatagram(payload);
        if (datagram.status == buf::UdpDatagramStatus::Empty) co_return;
        if (!datagram.Valid() || !datagram.target || !datagram.target->IsValid())
            throw transport::LinkError(ErrorCode::INVALID_ARGUMENT);
        if (write_closed_) throw transport::WriteClosed{};
        auto write = socket_.StartWrite();
        if (!server_endpoint_) {
            auto server = co_await ResolveUdpEndpoint(dns_, server_, socket_, write);
            if (!server) throw transport::LinkError(server.error());
            server_endpoint_ = *server;
        }
        if (write.Cancelled()) throw transport::LinkError(write.CancellationReason());
        const buf::ContiguousBufferView view(payload);
        const auto bytes = view.Bytes();
        const size_t encoded_len = EncodedPacketSize(*datagram.target, bytes);
        const size_t maximum = server_endpoint_->address().is_v6() ? 65527 : 65507;
        if (encoded_len == 0 || encoded_len > maximum)
            throw transport::LinkError(ErrorCode::INVALID_ARGUMENT);
        buf::ContiguousWriteBuffer encoded;
        uint8_t* dst = encoded.Prepare(encoded_len);
        if (EncodePacketTo(*datagram.target, bytes, dst, encoded_len) != encoded_len)
            throw transport::LinkError(ErrorCode::INTERNAL);
        const std::array<net::const_buffer, 1> buffers{net::buffer(dst, encoded_len)};
        co_await write.SendTo(*server_endpoint_, buffers);
    }
private:
    size_t EncodedPacketSize(const TargetAddress& target, std::span<const uint8_t> payload) {
        return EncodePacketTo(target, payload, nullptr, 0);
    }
    size_t EncodePacketTo(const TargetAddress& target, std::span<const uint8_t> payload,
                          uint8_t* output, size_t output_size) {
        const ForwardedMetadataView forwarded =
            forwarded_ ? forwarded_->View() : ForwardedMetadataView{};
        if (ss2022_state_)
            return ss::Encode2022UdpRequestPacketTo(target, payload.data(), payload.size(),
                *ss2022_state_, psk_chain_, output, output_size, forwarded);
        return ss::EncodeUdpPacketTo(target, payload.data(), payload.size(), master_key_.span(),
            cipher_info_.type, cipher_info_.key_size, cipher_info_.salt_size,
            output, output_size, forwarded);
    }

    app::dns::DNS& dns_;
    const TargetAddress server_;
    std::optional<udp::endpoint> server_endpoint_;
    const ss::SsCipherInfo cipher_info_;
    ss::KeyBytes master_key_;
    const std::span<const ss::KeyBytes> psk_chain_;
    std::optional<ForwardedMetadata> forwarded_;
    std::optional<ss::Ss2022UdpSessionState> ss2022_state_;
};

// A complete, validated credential value. Preparation never drops a chain link
// or substitutes a different cipher; Worker handlers only consume this value.
class Credentials {
public:
    [[nodiscard]] static std::optional<Credentials> Prepare(
        std::string_view method, std::string_view password);

    [[nodiscard]] const ss::SsCipherInfo& Cipher() const noexcept { return cipher_; }
    [[nodiscard]] const ss::KeyBytes& MasterKey() const noexcept { return master_key_; }
    [[nodiscard]] std::span<const ss::KeyBytes> PskChain() const noexcept {
        return psk_chain_;
    }

private:
    Credentials(ss::SsCipherInfo cipher, ss::KeyBytes master_key,
                std::vector<ss::KeyBytes> psk_chain)
        : cipher_(cipher), master_key_(master_key), psk_chain_(std::move(psk_chain)) {}

    ss::SsCipherInfo cipher_;
    ss::KeyBytes master_key_;
    std::vector<ss::KeyBytes> psk_chain_;
};

[[nodiscard]] tl::expected<std::optional<proxy::uot::Version>, std::string>
ParseUotVersion(const json::object& source);

struct PreparedSettings {
    SsOutboundConfig config;
    Credentials credentials;
};

class Handler final : public ::Outbound {
public:
    explicit Handler(std::shared_ptr<const PreparedSettings> prepared);

    ~Handler() noexcept override = default;

    ::net::awaitable<::OutboundProcessResult> Process(
        ::session::Context& ctx,
        ::transport::Link inbound,
        ::OutboundDialer& dialer,
        const ::TimeoutsConfig& timeouts,
        ::StatsShard& stats,
        const ::RelayConfig& relay_config,
        ::buf::MultiBufferBatch first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;

private:
    std::shared_ptr<const PreparedSettings> prepared_;
};

}  // namespace proxy::shadowsocks::outbound
