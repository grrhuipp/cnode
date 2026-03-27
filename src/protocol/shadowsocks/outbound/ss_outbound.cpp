#include "acppnode/protocol/shadowsocks/outbound/ss_outbound.hpp"
#include "acppnode/protocol/protocol_registry.hpp"
#include "acppnode/protocol/outbound_helpers.hpp"
#include "acppnode/transport/stream_helpers.hpp"
#include "acppnode/dns/dns_service.hpp"
#include "acppnode/infra/json_helpers.hpp"
#include "acppnode/infra/log.hpp"

#include <openssl/rand.h>

#include "acppnode/common/buffer_util.hpp"
#include <algorithm>
#include <cstring>

namespace acpp {

namespace {

[[noreturn]] void ThrowSsWriteError(const char* what) {
    throw boost::system::system_error(boost::asio::error::connection_reset, what);
}

}  // namespace

// ============================================================================
// SsClientAsyncStream
// ============================================================================

SsClientAsyncStream::SsClientAsyncStream(
    std::unique_ptr<AsyncStream> inner,
    ss::SsCipherType cipher_type,
    size_t key_size,
    size_t salt_size,
    std::span<const uint8_t> master_key,
    TargetAddress target)
    : inner_(std::move(inner))
    , target_(std::move(target))
    , cipher_type_(cipher_type)
    , key_size_(key_size)
    , salt_size_(salt_size)
    , master_key_(master_key.begin(), master_key.end()) {
}

// ── 内部辅助 ─────────────────────────────────────────────────────────────────

cobalt::task<bool> SsClientAsyncStream::ReadFull(uint8_t* buf, size_t len) {
    co_return co_await acpp::ReadFull(*inner_, buf, len);
}

cobalt::task<bool> SsClientAsyncStream::WriteFull(const uint8_t* buf, size_t len) {
    co_return co_await acpp::WriteFull(*inner_, buf, len);
}

cobalt::task<bool> SsClientAsyncStream::ReadNextChunk() {
    // 初始化读端（首次读时接收 server salt）
    if (!read_init_) {
        if (salt_size_ > 64 || key_size_ > 64) {
            co_return false;
        }

        std::array<uint8_t, 64> server_salt{};
        if (!co_await ReadFull(server_salt.data(), salt_size_)) co_return false;

        std::array<uint8_t, 64> read_subkey{};
        if (!ss::DeriveSubkey(master_key_.data(), key_size_,
                              server_salt.data(), salt_size_,
                              read_subkey.data())) {
            co_return false;
        }

        read_cipher_ = std::make_unique<ss::SsAeadCipher>(
            cipher_type_, read_subkey.data(), key_size_);
        read_nonce_ = 0;
        read_init_  = true;
    }

    // 读 [enc_len(2) + tag(16)]
    uint8_t enc_len_buf[2 + ss::SsAeadCipher::kTagSize];
    if (!co_await ReadFull(enc_len_buf, sizeof(enc_len_buf))) co_return false;

    uint8_t len_plain[2];
    auto nonce = ss::MakeNonce(read_nonce_);
    if (!read_cipher_->Decrypt(nonce.data(), enc_len_buf, sizeof(enc_len_buf), len_plain)) {
        co_return false;
    }
    ++read_nonce_;

    const uint16_t payload_len =
        static_cast<uint16_t>((len_plain[0] << 8) | len_plain[1]);

    if (payload_len == 0 || payload_len > ss::kMaxChunkPayload) co_return false;

    // 读 [enc_payload(payload_len) + tag(16)]
    if (!co_await ReadFull(read_chunk_buf_.data(),
                           payload_len + ss::SsAeadCipher::kTagSize)) co_return false;

    if (read_buf_offset_ >= read_buf_.size()) {
        read_buf_.clear();
        read_buf_offset_ = 0;
    }
    const size_t old_size = read_buf_.size();
    read_buf_.resize(old_size + payload_len);

    auto nonce2 = ss::MakeNonce(read_nonce_);
    if (!read_cipher_->Decrypt(nonce2.data(), read_chunk_buf_.data(),
                               payload_len + ss::SsAeadCipher::kTagSize,
                               read_buf_.data() + old_size)) {
        read_buf_.resize(old_size);
        co_return false;
    }
    ++read_nonce_;

    co_return true;
}

// SendHandshake — 首次写：生成 client salt，发送 [salt][addr_chunk][data_chunk(可选)]
cobalt::task<bool> SsClientAsyncStream::SendHandshake(const uint8_t* data, size_t data_len) {
    if (salt_size_ > 64 || key_size_ > 64) {
        co_return false;
    }

    // 生成 client salt
    std::array<uint8_t, 64> client_salt{};
    if (RAND_bytes(client_salt.data(), static_cast<int>(salt_size_)) != 1) {
        co_return false;
    }

    // 派生写子密钥
    std::array<uint8_t, 64> write_subkey{};
    if (!ss::DeriveSubkey(master_key_.data(), key_size_,
                          client_salt.data(), salt_size_,
                          write_subkey.data())) {
        co_return false;
    }

    write_cipher_ = std::make_unique<ss::SsAeadCipher>(
        cipher_type_, write_subkey.data(), key_size_);
    write_nonce_ = 0;

    auto addr_bytes = ss::EncodeSocks5Address(target_);
    if (addr_bytes.empty() || addr_bytes.size() > ss::kMaxChunkPayload) {
        co_return false;
    }
    const size_t first_chunk_data = std::min(
        data_len, ss::kMaxChunkPayload - addr_bytes.size());

    std::array<uint8_t, ss::kMaxChunkPayload> first_chunk{};
    std::memcpy(first_chunk.data(), addr_bytes.data(), addr_bytes.size());
    if (first_chunk_data > 0) {
        std::memcpy(first_chunk.data() + addr_bytes.size(), data, first_chunk_data);
    }

    // 合并 salt + enc_len + enc_payload 为单次写入
    const size_t payload_size = addr_bytes.size() + first_chunk_data;
    {
        // 组装到 handshake_buf: [salt][enc_len(18)][enc_payload]
        const size_t enc_payload_size = payload_size + ss::SsAeadCipher::kTagSize;
        const size_t total = salt_size_ + kLenHeaderSize + enc_payload_size;
        memory::ByteVector handshake_buf(total);

        // salt
        std::memcpy(handshake_buf.data(), client_salt.data(), salt_size_);
        size_t pos = salt_size_;

        // enc_len
        uint8_t len_plain[2] = {
            static_cast<uint8_t>(payload_size >> 8),
            static_cast<uint8_t>(payload_size & 0xFF)
        };
        auto nonce_l = ss::MakeNonce(write_nonce_);
        if (!write_cipher_->Encrypt(nonce_l.data(), len_plain, 2,
                                    handshake_buf.data() + pos)) {
            co_return false;
        }
        ++write_nonce_;
        pos += kLenHeaderSize;

        // enc_payload
        auto nonce_p = ss::MakeNonce(write_nonce_);
        if (!write_cipher_->Encrypt(nonce_p.data(), first_chunk.data(), payload_size,
                                    handshake_buf.data() + pos)) {
            co_return false;
        }
        ++write_nonce_;

        if (!co_await WriteFull(handshake_buf.data(), total)) co_return false;
    }

    // 剩余数据用常规 WriteChunk（已优化为单次写入）
    if (data_len > first_chunk_data) {
        if (!co_await WriteChunk(data + first_chunk_data, data_len - first_chunk_data)) {
            co_return false;
        }
    }

    handshake_sent_ = true;
    co_return true;
}

cobalt::task<bool> SsClientAsyncStream::WriteChunk(const uint8_t* data, size_t data_len) {
    size_t offset = 0;
    while (offset < data_len) {
        const size_t chunk_size = std::min(data_len - offset, ss::kMaxChunkPayload);

        // enc_len → write_chunk_buf_[0..17]
        uint8_t len_plain[2] = {
            static_cast<uint8_t>(chunk_size >> 8),
            static_cast<uint8_t>(chunk_size & 0xFF)
        };
        auto nonce_l = ss::MakeNonce(write_nonce_);
        if (!write_cipher_->Encrypt(nonce_l.data(), len_plain, 2,
                                    write_chunk_buf_.data())) {
            co_return false;
        }
        ++write_nonce_;

        // enc_payload → write_chunk_buf_[18..]
        auto nonce_p = ss::MakeNonce(write_nonce_);
        if (!write_cipher_->Encrypt(nonce_p.data(), data + offset, chunk_size,
                                    write_chunk_buf_.data() + kLenHeaderSize)) {
            co_return false;
        }
        ++write_nonce_;

        // 单次写入 enc_len + enc_payload
        const size_t total = kLenHeaderSize + chunk_size + ss::SsAeadCipher::kTagSize;
        if (!co_await WriteFull(write_chunk_buf_.data(), total)) {
            co_return false;
        }

        offset += chunk_size;
    }
    co_return true;
}

cobalt::task<size_t> SsClientAsyncStream::AsyncRead(net::mutable_buffer buf) {
    if (read_buf_offset_ >= read_buf_.size()) {
        read_buf_.clear();
        read_buf_offset_ = 0;
        if (!co_await ReadNextChunk()) co_return 0;
    }

    const size_t available = read_buf_.size() - read_buf_offset_;
    const size_t to_copy = std::min(buf.size(), available);
    std::memcpy(buf.data(), read_buf_.data() + read_buf_offset_, to_copy);
    read_buf_offset_ += to_copy;

    if (read_buf_offset_ >= read_buf_.size()) {
        read_buf_.clear();
        read_buf_offset_ = 0;
        ReleaseIdleBuffer(read_buf_, 8 * 1024);
    }
    co_return to_copy;
}

cobalt::task<size_t> SsClientAsyncStream::AsyncWrite(net::const_buffer buf) {
    const uint8_t* data = static_cast<const uint8_t*>(buf.data());
    const size_t   len  = buf.size();

    if (!handshake_sent_) {
        if (!co_await SendHandshake(data, len)) {
            ThrowSsWriteError("Shadowsocks client send handshake failed");
        }
        co_return len;
    }

    if (!co_await WriteChunk(data, len)) {
        ThrowSsWriteError("Shadowsocks client write chunk failed");
    }
    co_return len;
}

// ============================================================================
// SsOutboundHandler
// ============================================================================

SsOutboundHandler::SsOutboundHandler(ss::SsCipherType cipher_type,
                                     size_t key_size,
                                     size_t salt_size,
                                     std::span<const uint8_t> master_key)
    : cipher_type_(cipher_type)
    , key_size_(key_size)
    , salt_size_(salt_size)
    , master_key_(master_key.begin(), master_key.end()) {
}

cobalt::task<OutboundWrapResult> SsOutboundHandler::WrapStream(
    std::unique_ptr<AsyncStream> stream,
    const SessionContext& ctx) {

    const auto& target = ctx.EffectiveTarget();

    co_return OutboundWrapResult(std::make_unique<SsClientAsyncStream>(
        std::move(stream),
        cipher_type_,
        key_size_,
        salt_size_,
        master_key_,
        target));
}

// ============================================================================
// SsOutbound
// ============================================================================

SsOutbound::SsOutbound(net::any_io_executor executor,
                       const SsOutboundConfig& config,
                       IDnsService* dns_service)
    : config_(config)
    , dns_service_(dns_service) {
    (void)executor;

    auto info = ss::ParseCipherMethod(config_.method);
    if (info) {
        cipher_info_ = *info;
    } else {
        LOG_WARN("[SsOutbound] Unknown cipher '{}', fallback to aes-256-gcm", config_.method);
        cipher_info_ = ss::SsCipherInfo{ss::SsCipherType::AES_256_GCM, 32, 32};
    }

    {
        auto derived_key = ss::DeriveKey(config_.password, cipher_info_.key_size);
        master_key_.assign(derived_key.begin(), derived_key.end());
    }
    stream_settings_ = config_.stream_settings;
    stream_settings_.RecomputeModes();
    if (stream_settings_.network.empty()) {
        stream_settings_.network = "tcp";
        stream_settings_.security = "none";
        stream_settings_.RecomputeModes();
    }

    handler_ = std::make_unique<SsOutboundHandler>(
        cipher_info_.type,
        cipher_info_.key_size,
        cipher_info_.salt_size,
        master_key_);
}

cobalt::task<std::expected<OutboundTransportTarget, ErrorCode>>
SsOutbound::ResolveTransportTarget(SessionContext& ctx) {
    try {
        auto addrs_result = co_await ResolveOutboundAddresses(config_.address, dns_service_);
        if (!addrs_result || addrs_result->empty()) {
            co_return std::unexpected(addrs_result ? ErrorCode::DNS_RESOLVE_FAILED : addrs_result.error());
        }

        OutboundTransportTarget target;
        target.host = config_.address;
        target.port = config_.port;
        target.timeout = config_.timeout;
        target.stream_settings = &stream_settings_;
        target.candidates.reserve(addrs_result->size());
        for (const auto& addr : *addrs_result) {
            target.candidates.push_back(OutboundDialCandidate{
                .endpoint = tcp::endpoint(addr, config_.port),
                .bind_local = std::nullopt
            });
        }
        co_return target;

    } catch (const std::exception& e) {
        LOG_CONN_FAIL_CTX(ctx, "[SsOutbound] resolve target failed: {}", e.what());
        co_return std::unexpected(ErrorCode::OUTBOUND_CONNECTION_FAILED);
    }
}

std::unique_ptr<IOutbound> CreateSsOutbound(
    net::any_io_executor executor,
    const SsOutboundConfig& config,
    IDnsService* dns_service) {
    return std::make_unique<SsOutbound>(executor, config, dns_service);
}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kSsRegistered = (acpp::OutboundFactory::Instance().Register(
    "shadowsocks",
    [](const acpp::OutboundConfig& cfg,
       acpp::net::any_io_executor executor,
       acpp::IDnsService* dns,
       acpp::UDPSessionManager* /*udp_mgr*/,
       std::chrono::seconds timeout) -> std::unique_ptr<acpp::IOutbound> {

        const auto& s = cfg.settings;

        acpp::SsOutboundConfig ss_config;
        ss_config.tag     = cfg.tag;
        ss_config.timeout = timeout;

        // Xray 格式: servers[0] 包含 address/port/method/password
        const auto* servers_p = s.if_contains("servers");
        if (servers_p && servers_p->is_array() && !servers_p->as_array().empty()) {
            const auto& srv = servers_p->as_array()[0].as_object();
            ss_config.address  = acpp::json::GetString(srv, "address", "");
            ss_config.port     = static_cast<uint16_t>(acpp::json::GetInt(srv, "port", 8388));
            ss_config.password = acpp::json::GetString(srv, "password", "");
            ss_config.method   = acpp::json::GetString(srv, "method", "aes-256-gcm");
        } else {
            // 兼容旧扁平格式
            ss_config.address  = acpp::json::GetString(s, "Address",  "address",  "");
            ss_config.port     = static_cast<uint16_t>(acpp::json::GetInt(s, "Port", "port", 8388));
            ss_config.password = acpp::json::GetString(s, "Password", "password", "");
            ss_config.method   = acpp::json::GetString(s, "Method",   "method",   "aes-256-gcm");
        }

        ss_config.stream_settings = cfg.stream_settings;
        ss_config.stream_settings.RecomputeModes();

        if (ss_config.address.empty() || ss_config.password.empty()) {
            return nullptr;
        }

        return acpp::CreateSsOutbound(executor, ss_config, dns);
    }), true);
}  // namespace
