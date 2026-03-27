#include "acppnode/protocol/vmess/outbound/vmess_outbound.hpp"
#include "acppnode/protocol/protocol_registry.hpp"
#include "acppnode/protocol/outbound_helpers.hpp"
#include "acppnode/transport/stream_helpers.hpp"
#include "acppnode/infra/json_helpers.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/app/session_context.hpp"
#include "acppnode/common/unsafe.hpp"       // ISSUE-02-02: unsafe cast 收敛
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <chrono>
#include <cstring>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include "acppnode/common/buffer_util.hpp"
#include <format>

namespace acpp {

namespace {

constexpr size_t kVMessHandshakeHeaderMax = 512;
constexpr size_t kVMessHandshakeHeaderEncMax = kVMessHandshakeHeaderMax + 16;
constexpr size_t kVMessHandshakePacketMax = 16 + 18 + 8 + kVMessHandshakeHeaderEncMax;
constexpr size_t kVMessResponseHeaderMax = 1024;
constexpr size_t kWriteBatchKeepCapacity = 128 * 1024;

[[noreturn]] void ThrowVMessWriteError(const char* what) {
    throw boost::system::system_error(boost::asio::error::connection_reset, what);
}

}  // namespace

using namespace vmess;

// ============================================================================
// VMessOutbound 实现
// ============================================================================

VMessOutbound::VMessOutbound(net::any_io_executor executor,
                             const VMessOutboundConfig& config,
                             IDnsService* dns_service)
    : config_(config)
    , dns_service_(dns_service) {
    (void)executor;

    user_ = VMessUser::FromUUID(config_.uuid);
    if (!user_) {
        LOG_ERROR("VMess outbound '{}': invalid UUID", config_.tag);
    } else {
        handler_ = std::make_unique<VMessOutboundHandler>(*user_, config_.security);
    }

    config_.stream_settings.RecomputeModes();
    LOG_DEBUG("VMess outbound '{}' created: {}:{}, network={}, security={}",
              config_.tag, config_.address, config_.port,
              config_.stream_settings.network,
              config_.stream_settings.security);
}

cobalt::task<std::expected<OutboundTransportTarget, ErrorCode>>
VMessOutbound::ResolveTransportTarget(SessionContext& ctx) {
    if (!user_) {
        co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    auto addrs_result = co_await ResolveOutboundAddresses(config_.address, dns_service_);
    if (!addrs_result || addrs_result->empty()) {
        LOG_CONN_FAIL_CTX(ctx, "[VMess] DNS resolve failed for {}", config_.address);
        co_return std::unexpected(addrs_result ? ErrorCode::DNS_RESOLVE_FAILED : addrs_result.error());
    }

    OutboundTransportTarget target;
    target.host = config_.address;
    target.port = config_.port;
    target.timeout = config_.timeout;
    target.stream_settings = &config_.stream_settings;
    target.candidates.reserve(addrs_result->size());
    for (const auto& addr : *addrs_result) {
        target.candidates.push_back(OutboundDialCandidate{
            .endpoint = tcp::endpoint(addr, config_.port),
            .bind_local = std::nullopt
        });
    }
    target.server_name = config_.stream_settings.tls.server_name.empty()
        ? config_.address
        : config_.stream_settings.tls.server_name;

    if (target.stream_settings->IsWs()) {
        const auto ws_it = target.stream_settings->ws.headers.find("Host");
        if (ws_it != target.stream_settings->ws.headers.end() && !ws_it->second.empty()) {
            target.server_name = ws_it->second;
        }
    }

    LOG_CONN_DEBUG(ctx, "[VMess] transport target {}:{} ({}/{})",
                   target.host, target.port,
                   target.stream_settings->security,
                   target.stream_settings->network);
    co_return target;
}

// ============================================================================
// VMessOutboundHandler 实现
// ============================================================================

cobalt::task<OutboundWrapResult> VMessOutboundHandler::WrapStream(
    std::unique_ptr<AsyncStream> stream,
    const SessionContext& ctx) {

    const auto& target = ctx.EffectiveTarget();

    auto vmess_stream = std::make_unique<VMessClientAsyncStream>(
        std::move(stream), user_, target, security_, ctx.conn_id);

    auto handshake_result = co_await vmess_stream->SendHandshake();
    if (!handshake_result) {
        ErrorCode code = handshake_result.error();
        if (code == ErrorCode::OK) {
            code = ErrorCode::PROTOCOL_AUTH_FAILED;
        }
        LOG_CONN_FAIL("[conn={}] VMessOutboundHandler: protocol handshake failed: {}",
                      ctx.conn_id, ErrorCodeToString(code));
        co_return std::unexpected(code);
    }

    LOG_CONN_DEBUG(ctx, "[VMess] WrapStream OK");
    co_return OutboundWrapResult(std::move(vmess_stream));
}

std::unique_ptr<IOutbound> CreateVMessOutbound(
    net::any_io_executor executor,
    const VMessOutboundConfig& config,
    IDnsService* dns_service) {
    return std::make_unique<VMessOutbound>(executor, config, dns_service);
}

// ============================================================================
// VMessClientAsyncStream 实现
// ============================================================================

namespace vmess {

VMessClientAsyncStream::VMessClientAsyncStream(
    std::unique_ptr<AsyncStream> inner,
    const VMessUser& user,
    const TargetAddress& target,
    Security security,
    uint64_t conn_id)
    : inner_(std::move(inner))
    , user_(user)
    , target_(target)
    , security_(security) {
    (void)conn_id;

    // 生成随机 body_key 和 body_iv
    RAND_bytes(body_key_.data(), 16);
    RAND_bytes(body_iv_.data(), 16);

    // 生成 response_header
    RAND_bytes(&response_header_, 1);

    // 设置选项 - 必须包含 CHUNK_STREAM
    // CHUNK_STREAM: 分块传输模式（必需）
    // CHUNK_MASKING: 长度混淆
    // GLOBAL_PADDING: 全局填充
    options_ = Option::CHUNK_STREAM | Option::CHUNK_MASKING | Option::GLOBAL_PADDING;
    global_padding_ = true;

    // AEAD 模式：直接使用 body_key 和 body_iv
    std::memcpy(request_key_.data(), body_key_.data(), 16);
    std::memcpy(request_iv_.data(), body_iv_.data(), 16);

    // ResponseKey = SHA256(RequestKey)[0:16]
    // ResponseIV = SHA256(RequestIV)[0:16]
    auto resp_key_hash = SHA256Sum(request_key_.data(), 16);
    auto resp_iv_hash = SHA256Sum(request_iv_.data(), 16);
    std::memcpy(response_key_.data(), resp_key_hash.data(), 16);
    std::memcpy(response_iv_.data(), resp_iv_hash.data(), 16);

    // 创建加密器
    // 客户端：写用 request 密钥，读用 response 密钥
    write_cipher_ = std::make_unique<VMessCipher>(security_, request_key_.data(), request_iv_.data());
    read_cipher_ = std::make_unique<VMessCipher>(security_, response_key_.data(), response_iv_.data());

    // 创建 mask
    // 客户端：写用原始 body_iv，读用 response_iv
    write_mask_ = std::make_unique<ShakeMask>(body_iv_.data());
    read_mask_ = std::make_unique<ShakeMask>(response_iv_.data());
}

cobalt::task<OutboundHandshakeResult> VMessClientAsyncStream::SendHandshake() {
    auto fail = [](ErrorCode code) -> OutboundHandshakeResult {
        if (code == ErrorCode::OK) {
            code = ErrorCode::PROTOCOL_AUTH_FAILED;
        }
        return std::unexpected(code);
    };

    if (handshake_sent_) {
        co_return {};
    }

    // 获取当前时间戳
    auto now = std::chrono::system_clock::now();
    int64_t ts = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();

    // 构建请求头（固定缓冲，避免握手阶段临时堆分配）
    std::array<uint8_t, kVMessHandshakeHeaderMax> header{};
    size_t header_len = 0;
    auto append_header = [&](const void* data, size_t len) -> bool {
        if (header_len + len > header.size()) return false;
        std::memcpy(header.data() + header_len, data, len);
        header_len += len;
        return true;
    };
    auto append_header_u8 = [&](uint8_t v) -> bool {
        return append_header(&v, 1);
    };

    if (!append_header_u8(VERSION)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    if (!append_header(body_iv_.data(), body_iv_.size())) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    if (!append_header(body_key_.data(), body_key_.size())) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    if (!append_header_u8(response_header_)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    if (!append_header_u8(options_)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);

    // Padding Length + Security (1 byte)
    uint8_t padding_len = 0;
    if (!append_header_u8(static_cast<uint8_t>((padding_len << 4) | static_cast<uint8_t>(security_)))) {
        co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    if (!append_header_u8(0)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);  // Reserved
    if (!append_header_u8(static_cast<uint8_t>(Command::TCP))) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);

    const uint8_t port_be[2] = {
        static_cast<uint8_t>(target_.port >> 8),
        static_cast<uint8_t>(target_.port & 0xFF)
    };
    if (!append_header(port_be, sizeof(port_be))) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);

    // Address
    boost::system::error_code ec;
    auto addr = net::ip::make_address(target_.host, ec);

    if (!ec && addr.is_v4()) {
        // IPv4
        if (!append_header_u8(1)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
        auto bytes = addr.to_v4().to_bytes();
        if (!append_header(bytes.data(), bytes.size())) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    } else if (!ec && addr.is_v6()) {
        // IPv6
        if (!append_header_u8(3)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
        auto bytes = addr.to_v6().to_bytes();
        if (!append_header(bytes.data(), bytes.size())) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    } else {
        // Domain
        if (target_.host.size() > 255) co_return fail(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        if (!append_header_u8(2)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
        if (!append_header_u8(static_cast<uint8_t>(target_.host.size()))) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
        if (!append_header(target_.host.data(), target_.host.size())) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    // Padding (可选)
    if (padding_len > 0) {
        if (header_len + padding_len > header.size()) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
        if (RAND_bytes(header.data() + header_len, static_cast<int>(padding_len)) != 1) {
            co_return fail(ErrorCode::INTERNAL);
        }
        header_len += padding_len;
    }

    // F (checksum) - FNV1a of header
    uint32_t checksum = FNV1a32(header.data(), header_len);
    const uint8_t checksum_be[4] = {
        static_cast<uint8_t>(checksum >> 24),
        static_cast<uint8_t>(checksum >> 16),
        static_cast<uint8_t>(checksum >> 8),
        static_cast<uint8_t>(checksum)
    };
    if (!append_header(checksum_be, sizeof(checksum_be))) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);

    // 生成 AuthID
    std::array<uint8_t, 16> auth_id;
    GenerateAuthID(user_.auth_key.data(), ts, auth_id.data());

    // 生成 connection nonce (8 bytes)
    uint8_t connection_nonce[8];
    if (RAND_bytes(connection_nonce, 8) != 1) {
        co_return fail(ErrorCode::INTERNAL);
    }

    // 派生密钥需要 auth_id 和 nonce
    // ISSUE-02-02: 使用 unsafe::ptr_cast 替代 reinterpret_cast
    std::string auth_id_str(unsafe::ptr_cast<const char>(auth_id.data()), 16);
    std::string nonce_str(unsafe::ptr_cast<const char>(connection_nonce), 8);

    // 加密长度
    const std::array<std::string_view, 3> len_key_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
        auth_id_str,
        nonce_str
    };
    auto len_key = KDF16(user_.cmd_key.data(), 16, len_key_path);

    uint8_t len_iv[12];
    const std::array<std::string_view, 3> len_iv_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
        auth_id_str,
        nonce_str
    };
    KDF(user_.cmd_key.data(), 16, len_iv_path, len_iv, 12);

    uint8_t len_plain[2] = {
        static_cast<uint8_t>((header_len >> 8) & 0xFF),
        static_cast<uint8_t>(header_len & 0xFF)
    };

    // 加密长度（使用 AAD = auth_id）
    uint8_t len_enc[18];
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        co_return fail(ErrorCode::INTERNAL);
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, len_key.data(), len_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    // AAD = auth_id
    int out_len;
    if (EVP_EncryptUpdate(ctx, nullptr, &out_len, auth_id.data(),
                          static_cast<int>(auth_id.size())) != 1 ||
        EVP_EncryptUpdate(ctx, len_enc, &out_len, len_plain,
                          static_cast<int>(sizeof(len_plain))) != 1 ||
        EVP_EncryptFinal_ex(ctx, len_enc + out_len, &out_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, len_enc + 2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    EVP_CIPHER_CTX_free(ctx);

    // 加密请求头
    const std::array<std::string_view, 3> header_key_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_AEAD_KEY,
        auth_id_str,
        nonce_str
    };
    auto header_key = KDF16(user_.cmd_key.data(), 16, header_key_path);

    uint8_t header_iv[12];
    const std::array<std::string_view, 3> header_iv_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_AEAD_IV,
        auth_id_str,
        nonce_str
    };
    KDF(user_.cmd_key.data(), 16, header_iv_path, header_iv, 12);

    // 加密头部（使用 AAD = auth_id）
    std::array<uint8_t, kVMessHandshakeHeaderEncMax> header_enc{};
    const size_t header_enc_len = header_len + 16;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        co_return fail(ErrorCode::INTERNAL);
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, header_key.data(), header_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    // AAD = auth_id
    if (EVP_EncryptUpdate(ctx, nullptr, &out_len, auth_id.data(),
                          static_cast<int>(auth_id.size())) != 1 ||
        EVP_EncryptUpdate(ctx, header_enc.data(), &out_len, header.data(),
                          static_cast<int>(header_len)) != 1 ||
        EVP_EncryptFinal_ex(ctx, header_enc.data() + out_len, &out_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                            header_enc.data() + header_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    EVP_CIPHER_CTX_free(ctx);

    // 发送: AuthID (16) + EncLen (18) + ConnectionNonce (8) + EncHeader
    std::array<uint8_t, kVMessHandshakePacketMax> packet{};
    size_t packet_len = 0;
    auto append_packet = [&](const void* data, size_t len) -> bool {
        if (packet_len + len > packet.size()) return false;
        std::memcpy(packet.data() + packet_len, data, len);
        packet_len += len;
        return true;
    };
    if (!append_packet(auth_id.data(), auth_id.size())) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    if (!append_packet(len_enc, sizeof(len_enc))) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    if (!append_packet(connection_nonce, sizeof(connection_nonce))) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    if (!append_packet(header_enc.data(), header_enc_len)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);

    if (!co_await WriteFull(packet.data(), packet_len)) {
        co_return fail(ErrorCode::SOCKET_WRITE_FAILED);
    }

    handshake_sent_ = true;
    co_return {};
}

cobalt::task<bool> VMessClientAsyncStream::ReadResponseHeader() {
    if (response_received_) {
        co_return true;
    }

    // 读取响应头长度 (2 + 16 bytes)
    uint8_t len_enc[18];
    if (!co_await ReadFull(len_enc, 18)) {
        co_return false;
    }

    // 派生响应头长度解密密钥
    uint8_t len_key[16], len_iv[12];
    const std::array<std::string_view, 1> resp_len_key_path{
        KDFSalt::AEAD_RESP_HEADER_LEN_KEY
    };
    const std::array<std::string_view, 1> resp_len_iv_path{
        KDFSalt::AEAD_RESP_HEADER_LEN_IV
    };
    KDF(response_key_.data(), 16, resp_len_key_path, len_key, 16);
    KDF(response_iv_.data(), 16, resp_len_iv_path, len_iv, 12);

    // 解密长度
    uint8_t len_dec[2];
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, len_key, len_iv);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, len_enc + 2);

    int out_len;
    EVP_DecryptUpdate(ctx, len_dec, &out_len, len_enc, 2);
    int ret = EVP_DecryptFinal_ex(ctx, len_dec + out_len, &out_len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        co_return false;
    }

    uint16_t header_len = (static_cast<uint16_t>(len_dec[0]) << 8) | len_dec[1];

    if (header_len < 4 || header_len > kVMessResponseHeaderMax) {
        co_return false;
    }

    // 读取响应头
    std::array<uint8_t, kVMessResponseHeaderMax + 16> header_enc{};
    if (!co_await ReadFull(header_enc.data(), static_cast<size_t>(header_len) + 16)) {
        co_return false;
    }

    // 派生响应头解密密钥
    uint8_t header_key[16], header_iv[12];
    const std::array<std::string_view, 1> resp_header_key_path{
        KDFSalt::AEAD_RESP_HEADER_PAYLOAD_KEY
    };
    const std::array<std::string_view, 1> resp_header_iv_path{
        KDFSalt::AEAD_RESP_HEADER_PAYLOAD_IV
    };
    KDF(response_key_.data(), 16, resp_header_key_path, header_key, 16);
    KDF(response_iv_.data(), 16, resp_header_iv_path, header_iv, 12);

    std::array<uint8_t, kVMessResponseHeaderMax> header_dec{};
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, header_key, header_iv);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, header_enc.data() + header_len);

    EVP_DecryptUpdate(ctx, header_dec.data(), &out_len, header_enc.data(), static_cast<int>(header_len));
    ret = EVP_DecryptFinal_ex(ctx, header_dec.data() + out_len, &out_len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        co_return false;
    }

    // 验证 response_header 字节
    if (header_dec[0] != response_header_) {
        co_return false;
    }

    response_received_ = true;
    co_return true;
}

cobalt::task<size_t> VMessClientAsyncStream::AsyncRead(net::mutable_buffer buffer) {
    uint8_t* buf = static_cast<uint8_t*>(buffer.data());
    size_t len = buffer.size();

    // 确保收到响应头
    if (!response_received_) {
        if (!co_await ReadResponseHeader()) {
            ThrowVMessWriteError("VMess client read response header failed");
        }
    }

    // 先消费缓冲区
    if (read_buffer_offset_ < read_buffer_.size()) {
        size_t available = read_buffer_.size() - read_buffer_offset_;
        size_t copy = std::min(len, available);
        std::memcpy(buf, read_buffer_.data() + read_buffer_offset_, copy);
        read_buffer_offset_ += copy;

        // 如果全部消费完，清空缓冲区
        if (read_buffer_offset_ >= read_buffer_.size()) {
            read_buffer_.clear();
            read_buffer_offset_ = 0;
            ReleaseIdleBuffer(read_buffer_, 8 * 1024);
        }

        co_return copy;
    }

    // 检查 EOF
    if (read_eof_) {
        co_return 0;
    }

    // 直接读取到调用者 buffer（零拷贝）
    ssize_t result = co_await ReadChunkInto(buf, len);
    if (result == 0) {
        // VMess EOF marker：合法的协议级关闭
        co_return 0;
    }
    if (result < 0) {
        // 错误（TCP-level close / 解密失败 / 数据损坏）：抛异常让 relay 感知错误
        throw boost::system::system_error(
            boost::asio::error::connection_reset,
            "VMess client stream read error");
    }
    co_return static_cast<size_t>(result);
}

cobalt::task<ssize_t> VMessClientAsyncStream::ReadChunkInto(uint8_t* buf, size_t max_len) {
    // 1. 读取长度 (2 bytes)
    uint8_t len_buf[2];
    if (!co_await ReadFull(len_buf, 2)) {
        LOG_ACCESS_DEBUG("VMess client: ReadChunk TCP-level close (failed to read chunk header)");
        read_eof_ = true;
        co_return -1;  // TCP-level close 不是合法 VMess EOF，视为错误
    }

    uint16_t raw_len = (static_cast<uint16_t>(len_buf[0]) << 8) | len_buf[1];

    // 2. 按照 v2ray 的顺序：先获取 padding mask，再获取 size mask
    size_t padding_len = 0;
    if (global_padding_ && read_mask_) {
        uint16_t padding_mask = read_mask_->NextMask();
        padding_len = padding_mask % 64;
    }

    uint16_t chunk_len = raw_len;
    if (read_mask_) {
        uint16_t size_mask = read_mask_->NextMask();
        chunk_len ^= size_mask;
    }

    // 3. 处理 EOF (长度 == overhead 表示空数据)
    size_t overhead = read_cipher_->Overhead();

    if (chunk_len == overhead + padding_len) {
        // 读取并丢弃 EOF 数据（使用固定缓冲区）
        co_await ReadFull(crypto_buf_, chunk_len);
        read_eof_ = true;
        co_return 0;
    }

    if (chunk_len < overhead + padding_len || chunk_len > MAX_CHUNK_SIZE + overhead + 64) {
        LOG_ACCESS_DEBUG("VMess client: ReadChunk INVALID length raw_len={} chunk_len={} "
                         "overhead={} padding={}", raw_len, chunk_len, overhead, padding_len);
        co_return -1;
    }

    // 4. 读取加密数据到固定缓冲区
    if (!co_await ReadFull(crypto_buf_, chunk_len)) {
        LOG_ACCESS_DEBUG("VMess client: ReadChunk ReadFull failed chunk_len={} "
                         "(TCP 连接在 chunk body 传输中断开)", chunk_len);
        co_return -1;
    }

    // 5. 解密（不包含 padding）
    size_t data_len = chunk_len - padding_len;
    size_t decrypted_max = data_len - overhead;

    // 判断是否可以直接解密到调用者 buffer
    uint8_t* decrypt_target;
    if (max_len >= decrypted_max) {
        // 直接解密到调用者 buffer（零拷贝）
        decrypt_target = buf;
    } else {
        // 解密到内部缓冲区，稍后拷贝
        read_buffer_.resize(decrypted_max);
        decrypt_target = read_buffer_.data();
    }

    ssize_t dec_len = read_cipher_->Decrypt(crypto_buf_, data_len, decrypt_target);
    if (dec_len < 0) {
        LOG_ACCESS_DEBUG("VMess client: ReadChunk decrypt FAILED data_len={} security={} "
                         "raw_hex=[{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}...]",
                         data_len, static_cast<int>(security_),
                         data_len > 0 ? crypto_buf_[0] : 0,
                         data_len > 1 ? crypto_buf_[1] : 0,
                         data_len > 2 ? crypto_buf_[2] : 0,
                         data_len > 3 ? crypto_buf_[3] : 0,
                         data_len > 4 ? crypto_buf_[4] : 0,
                         data_len > 5 ? crypto_buf_[5] : 0,
                         data_len > 6 ? crypto_buf_[6] : 0,
                         data_len > 7 ? crypto_buf_[7] : 0);
        co_return -1;
    }

    if (decrypt_target == buf) {
        // 直接解密到调用者 buffer，返回实际长度
        co_return dec_len;
    } else {
        // 从内部缓冲区拷贝
        read_buffer_.resize(dec_len);
        size_t copy = std::min(max_len, static_cast<size_t>(dec_len));
        std::memcpy(buf, read_buffer_.data(), copy);
        read_buffer_offset_ = copy;
        co_return static_cast<ssize_t>(copy);
    }
}

cobalt::task<size_t> VMessClientAsyncStream::AsyncWrite(net::const_buffer buffer) {
    const uint8_t* data = static_cast<const uint8_t*>(buffer.data());
    size_t len = buffer.size();
    size_t total_written = 0;

    while (total_written < len) {
        size_t chunk_size = std::min(len - total_written, size_t(MAX_CHUNK_SIZE - 16));

        if (!co_await WriteChunk(data + total_written, chunk_size)) {
            ThrowVMessWriteError("VMess client write chunk failed");
        }

        total_written += chunk_size;
    }

    co_return total_written;
}

// 批量加密写入：将多个 Buffer 合并为单次 inner_ 写入
cobalt::task<void> VMessClientAsyncStream::WriteMultiBuffer(MultiBuffer mb) {
    MultiBufferGuard guard{mb};

    if (mb.empty()) co_return;

    // 快速路径：单 Buffer 退化为现有 AsyncWrite
    if (mb.size() == 1) {
        auto bytes = mb[0]->Bytes();
        if (!bytes.empty()) {
            size_t written = co_await AsyncWrite(net::const_buffer(bytes.data(), bytes.size()));
            if (written != bytes.size()) {
                ThrowVMessWriteError("VMess client partial single-buffer write");
            }
        }
        co_return;
    }

    // 批量路径
    write_batch_buf_.clear();

    for (auto* buf : mb) {
        auto bytes = buf->Bytes();
        if (bytes.empty()) continue;

        const uint8_t* data = bytes.data();
        size_t len = bytes.size();
        size_t offset = 0;

        while (offset < len) {
            size_t chunk_size = std::min(len - offset, size_t(MAX_CHUNK_SIZE - 16));

            // padding mask（与 WriteChunk 逻辑一致：先 padding，再加密，再 size）
            size_t padding_len = 0;
            if (global_padding_ && write_mask_) {
                uint16_t padding_mask = write_mask_->NextMask();
                padding_len = padding_mask % 64;
            }

            // 加密到 write_output_buf_ + 2（复用固定缓冲区做临时空间）
            ssize_t enc_len = write_cipher_->Encrypt(data + offset, chunk_size, write_output_buf_ + 2);
            if (enc_len < 0) {
                ThrowVMessWriteError("VMess client batch encrypt failed");
            }

            uint16_t total_len = static_cast<uint16_t>(enc_len + padding_len);
            uint16_t masked_len = total_len;
            if (write_mask_) {
                uint16_t size_mask = write_mask_->NextMask();
                masked_len ^= size_mask;
            }

            // 追加到批量缓冲
            size_t output_size = 2 + static_cast<size_t>(enc_len) + padding_len;
            size_t old_size = write_batch_buf_.size();
            write_batch_buf_.resize(old_size + output_size);
            uint8_t* out = write_batch_buf_.data() + old_size;

            out[0] = static_cast<uint8_t>((masked_len >> 8) & 0xFF);
            out[1] = static_cast<uint8_t>(masked_len & 0xFF);
            std::memcpy(out + 2, write_output_buf_ + 2, enc_len);

            if (padding_len > 0) {
                RAND_bytes(out + 2 + enc_len, static_cast<int>(padding_len));
            }

            offset += chunk_size;
        }
    }

    if (!write_batch_buf_.empty()) {
        if (!co_await WriteFull(write_batch_buf_.data(), write_batch_buf_.size())) {
            write_batch_buf_.clear();
            ReleaseIdleBuffer(write_batch_buf_, kWriteBatchKeepCapacity);
            ThrowVMessWriteError("VMess client batch write failed");
        }
        write_batch_buf_.clear();
        ReleaseIdleBuffer(write_batch_buf_, kWriteBatchKeepCapacity);
    }
}

cobalt::task<bool> VMessClientAsyncStream::WriteChunk(const uint8_t* data, size_t len) {
    // 1. 如果启用 padding，先获取 padding 长度的 mask
    size_t padding_len = 0;
    if (global_padding_ && write_mask_) {
        uint16_t padding_mask = write_mask_->NextMask();
        padding_len = padding_mask % 64;
    }

    // 2. 直接加密到固定缓冲区 (跳过 2 字节长度头)
    ssize_t enc_len = write_cipher_->Encrypt(data, len, write_output_buf_ + 2);
    if (enc_len < 0) {
        co_return false;
    }

    // 3. 计算总长度
    uint16_t total_len = static_cast<uint16_t>(enc_len + padding_len);

    // 4. 混淆长度
    uint16_t masked_len = total_len;
    if (write_mask_) {
        uint16_t size_mask = write_mask_->NextMask();
        masked_len ^= size_mask;
    }

    // 5. 组装输出到固定缓冲区: [length][encrypted][padding]
    write_output_buf_[0] = (masked_len >> 8) & 0xFF;
    write_output_buf_[1] = masked_len & 0xFF;

    // 填充随机 padding
    if (padding_len > 0) {
        RAND_bytes(write_output_buf_ + 2 + enc_len, static_cast<int>(padding_len));
    }

    size_t output_size = 2 + enc_len + padding_len;

    // 6. 写入
    co_return co_await WriteFull(write_output_buf_, output_size);
}

cobalt::task<void> VMessClientAsyncStream::AsyncShutdownWrite() {
    if (write_eof_sent_) {
        co_return;
    }

    // 发送 EOF marker chunk: 长度 = overhead + padding
    // 按照 v2ray 的顺序：先获取 padding mask，再获取 size mask
    size_t padding_len = 0;
    if (global_padding_ && write_mask_) {
        uint16_t padding_mask = write_mask_->NextMask();
        padding_len = padding_mask % 64;
    }

    uint16_t length_mask = 0;
    if (write_mask_) {
        length_mask = write_mask_->NextMask();
    }

    // EOF marker: 加密空数据，只有 tag
    // 使用栈分配，最大 2 + 16(tag) + 64(padding) = 82 字节
    alignas(16) uint8_t eof_buf[128];
    ssize_t enc_len = write_cipher_->Encrypt(nullptr, 0, eof_buf + 2);
    if (enc_len < 0) {
        co_return;
    }

    uint16_t total_len = static_cast<uint16_t>(enc_len + padding_len);
    uint16_t masked_len = total_len ^ length_mask;

    // 组装 EOF marker: [masked_len(2)] + [tag(overhead)] + [random padding]
    eof_buf[0] = (masked_len >> 8) & 0xFF;
    eof_buf[1] = masked_len & 0xFF;

    if (padding_len > 0) {
        RAND_bytes(eof_buf + 2 + enc_len, static_cast<int>(padding_len));
    }

    size_t output_size = 2 + enc_len + padding_len;

    // 发送 EOF marker（忽略错误，因为无论如何都要关闭）
    co_await WriteFull(eof_buf, output_size);
    write_eof_sent_ = true;

    co_return;
}

void VMessClientAsyncStream::ShutdownWrite() {
    // 注意：同步版本不发送 VMess EOF marker
    // 因为 EOF marker 需要加密，在同步上下文中可能导致状态问题
    // 应使用 AsyncShutdownWrite() 来正确关闭 VMess 流
    // DoRelay 已修改为使用 AsyncShutdownWrite
    inner_->ShutdownWrite();
}

void VMessClientAsyncStream::Cancel() noexcept {
    inner_->Cancel();
}

cobalt::task<bool> VMessClientAsyncStream::ReadFull(uint8_t* buf, size_t len) {
    co_return co_await acpp::ReadFull(*inner_, buf, len);
}

cobalt::task<bool> VMessClientAsyncStream::WriteFull(const uint8_t* buf, size_t len) {
    co_return co_await acpp::WriteFull(*inner_, buf, len);
}

}  // namespace vmess
}  // namespace acpp

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kVMessRegistered = (acpp::OutboundFactory::Instance().Register(
    "vmess",
    [](const acpp::OutboundConfig& cfg,
       acpp::net::any_io_executor executor,
       acpp::IDnsService* dns,
       acpp::UDPSessionManager* /*udp_mgr*/,
       std::chrono::seconds timeout) -> std::unique_ptr<acpp::IOutbound> {
        const auto& s = cfg.settings;
        using acpp::json::GetString;
        using acpp::json::GetInt;

        // 解析 vnext[0]
        const auto* vnext_p = s.if_contains("vnext");
        if (!vnext_p || !vnext_p->is_array() || vnext_p->as_array().empty()) {
            return nullptr;
        }
        const auto& server = vnext_p->as_array()[0].as_object();

        // 解析 users[0]
        const auto* users_p = server.if_contains("users");
        if (!users_p || !users_p->is_array() || users_p->as_array().empty()) {
            return nullptr;
        }
        const auto& user = users_p->as_array()[0].as_object();

        acpp::VMessOutboundConfig vmess_config;
        vmess_config.tag      = cfg.tag;
        vmess_config.address  = GetString(server, "address");
        vmess_config.port     = static_cast<uint16_t>(GetInt(server, "port", 443));
        vmess_config.uuid     = GetString(user, "id");
        vmess_config.alter_id = static_cast<int>(GetInt(user, "alterId", 0));

        std::string security = GetString(user, "security", "auto");
        if (security == "aes-128-gcm" || security == "auto") {
            vmess_config.security = acpp::vmess::Security::AES_128_GCM;
        } else if (security == "chacha20-poly1305") {
            vmess_config.security = acpp::vmess::Security::CHACHA20_POLY1305;
        } else if (security == "none") {
            vmess_config.security = acpp::vmess::Security::NONE;
        }

        vmess_config.stream_settings = cfg.stream_settings;
        vmess_config.stream_settings.RecomputeModes();
        vmess_config.timeout = timeout;

        if (vmess_config.address.empty() || vmess_config.uuid.empty()) {
            return nullptr;  // 配置不完整
        }

        return acpp::CreateVMessOutbound(executor, vmess_config, dns);
    }), true);
}  // namespace
