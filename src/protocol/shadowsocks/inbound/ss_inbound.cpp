#include "acppnode/protocol/shadowsocks/inbound/ss_inbound.hpp"
#include "acppnode/protocol/shadowsocks/ss_udp_inbound.hpp"
#include "acppnode/protocol/inbound_registry.hpp"
#include "acppnode/transport/stream_helpers.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/session_context.hpp"
#include "acppnode/panel/v2board_panel.hpp"

#include "acppnode/common/buffer_util.hpp"
#include <openssl/rand.h>
#include <cstring>

namespace acpp {

namespace {

constexpr size_t kWriteBatchKeepCapacity = 128 * 1024;

}  // namespace

// ============================================================================
// SsInboundHandler
// ============================================================================

SsInboundHandler::SsInboundHandler(ss::SsUserManager& user_manager,
                                   StatsShard& stats,
                                   ConnectionLimiterPtr limiter,
                                   std::string cipher_method)
    : InboundHandlerBase(stats, std::move(limiter))
    , user_manager_(user_manager)
    , cipher_method_(std::move(cipher_method)) {

    auto info = ss::ParseCipherMethod(cipher_method_);
    if (info) {
        cipher_info_ = *info;
    } else {
        // 默认 aes-256-gcm
        LOG_WARN("[SS] Unknown cipher method '{}', falling back to aes-256-gcm", cipher_method_);
        cipher_info_ = ss::SsCipherInfo{ss::SsCipherType::AES_256_GCM, 32, 32};
    }
}

// ----------------------------------------------------------------------------
// ParseStream
// 流程：
//   1. 读取 salt（salt_size 字节）
//   2. 遍历所有用户，尝试派生子密钥并解密首 chunk 长度字段
//   3. 找到匹配用户后解密首 chunk payload
//   4. 解析 SOCKS5 目标地址
//   5. 将剩余数据作为 initial_payload
//   6. 将读子密钥状态存入 ctx.protocol_data 供 WrapStream 使用
//
// 握手超时由底层 TcpStream 空闲超时保护（SessionHandler 已在 ParseStream
// 前设置 handshake 超时），无需额外守卫。
// ----------------------------------------------------------------------------
cobalt::task<std::expected<ParsedAction, ErrorCode>> SsInboundHandler::ParseStream(
    AsyncStream& stream, SessionContext& ctx) {

    const std::string& tag       = ctx.inbound_tag;
    const std::string& client_ip = ctx.client_ip;

    LOG_CONN_DEBUG(ctx, "[SS][{}] ParseStream start from {}", tag, client_ip);

    if (RejectBanned(ctx)) co_return std::unexpected(ErrorCode::BLOCKED);

    const size_t salt_size = cipher_info_.salt_size;
    const size_t key_size  = cipher_info_.key_size;
    if (salt_size > 64 || key_size > 64) {
        LOG_CONN_FAIL_CTX(ctx, "[SS][{}] unsupported salt/key size: {}/{}",
                          tag, salt_size, key_size);
        co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    // ── 1. 读取 salt ─────────────────────────────────────────────────────────
    // 超时由底层 TcpStream 空闲超时保护
    std::array<uint8_t, 64> salt{};
    bool ok = co_await ReadFull(stream, salt.data(), salt_size);

    if (!ok) {
        LOG_CONN_FAIL_CTX(ctx, "[SS][{}] handshake read failed (salt) from {}", tag, client_ip);
        co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
    }

    // ── 2. 读首 chunk 长度密文（2 + 16 = 18 字节）──────────────────────────
    std::array<uint8_t, 2 + ss::SsAeadCipher::kTagSize> enc_len{};
    ok = co_await ReadFull(stream, enc_len.data(), enc_len.size());

    if (!ok) {
        LOG_CONN_FAIL_CTX(ctx, "[SS][{}] handshake read failed (enc_len) from {}", tag, client_ip);
        co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
    }

    // ── 3. 遍历用户，尝试匹配 ───────────────────────────────────────────────
    // 优化：先尝试上次匹配成功的用户（同一节点活跃用户高度集中）
    auto snapshot = user_manager_.GetSnapshot();
    auto users = snapshot->GetTagUserList(tag);
    if (!users || users->empty()) {
        LOG_CONN_FAIL("[{}] SS auth failed from {} (no users configured)", tag, client_ip);
        OnAuthFail(tag, client_ip);
        co_return std::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    const ss::SsUserInfo* matched = nullptr;
    std::array<uint8_t, 64> subkey_buf{};
    uint8_t len_plain[2];

    auto try_user = [&](const ss::SsUserInfo& user) -> bool {
        if (!ss::DeriveSubkey(user.derived_key.data(), key_size,
                              salt.data(), salt_size,
                              subkey_buf.data())) {
            return false;
        }
        ss::SsAeadCipher try_cipher(cipher_info_.type, subkey_buf.data(), key_size);
        auto nonce0 = ss::MakeNonce(0);
        return try_cipher.Decrypt(nonce0.data(), enc_len.data(), enc_len.size(), len_plain);
    };

    // 优先尝试上次匹配成功的用户
    const size_t hint = last_matched_index_.load(std::memory_order_relaxed);
    if (hint < users->size() && try_user(*(*users)[hint])) {
        matched = (*users)[hint];
    } else {
        // 全量遍历（跳过已尝试的 hint）
        for (size_t i = 0; i < users->size(); ++i) {
            if (i == hint) continue;
            if (try_user(*(*users)[i])) {
                matched = (*users)[i];
                last_matched_index_.store(i, std::memory_order_relaxed);
                break;
            }
        }
    }

    if (!matched) {
        LOG_CONN_FAIL("[{}] SS auth failed from {} (no matching user)", tag, client_ip);
        OnAuthFail(tag, client_ip);
        co_return std::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    // 用 matched 用户的子密钥建立正式 cipher
    if (!ss::DeriveSubkey(matched->derived_key.data(), key_size,
                          salt.data(), salt_size,
                          subkey_buf.data())) {
        co_return std::unexpected(ErrorCode::INTERNAL);
    }

    ss::SsAeadCipher read_cipher(cipher_info_.type, subkey_buf.data(), key_size);
    uint64_t read_nonce = 1;  // 已用 nonce=0 解密长度字段

    // ── 4. 读首 chunk payload ────────────────────────────────────────────────
    const uint16_t payload_len =
        static_cast<uint16_t>((len_plain[0] << 8) | len_plain[1]);

    if (payload_len == 0 || payload_len > ss::kMaxChunkPayload) {
        LOG_CONN_FAIL("[{}] SS invalid payload length {} from {}", tag, payload_len, client_ip);
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    std::vector<uint8_t> payload_buf(payload_len + ss::SsAeadCipher::kTagSize);
    ok = co_await ReadFull(stream, payload_buf.data(), payload_buf.size());

    if (!ok) {
        LOG_CONN_FAIL_CTX(ctx, "[SS][{}] handshake read failed (payload) from {}", tag, client_ip);
        co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
    }

    {
        auto nonce1 = ss::MakeNonce(read_nonce);
        if (!read_cipher.Decrypt(nonce1.data(), payload_buf.data(), payload_buf.size(),
                                 payload_buf.data())) {
            LOG_CONN_FAIL("[{}] SS payload decrypt failed from {}", tag, client_ip);
            co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        ++read_nonce;
    }

    // ── 5. 解析 SOCKS5 地址 ──────────────────────────────────────────────────
    auto addr_result = ss::ParseSocks5Address(payload_buf.data(), payload_len);
    if (!addr_result) {
        LOG_CONN_FAIL("[{}] SS SOCKS5 address parse failed from {}", tag, client_ip);
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    // ── 6. 填充上下文 ─────────────────────────────────────────────────────────
    FillUserInfo(ctx, matched->user_id, matched->email, matched->speed_limit);

    // 在线追踪：认证成功时注册，ctx 析构时自动解注册
    int64_t uid = matched->user_id;
    user_manager_.OnUserConnected(tag, uid);
    ctx.on_disconnect = [mgr = &user_manager_, t = tag, uid] {
        mgr->OnUserDisconnected(t, uid);
    };

    LOG_CONN_DEBUG(ctx, "[SS][{}] auth ok: {} -> {} user={}",
                   tag, client_ip, addr_result->target.ToString(), ctx.user_email);

    // ── 7. 存储 crypto 状态供 WrapStream 使用 ──────────────────────────────
    auto pd = std::make_unique<ss::SsProtocolData>();
    pd->cipher_type  = cipher_info_.type;
    pd->key_size     = key_size;
    pd->salt_size    = salt_size;
    pd->master_key   = matched->derived_key;
    pd->read_subkey.assign(subkey_buf.begin(), subkey_buf.begin() + static_cast<ptrdiff_t>(key_size));
    pd->read_nonce   = read_nonce;
    ctx.protocol_data = std::move(pd);

    // ── 8. 构建 ParsedAction ─────────────────────────────────────────────────
    ParsedAction action;
    action.target           = addr_result->target;
    action.network          = Network::TCP;
    action.payload_decrypted = true;

    // 地址后的剩余字节 = initial_payload
    const size_t addr_consumed = addr_result->consumed;
    if (addr_consumed < payload_len) {
        action.initial_payload.assign(payload_buf.begin() + static_cast<ptrdiff_t>(addr_consumed),
                                      payload_buf.begin() + static_cast<ptrdiff_t>(payload_len));
    }

    co_return action;
}

// ----------------------------------------------------------------------------
// WrapStream — 用 SsProtocolData 创建 SsServerAsyncStream
// ----------------------------------------------------------------------------
cobalt::task<InboundWrapResult> SsInboundHandler::WrapStream(
    std::unique_ptr<AsyncStream> stream, SessionContext& ctx) {

    auto* pd = dynamic_cast<ss::SsProtocolData*>(ctx.protocol_data.get());
    if (!pd) {
        co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    co_return InboundWrapResult(std::make_unique<SsServerAsyncStream>(
        std::move(stream),
        pd->cipher_type,
        pd->key_size,
        pd->salt_size,
        pd->master_key,
        pd->read_subkey,
        pd->read_nonce));
}

std::unique_ptr<IInboundHandler> CreateSsInboundHandler(
    ss::SsUserManager& user_manager,
    StatsShard& stats,
    ConnectionLimiterPtr limiter,
    std::string cipher_method) {
    return std::make_unique<SsInboundHandler>(
        user_manager, stats, std::move(limiter), std::move(cipher_method));
}

// ============================================================================
// SsServerAsyncStream
// ============================================================================

SsServerAsyncStream::SsServerAsyncStream(
    std::unique_ptr<AsyncStream> inner,
    ss::SsCipherType cipher_type,
    size_t key_size,
    size_t salt_size,
    std::vector<uint8_t> master_key,
    std::vector<uint8_t> read_subkey,
    uint64_t read_nonce)
    : DelegatingAsyncStream(std::move(inner))
    , read_cipher_(cipher_type, read_subkey.data(), key_size)
    , read_nonce_(read_nonce)
    , cipher_type_(cipher_type)
    , key_size_(key_size)
    , salt_size_(salt_size)
    , master_key_(std::move(master_key)) {
}

// ── 内部辅助 ─────────────────────────────────────────────────────────────────

cobalt::task<bool> SsServerAsyncStream::ReadFull(uint8_t* buf, size_t len) {
    co_return co_await acpp::ReadFull(*inner_, buf, len);
}

cobalt::task<bool> SsServerAsyncStream::WriteFull(const uint8_t* buf, size_t len) {
    co_return co_await acpp::WriteFull(*inner_, buf, len);
}

cobalt::task<bool> SsServerAsyncStream::ReadNextChunk() {
    // 读 [enc_len(2) + tag(16)]
    uint8_t enc_len_buf[2 + ss::SsAeadCipher::kTagSize];
    if (!co_await ReadFull(enc_len_buf, sizeof(enc_len_buf))) co_return false;

    uint8_t len_plain[2];
    auto nonce = ss::MakeNonce(read_nonce_);
    if (!read_cipher_.Decrypt(nonce.data(), enc_len_buf, sizeof(enc_len_buf), len_plain)) {
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
    if (!read_cipher_.Decrypt(nonce2.data(), read_chunk_buf_.data(),
                              payload_len + ss::SsAeadCipher::kTagSize,
                              read_buf_.data() + old_size)) {
        read_buf_.resize(old_size);
        co_return false;
    }
    ++read_nonce_;

    co_return true;
}

cobalt::task<bool> SsServerAsyncStream::InitWriteCipher() {
    if (salt_size_ > 64 || key_size_ > 64) {
        co_return false;
    }

    // 生成随机 server salt
    std::array<uint8_t, 64> server_salt{};
    if (RAND_bytes(server_salt.data(), static_cast<int>(salt_size_)) != 1) {
        co_return false;
    }

    // 派生写子密钥
    std::array<uint8_t, 64> write_subkey{};
    if (!ss::DeriveSubkey(master_key_.data(), key_size_,
                          server_salt.data(), salt_size_,
                          write_subkey.data())) {
        co_return false;
    }

    write_cipher_ = std::make_unique<ss::SsAeadCipher>(
        cipher_type_, write_subkey.data(), key_size_);
    write_nonce_ = 0;

    // 发送 server salt（客户端用于解密服务端响应）
    if (!co_await WriteFull(server_salt.data(), salt_size_)) {
        co_return false;
    }

    write_init_ = true;
    co_return true;
}

// ── AsyncRead ────────────────────────────────────────────────────────────────
cobalt::task<size_t> SsServerAsyncStream::AsyncRead(net::mutable_buffer buf) {
    // 如果解密缓冲区为空，读一个新 chunk
    if (read_buf_offset_ >= read_buf_.size()) {
        read_buf_.clear();
        read_buf_offset_ = 0;
        if (!co_await ReadNextChunk()) {
            co_return 0;
        }
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

// ── AsyncWrite ───────────────────────────────────────────────────────────────
cobalt::task<size_t> SsServerAsyncStream::AsyncWrite(net::const_buffer buf) {
    if (!write_init_) {
        if (!co_await InitWriteCipher()) co_return 0;
    }

    const uint8_t* data     = static_cast<const uint8_t*>(buf.data());
    size_t         remaining = buf.size();
    size_t         written   = 0;

    while (remaining > 0) {
        const size_t chunk_size = std::min(remaining, ss::kMaxChunkPayload);

        // enc_len → write_chunk_buf_[0..17]
        const uint8_t len_plain[2] = {
            static_cast<uint8_t>(chunk_size >> 8),
            static_cast<uint8_t>(chunk_size & 0xFF)
        };
        auto nonce_l = ss::MakeNonce(write_nonce_);
        if (!write_cipher_->Encrypt(nonce_l.data(), len_plain, 2,
                                    write_chunk_buf_.data())) {
            co_return written;
        }
        ++write_nonce_;

        // enc_payload → write_chunk_buf_[18..]
        auto nonce_p = ss::MakeNonce(write_nonce_);
        if (!write_cipher_->Encrypt(nonce_p.data(), data, chunk_size,
                                    write_chunk_buf_.data() + kLenHeaderSize)) {
            co_return written;
        }
        ++write_nonce_;

        // 单次写入 enc_len + enc_payload
        const size_t total = kLenHeaderSize + chunk_size + ss::SsAeadCipher::kTagSize;
        if (!co_await WriteFull(write_chunk_buf_.data(), total)) {
            co_return written;
        }

        data      += chunk_size;
        remaining -= chunk_size;
        written   += chunk_size;
    }

    co_return written;
}

// ── WriteMultiBuffer — 批量加密写入 ──────────────────────────────────────────
// 默认实现对每个 Buffer 调用 AsyncWrite，每个 chunk 产生 2 次 WriteFull
// （加密长度 + 加密 payload），共 2N 次 syscall。
// 本优化将所有 chunk 数据合并到 write_batch_buf_，单次 WriteFull 完成。
cobalt::task<void> SsServerAsyncStream::WriteMultiBuffer(MultiBuffer mb) {
    MultiBufferGuard guard{mb};

    if (mb.empty()) co_return;

    if (!write_init_) {
        if (!co_await InitWriteCipher()) co_return;
    }

    // 快速路径：单 Buffer 退化为现有 AsyncWrite
    if (mb.size() == 1) {
        auto bytes = mb[0]->Bytes();
        if (!bytes.empty()) {
            co_await AsyncWrite(net::const_buffer(bytes.data(), bytes.size()));
        }
        co_return;
    }

    // 批量路径
    write_batch_buf_.clear();

    for (auto* buf : mb) {
        auto bytes = buf->Bytes();
        if (bytes.empty()) continue;

        const uint8_t* data = bytes.data();
        size_t remaining = bytes.size();

        while (remaining > 0) {
            const size_t chunk_size = std::min(remaining, ss::kMaxChunkPayload);
            const size_t enc_payload_size = chunk_size + ss::SsAeadCipher::kTagSize;
            const size_t output_size = kLenHeaderSize + enc_payload_size;

            // 预分配空间，直接加密到 write_batch_buf_ 尾部
            size_t old_size = write_batch_buf_.size();
            write_batch_buf_.resize(old_size + output_size);
            uint8_t* out = write_batch_buf_.data() + old_size;

            // enc_len → out[0..17]
            const uint8_t len_plain[2] = {
                static_cast<uint8_t>(chunk_size >> 8),
                static_cast<uint8_t>(chunk_size & 0xFF)
            };
            auto nonce_l = ss::MakeNonce(write_nonce_);
            if (!write_cipher_->Encrypt(nonce_l.data(), len_plain, 2, out)) {
                write_batch_buf_.resize(old_size);
                co_return;
            }
            ++write_nonce_;

            // enc_payload → out[18..]
            auto nonce_p = ss::MakeNonce(write_nonce_);
            if (!write_cipher_->Encrypt(nonce_p.data(), data, chunk_size,
                                        out + kLenHeaderSize)) {
                write_batch_buf_.resize(old_size);
                co_return;
            }
            ++write_nonce_;

            data += chunk_size;
            remaining -= chunk_size;
        }
    }

    if (!write_batch_buf_.empty()) {
        co_await WriteFull(write_batch_buf_.data(), write_batch_buf_.size());
        write_batch_buf_.clear();
        ReleaseIdleBuffer(write_batch_buf_, kWriteBatchKeepCapacity);
    }
}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
const bool kSsInboundRegistered = [] {
    acpp::InboundProtocolRegistration reg;

    reg.create_tcp_handler =
        [](const acpp::InboundProtocolDeps& deps,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::InboundBuildRequest& req) -> std::unique_ptr<acpp::IInboundHandler> {
            if (!deps.ss_user_manager || !deps.stats) {
                return nullptr;
            }
            const std::string method = req.cipher_method.empty()
                ? "aes-256-gcm"
                : req.cipher_method;
            return acpp::CreateSsInboundHandler(
                *deps.ss_user_manager,
                *deps.stats,
                std::move(limiter),
                method);
        };

    reg.create_udp_handler =
        [](const acpp::InboundProtocolDeps& deps,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::InboundBuildRequest& req) -> std::unique_ptr<acpp::ss::SsUdpInboundHandler> {
            if (!deps.ss_user_manager) {
                return nullptr;
            }
            const std::string method = req.cipher_method.empty()
                ? "aes-256-gcm"
                : req.cipher_method;
            auto cipher = acpp::ss::ParseCipherMethod(method);
            if (!cipher) {
                return nullptr;
            }
            return acpp::ss::CreateSsUdpInboundHandler(
                *deps.ss_user_manager, *cipher, std::move(limiter));
        };

    reg.load_static_users =
        [](std::string_view tag, const boost::json::object& settings) -> bool {
            std::string method = "aes-256-gcm";
            if (const auto* m = settings.if_contains("method"); m && m->is_string()) {
                method = std::string(m->as_string());
            }

            auto cipher_info = acpp::ss::ParseCipherMethod(method);
            if (!cipher_info) {
                LOG_WARN("Static inbound '{}': unknown SS cipher '{}'", tag, method);
                return false;
            }

            std::vector<acpp::ss::SsUserInfo> users;
            int64_t synthetic_uid = -1;

            if (const auto* clients = settings.if_contains("clients");
                    clients && clients->is_array()) {
                for (const auto& c : clients->as_array()) {
                    if (!c.is_object()) continue;
                    const auto& co = c.as_object();

                    std::string password;
                    if (const auto* p = co.if_contains("password"); p && p->is_string()) {
                        password = std::string(p->as_string());
                    }
                    if (password.empty()) continue;

                    acpp::ss::SsUserInfo info;
                    info.password    = password;
                    info.user_id     = synthetic_uid--;
                    info.cipher_type = cipher_info->type;
                    info.key_size    = cipher_info->key_size;
                    info.salt_size   = cipher_info->salt_size;
                    info.derived_key = acpp::ss::DeriveKey(password, cipher_info->key_size);
                    if (const auto* e = co.if_contains("email"); e && e->is_string()) {
                        info.email = std::string(e->as_string());
                    }
                    users.push_back(std::move(info));
                }
            }

            acpp::ss::SsUserManager::UpdateSharedUsersForTag(std::string(tag), std::move(users));
            return true;
        };

    reg.sync_worker_users =
        [](const acpp::InboundProtocolDeps& deps, std::string_view tag) {
            if (!deps.ss_user_manager) return;
            deps.ss_user_manager->UpdateUsersForTag(std::string(tag), {});
        };

    reg.update_panel_users =
        [](std::string_view tag,
           const acpp::NodeConfig& node_config,
           const std::vector<acpp::PanelUser>& panel_users) {
            const std::string method = node_config.cipher.empty()
                ? "aes-256-gcm"
                : node_config.cipher;

            auto cipher_info = acpp::ss::ParseCipherMethod(method);
            if (!cipher_info) {
                LOG_WARN("UpdateUsers: unknown SS cipher '{}', skip update", method);
                return;
            }

            std::vector<acpp::ss::SsUserInfo> users;
            users.reserve(panel_users.size());

            for (const auto& pu : panel_users) {
                acpp::ss::SsUserInfo info;
                info.password    = pu.uuid;
                info.email       = pu.email;
                info.user_id     = pu.user_id;
                if (pu.speed_limit > 0) {
                    info.speed_limit = static_cast<uint64_t>(pu.speed_limit) * 1024 * 1024 / 8;
                }
                info.cipher_type = cipher_info->type;
                info.key_size    = cipher_info->key_size;
                info.salt_size   = cipher_info->salt_size;
                info.derived_key = acpp::ss::DeriveKey(pu.uuid, cipher_info->key_size);
                users.push_back(std::move(info));
            }

            acpp::ss::SsUserManager::UpdateSharedUsersForTag(std::string(tag), std::move(users));
        };

    reg.clear_users = [](std::string_view tag) {
        acpp::ss::SsUserManager::UpdateSharedUsersForTag(std::string(tag), {});
    };

    acpp::InboundFactory::Instance().Register("shadowsocks", std::move(reg));
    return true;
}();
}  // namespace
