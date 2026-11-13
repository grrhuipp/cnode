#include "proxy/shadowsocks/ss_inbound.hpp"
#include "proxy/shadowsocks/ss_salt_pool.hpp"
#include "proxy/handshake_errors.hpp"
#include "common/scoped_cleanse.hpp"
#include "proxy/inbound_admission.hpp"
#include "transport/async_stream.hpp"
#include "common/address_codec.hpp"
#include "proxy/uot/uot.hpp"
#include "app/relay.hpp"
#include "app/stats.hpp"
#include "routing/dispatcher.hpp"
#include "app/inbound_handler.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "common/multi_buffer.hpp"
#include "common/session.hpp"

#include "common/byte_reader.hpp"
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <algorithm>
#include <optional>
#include <span>
#include <utility>

namespace proxy {


namespace {

bool DecryptIdentityHeader(
    const app::PreparedKeyBytes& identity_key,
    const SsCipherInfo& cipher_info,
    std::span<const uint8_t> salt,
    std::span<const uint8_t, 16> encrypted_identity,
    std::array<uint8_t, 16>& identity_hash) {
    // BuildMasterKey/Decode2022Psk admit only the configured cipher's exact
    // key length; malformed prepared credentials are not identity groups.
    if (identity_key.size != cipher_info.key_size) return false;
    std::array<uint8_t, 32> block_key{};
    const bool ok =
        Derive2022IdentitySubkey(identity_key.data(), cipher_info.key_size,
                                 salt.data(), salt.size(), block_key.data()) &&
        AesBlocksCrypt<16>(
            std::span<const uint8_t>(block_key.data(), cipher_info.key_size),
            encrypted_identity, std::span<uint8_t, 16>(identity_hash), false);
    OPENSSL_cleanse(block_key.data(), block_key.size());
    return ok;
}

bool DecryptSs2022FixedHeader(const app::UserStore::ShadowsocksCredential& user,
                              const SsCipherInfo& cipher_info,
                              std::span<const uint8_t> salt,
                              std::span<const uint8_t> encrypted_fixed,
                              SsAeadCipher& read_cipher,
                              std::array<uint8_t, kSs2022RequestFixedHeaderSize>& fixed_plain) {
    if (user.derived_key.size < cipher_info.key_size) return false;
    std::array<uint8_t, 32> subkey{};
    const bool key_ok = Derive2022Subkey(user.derived_key.data(), cipher_info.key_size,
                                         salt.data(), salt.size(), subkey.data()) &&
                        read_cipher.ResetKey(subkey.data(), cipher_info.key_size);
    OPENSSL_cleanse(subkey.data(), subkey.size());
    if (!key_ok) return false;
    const auto nonce = MakeNonce(0);
    return read_cipher.Decrypt(nonce.data(), encrypted_fixed.data(), encrypted_fixed.size(),
                               fixed_plain.data());
}

struct Ss2022RequestHeader {
    std::array<uint8_t, 16> identity{};
    std::array<uint8_t, kSs2022RequestFixedHeaderSize + SsAeadCipher::kTagSize> encrypted{};
    std::array<uint8_t, kSs2022RequestFixedHeaderSize> plain{};
};

void AuthenticateSs2022Header(
    const app::UserStore::ShadowsocksUsersView& users,
    const SsCipherInfo& cipher_info, ReadTCPSessionResult& result,
    Ss2022RequestHeader& header, SsAeadCipher& read_cipher, size_t& last_matched_index) {
    const bool use_identity = Is2022AesCipher(cipher_info.type) &&
        users[users.size() - 1].identity_key.size >= cipher_info.key_size;
    const size_t hint = last_matched_index;

    auto try_user = [&](size_t index) -> bool {
        const auto& user = users[index];
        if (!DecryptSs2022FixedHeader(
                user,
                cipher_info,
                result.request_salt.span(),
                header.encrypted,
                read_cipher,
                header.plain)) {
            return false;
        }
        result.user = users.Share(user);
        last_matched_index = index;
        return true;
    };

    if (use_identity) {
        std::array<uint8_t, 16> identity_hash{};
        common::ScopedCleanse cleanse_identity{identity_hash};
        const auto& list = *users.users;
        const auto try_candidates = [&](size_t begin, size_t end) {
            // The hash selects candidates, never authenticates a user:
            // collisions still require the fixed header's AEAD tag.
            for (size_t index = users.IdentityHashLowerBound(begin, end, identity_hash);
                 index != end &&
                 CRYPTO_memcmp(users[index].psk_hash.data(), identity_hash.data(),
                               identity_hash.size()) == 0; ++index) {
                if (index != hint && try_user(index)) break;
            }
        };
        size_t hinted_begin = users.size();
        size_t hinted_end = users.size();
        if (hint < list.size()) {
            const auto& key = list[hint].identity_key;
            const bool decoded = DecryptIdentityHeader(
                key, cipher_info, result.request_salt.span(), header.identity, identity_hash);
            if (decoded &&
                CRYPTO_memcmp(list[hint].psk_hash.data(), identity_hash.data(),
                              identity_hash.size()) == 0) {
                try_user(hint);
            }
            if (!result.user) {
                // A hit remains O(1). Only a miss needs to locate the hinted
                // group, whose identity work must not be repeated below.
                hinted_begin = static_cast<size_t>(std::partition_point(
                    list.begin(), list.begin() + hint, [&](const auto& user) {
                        return user.identity_key.size != key.size ||
                            CRYPTO_memcmp(user.identity_key.data(), key.data(), key.size) != 0;
                    }) - list.begin());
                hinted_end = users.IdentityGroupEnd(hint);
                if (decoded) try_candidates(hinted_begin, hinted_end);
            }
        }
        for (size_t group = 0; group != users.size() && !result.user;) {
            if (group == hinted_begin) {
                group = hinted_end;
                continue;
            }
            const size_t end = users.IdentityGroupEnd(group);
            if (DecryptIdentityHeader(users[group].identity_key, cipher_info,
                                      result.request_salt.span(), header.identity, identity_hash)) {
                try_candidates(group, end);
            }
            group = end;
        }
    } else if (hint >= users.size() || !try_user(hint)) {
        for (size_t i = 0; i < users.size(); ++i) {
            if (i != hint && try_user(i)) break;
        }
    }
}

tl::expected<void, common::ErrorCode> ParseInitialRequest(
    ReadTCPSessionResult& result, common::MultiBuffer payload, bool padded) {
    const auto first = payload.FrontSpan();
    auto address = common::DecodeAddress(first, common::AddressWireFormat::Socks5,
        {.require_non_empty_domain = true, .allow_metadata = true});
    if (address.status != common::AddressDecodeStatus::Complete)
        return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    result.target = std::move(address.target);
    result.forwarded = std::move(address.forwarded);
    if (!result.target.IsValid() && !proxy::VersionFromMagicAddress(result.target))
        return tl::unexpected(common::ErrorCode::PROTOCOL_INVALID_ADDRESS);
    size_t offset = address.consumed;
    if (padded) {
        if (first.size() - offset < sizeof(uint16_t))
            return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        const auto padding = common::LoadU16BE(first.data() + offset);
        offset += sizeof(uint16_t);
        if (padding > payload.byte_size() - offset)
            return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        offset += padding;
    }
    payload.DropPrefixBytes(offset);
    payload.ReleaseIfIdle();
    result.initial_payload = common::InitialPayload(std::move(payload));
    return {};
}

net::awaitable<tl::expected<ReadTCPSessionResult, common::ErrorCode>> ReadTCPSession2022(
    transport::AsyncStream& stream,
    const SsCipherInfo& cipher_info,
    std::string_view tag,
    size_t& last_matched_index) {
    try {
    const size_t salt_size = cipher_info.salt_size;
    const size_t key_size = cipher_info.key_size;
    if (salt_size > KeyBytes::kMaxSize || key_size > KeyBytes::kMaxSize) {
        co_return tl::unexpected(common::ErrorCode::INVALID_ARGUMENT);
    }

    const auto users = app::UserStore::ShadowsocksUsers(tag);
    if (users.empty()) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    ReadTCPSessionResult result;
    result.request_salt.size = salt_size;
    if (auto read_res = co_await proxy::ReadHandshakeExact(stream, {result.request_salt.data(), salt_size}, proxy::HandshakeProgress::NotStarted);
        !read_res) {
        co_return tl::unexpected(read_res.error());
    }

    const bool use_identity = Is2022AesCipher(cipher_info.type) &&
        users[users.size() - 1].identity_key.size >= key_size;
    Ss2022RequestHeader header;
    if (use_identity) {
        if (auto read_res = co_await proxy::ReadHandshakeExact(stream, {header.identity.data(), header.identity.size()}, proxy::HandshakeProgress::Started);
            !read_res) {
            co_return tl::unexpected(read_res.error());
        }
    }

    if (auto read_res = co_await proxy::ReadHandshakeExact(stream, {header.encrypted.data(), header.encrypted.size()}, proxy::HandshakeProgress::Started);
        !read_res) {
        co_return tl::unexpected(read_res.error());
    }

    SsAeadCipher read_cipher(cipher_info.type);
    common::ScopedCleanse cleanse_req_fixed{header.plain};
    AuthenticateSs2022Header(users, cipher_info, result, header, read_cipher, last_matched_index);

    if (!result.user) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_AUTH_FAILED);
    }
    if (header.plain[0] != 0 ||
        !TimestampFresh(common::LoadU64BE(header.plain.data() + 1), UnixSecondsNow())) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const uint16_t variable_len = common::LoadU16BE(header.plain.data() + 9);
    if (variable_len == 0) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    common::MultiBuffer variable_mb;
    if (auto decrypt_res = co_await ReadAndDecryptStreamPayload(
            stream, read_cipher, MakeNonce(1), variable_len, variable_mb);
        !decrypt_res) {
        co_return tl::unexpected(
            proxy::ResolveHandshakeReadFailure(stream, decrypt_res.error()));
    }

    if (auto parsed = ParseInitialRequest(result, std::move(variable_mb), true); !parsed)
        co_return tl::unexpected(parsed.error());

    result.body_reader.emplace(
        std::move(read_cipher), 2, stream, kSs2022MaxChunkPayload);
    co_return result;
    } catch (...) {
        co_return tl::unexpected(
            proxy::ClassifyInboundHandshakeException(std::current_exception(), &stream));
    }
}
net::awaitable<tl::expected<ReadTCPSessionResult, common::ErrorCode>> ReadTCPSessionClassic(
    transport::AsyncStream& stream,
    const SsCipherInfo& cipher_info,
    std::string_view tag,
    size_t& last_matched_index) {
    try {
    const size_t salt_size = cipher_info.salt_size;
    const size_t key_size = cipher_info.key_size;
    if (salt_size > KeyBytes::kMaxSize || key_size > KeyBytes::kMaxSize) {
        co_return tl::unexpected(common::ErrorCode::INVALID_ARGUMENT);
    }

    ReadTCPSessionResult result;

    std::array<uint8_t, KeyBytes::kMaxSize> salt{};
    common::ScopedCleanse cleanse_legacy_salt{salt};
    if (auto read_res = co_await proxy::ReadHandshakeExact(stream, {salt.data(), salt_size}, proxy::HandshakeProgress::NotStarted);
        !read_res) {
        co_return tl::unexpected(read_res.error());
    }
    std::array<uint8_t, 2 + SsAeadCipher::kTagSize> enc_len{};
    if (auto read_res = co_await proxy::ReadHandshakeExact(stream, {enc_len.data(), enc_len.size()}, proxy::HandshakeProgress::Started);
        !read_res) {
        co_return tl::unexpected(read_res.error());
    }

    const auto users = app::UserStore::ShadowsocksUsers(tag);
    if (users.empty()) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    uint8_t len_plain[2]{};
    SsAeadCipher read_cipher(cipher_info.type);

    auto try_user = [&](const app::UserStore::ShadowsocksCredential& user) -> bool {
        std::array<uint8_t, 32> read_subkey{};
        if (!DeriveSsSubkey(user.derived_key.data(), key_size,
                          salt.data(), salt_size,
                          read_subkey.data())) {
            return false;
        }
        const bool key_ok = read_cipher.ResetKey(read_subkey.data(), key_size);
        OPENSSL_cleanse(read_subkey.data(), read_subkey.size());
        if (!key_ok) return false;
        auto nonce0 = MakeNonce(0);
        return read_cipher.Decrypt(nonce0.data(), enc_len.data(), enc_len.size(), len_plain);
    };

    const size_t hint = last_matched_index;
    if (hint < users.size() && try_user(users[hint])) {
        result.user = users.Share(users[hint]);
    } else {
        for (size_t i = 0; i < users.size(); ++i) {
            if (i == hint) continue;
            if (try_user(users[i])) {
                result.user = users.Share(users[i]);
                last_matched_index = i;
                break;
            }
        }
    }

    if (!result.user) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    uint64_t read_nonce = 1;  // nonce=0 was used for the length header.

    const uint16_t payload_len = common::LoadU16BE(len_plain);
    if (payload_len == 0 || payload_len > kMaxChunkPayload) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    common::MultiBuffer payload_mb;
    if (auto decrypt_res = co_await ReadAndDecryptStreamPayload(
            stream, read_cipher, MakeNonce(read_nonce), payload_len, payload_mb);
        !decrypt_res) {
        co_return tl::unexpected(
            proxy::ResolveHandshakeReadFailure(stream, decrypt_res.error()));
    }
    ++read_nonce;

    if (auto parsed = ParseInitialRequest(result, std::move(payload_mb), false); !parsed)
        co_return tl::unexpected(parsed.error());

    result.body_reader.emplace(
        std::move(read_cipher), read_nonce, stream);
    co_return result;
    } catch (...) {
        co_return tl::unexpected(
            proxy::ClassifyInboundHandshakeException(std::current_exception(), &stream));
    }
}

}  // namespace

net::awaitable<tl::expected<ReadTCPSessionResult, common::ErrorCode>> ReadTCPSession(
    transport::AsyncStream& stream,
    const SsCipherInfo& cipher_info,
    std::string_view tag,
    size_t& last_matched_index) {
    if (Is2022Cipher(cipher_info.type)) {
        return ReadTCPSession2022(stream, cipher_info, tag, last_matched_index);
    }
    return ReadTCPSessionClassic(stream, cipher_info, tag, last_matched_index);
}
tl::expected<SsStreamWriter, common::ErrorCode> WriteTCPResponse(
    const app::UserStore::ShadowsocksCredential& user,
    const SsCipherInfo& cipher_info,
    const KeyBytes& request_salt,
    transport::AsyncStream& stream) {
    try {
        return SsStreamWriter(user, cipher_info, request_salt, stream);
    } catch (...) {
        return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
    }
}

namespace {

struct PreparedSsTcpSession {
    proxy::BodyReader request_reader;
    proxy::SsStreamWriter response_writer;
    common::InitialPayload initial_payload;
    common::UserOnlineSessionGuard user_session;
    std::optional<proxy::UotVersion> uot_version;
};

net::awaitable<tl::expected<PreparedSsTcpSession, common::ErrorCode>>
PrepareSsTcpSession(
    transport::AsyncStream& stream,
    const proxy::SsCipherInfo& cipher_info,
    size_t& last_matched_index,
    const app::AdmissionEnvironment& environment,
    common::Context& ctx) {
    auto auth_phase = co_await proxy::BeginInboundAuthentication(environment, ctx);
    if (!auth_phase) {
        co_return tl::unexpected(auth_phase.error());
    }
    auto authentication = std::move(*auth_phase);
    const std::string_view tag = ctx.inbound.tag;
    const auto& client_ip = ctx.inbound.source_ip;
    auto session_result = co_await proxy::ReadTCPSession(
        stream,
        cipher_info,
        tag,
        last_matched_index);
    if (!session_result) {
        const common::ErrorCode error = session_result.error();
        if (error == common::ErrorCode::PROTOCOL_AUTH_FAILED) {
            (void)co_await authentication.RejectCredential("no matching credential");
        } else if (error == common::ErrorCode::SOCKET_EOF) {
            LOG_CONN_DEBUG(ctx, "TCP peer closed before its handshake");
        } else if (error != common::ErrorCode::CONNECTION_CLOSED &&
                   error != common::ErrorCode::CANCELLED) {
            LOG_CONN_WARN(ctx, "TCP session handshake failed from {}:{} > {}",
                          client_ip, ctx.inbound.source_port, common::ErrorCodeToString(error));
        }
        co_return tl::unexpected(error);
    }

    auto request_reader = std::move(session_result->body_reader);
    const auto* matched = session_result->user.get();
    if (!matched) {
        co_return tl::unexpected(co_await authentication.RejectCredential("no authenticated user"));
    }

    // UoT resolves its UDP destination only after admission; the magic address
    // is admitted as the TCP request target, as before.
    const auto uot_version = proxy::VersionFromMagicAddress(session_result->target);
    auto bound = std::move(authentication).Bind(matched->profile,
        proxy::InboundRequestTarget{
            common::Network::TCP,
            std::move(session_result->target),
            std::move(session_result->forwarded)});
    if (proxy::Is2022Cipher(cipher_info.type)) {
        try {
            const auto salt = co_await proxy::AdmitSs2022RequestSalt(environment.coordinator, session_result->request_salt);
            if (salt != proxy::Ss2022SaltAdmission::Accepted) {
                co_return tl::unexpected(std::move(bound).Reject(
                    salt == proxy::Ss2022SaltAdmission::Replayed ? "request salt replay" : "request salt tracking capacity",
                    salt == proxy::Ss2022SaltAdmission::Replayed ? common::ErrorCode::PERMISSION_DENIED : common::ErrorCode::RESOURCE_EXHAUSTED));
            }
        } catch (...) {
            co_return tl::unexpected(
                proxy::ClassifyInboundHandshakeException(std::current_exception()));
        }
    }
    auto user_session = co_await std::move(bound).Admit();
    if (!user_session) co_return tl::unexpected(user_session.error());

    auto response_writer_result = proxy::WriteTCPResponse(
        *matched, cipher_info, session_result->request_salt, stream);
    if (!request_reader) {
        co_return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
    }
    if (!response_writer_result) {
        co_return tl::unexpected(response_writer_result.error());
    }
    // Both directions now own their cipher/key state, including the lazy
    // response header. Authentication ownership must end before UoT/relay waits.
    session_result->user.reset();

    co_return PreparedSsTcpSession{
        .request_reader = std::move(*request_reader),
        .response_writer = std::move(*response_writer_result),
        .initial_payload = std::move(session_result->initial_payload),
        .user_session = std::move(*user_session),
        .uot_version = uot_version,
    };
}

net::awaitable<app::RelayResult> DispatchSsUotSession(
    proxy::UotVersion uot_version,
    std::unique_ptr<transport::AsyncStream> stream,
    transport::MultiBufferReader& request_reader,
    transport::MultiBufferWriter& response_writer,
    common::MultiBuffer pending,
    routing::Dispatcher& dispatcher,
    const routing::DispatchPolicy& dispatch_policy,
    net::io_context& io_context,
    common::Context& ctx,
    app::StatsShard& stats,
    const infra::TimeoutsConfig& timeouts) {
    tl::expected<proxy::PreparedRequest, common::ErrorCode> prepared =
        tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    try {
        prepared = co_await proxy::ReadUotRequestHeader(
            uot_version, request_reader, std::move(pending));
    } catch (...) {
        auto error = proxy::ClassifyInboundHandshakeException(std::current_exception());
        if (stream && error != common::ErrorCode::RESOURCE_EXHAUSTED)
            error = proxy::ResolveHandshakeReadFailure(*stream, error);
        prepared = tl::unexpected(error);
    }
    if (!prepared) {
        co_return proxy::RejectInbound(stats, stream.get(), prepared.error());
    }
    co_return co_await proxy::DispatchPreparedUotRequest(
        std::move(*prepared),
        std::move(stream),
        request_reader,
        response_writer,
        dispatcher,
        dispatch_policy,
        io_context,
        ctx,
        stats,
        timeouts);
}

}  // namespace

// ============================================================================
// proxy/shadowsocks/inbound.Handler
// ============================================================================

proxy::SsInboundHandler::SsInboundHandler(
    const app::AdmissionEnvironment& environment,
    proxy::SsCipherInfo cipher_info)
    : environment_(environment)
    , cipher_info_(cipher_info) {}

// ----------------------------------------------------------------------------
// Process
// 流程：
//   1. 读取 salt（salt_size 字节）
//   2. 遍历所有用户，尝试派生子密钥并解密首 chunk 长度字段
//   3. 找到匹配用户后解密首 chunk payload
//   4. 解析 SOCKS5 目标地址
//   5. 将剩余数据作为 initial_payload
//   6. 调用 dispatcher 进入出站处理
//
// 握手超时由底层 TcpStream 空闲超时保护（proxyman inbound 已在 Process
// 前设置 handshake 超时），无需额外守卫。
// ----------------------------------------------------------------------------
net::awaitable<app::RelayResult>
proxy::SsInboundHandler::Process(
    std::unique_ptr<transport::AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const app::ReceiverSettings& receiver,
    net::io_context& io_context,
    common::Context& ctx,
    const infra::TimeoutsConfig& timeouts,
    uint32_t /*pressure_idle_timeout*/) {


    const std::string_view client_ip = ctx.inbound.source_ip;

    LOG_CONN_DEBUG(ctx, "processing connection from {}:{}", client_ip, ctx.inbound.source_port);

    auto prepared = co_await PrepareSsTcpSession(
        *stream,
        cipher_info_,
        last_matched_index_,
        environment_,
        ctx);
    if (!prepared) {
        co_return proxy::RejectInbound(environment_.stats, stream.get(), prepared.error());
    }

    if (prepared->uot_version) {
        co_return co_await DispatchSsUotSession(
            *prepared->uot_version,
            std::move(stream),
            prepared->request_reader,
            prepared->response_writer,
            std::move(prepared->initial_payload).MoveToMultiBuffer(),
            dispatcher,
            receiver.dispatch_policy,
            io_context,
            ctx,
            environment_.stats,
            timeouts);
    }

    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver.dispatch_policy,
        std::move(stream),
        transport::Link{&prepared->request_reader, &prepared->response_writer},
        std::move(prepared->initial_payload),
        ctx,
        environment_.stats,
        timeouts);
}

tl::expected<::proxy::InboundDatagramResult, ::common::ErrorCode>
proxy::SsInboundHandler::Process(
    const proxy::InboundDatagramRequest& request) {
    const auto tag = request.tag;

    auto users = app::UserStore::ShadowsocksUsers(tag);
    if (users.empty()) {
        return tl::unexpected(common::ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    auto decoded = proxy::DecodeUdpPacket(
        request.payload.data(), request.payload.size(), users,
        cipher_info_.type, cipher_info_.key_size, cipher_info_.salt_size,
        udp_replay_cache_, request.associations != nullptr);
    if (!decoded) {
        // UDP datagrams use the socket peer address, never a PROXY protocol source.
        return tl::unexpected(common::ErrorCode::PROTOCOL_AUTH_FAILED);
    }
    const auto& user = users[decoded->user_index];

    proxy::InboundDatagramResult result;
    if (!result.session_owner.Assign(user.derived_key.span())) {
        return tl::unexpected(common::ErrorCode::INTERNAL);
    }
    result.target = std::move(decoded->target);
    result.payload = std::move(decoded->payload);
    result.forwarded = std::move(decoded->forwarded);
    result.session_id = decoded->session_id;
    result.packet_id = decoded->packet_id;
    if (request.associations && decoded->session_id && decoded->packet_id) {
        result.association_policy = &proxy::Ss2022UdpAssociation::Policy();
        const auto found = request.associations->find(proxy::InboundDatagramAssociationKey{
            result.session_owner, *decoded->session_id, request.configuration});
        if (found != request.associations->end() && found->second) {
            auto* association = found->second;
            if (&association->Policy() != result.association_policy)
                return tl::unexpected(common::ErrorCode::PROTOCOL_AUTH_FAILED);
            if (!association->claimed) {
                auto& state = static_cast<proxy::Ss2022UdpAssociation&>(*association);
                if (!state.proxy::Ss2022UdpAssociation::Check(*decoded->packet_id, request.worker_id,
                        request.client_endpoint, proxy::InboundDatagramCheck::Commit))
                    return tl::unexpected(common::ErrorCode::PROTOCOL_AUTH_FAILED);
                result.committed_association = association;
            }
        }
    }
    result.user = &user.profile;
    return result;
}

tl::expected<std::shared_ptr<proxy::InboundDatagramResponse>, common::ErrorCode>
proxy::SsInboundHandler::CreateDatagramResponse(
    const proxy::InboundDatagramResult& decoded) {
    proxy::KeyBytes key;
    if (!key.assign(std::span(decoded.session_owner.bytes).first(decoded.session_owner.size))) {
        return tl::unexpected(common::ErrorCode::INTERNAL);
    }
    if (!proxy::Is2022Cipher(cipher_info_.type)) {
        return std::make_shared<proxy::UdpResponse>(key, cipher_info_);
    }
    if (!decoded.session_id) return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    proxy::Ss2022UdpTxState state;
    state.cipher_info = cipher_info_;
    state.key = key;
    common::StoreU64BE(state.client_session_id.data(), *decoded.session_id);
    if (RAND_bytes(state.server_session_id.data(), state.server_session_id.size()) != 1) {
        return tl::unexpected(common::ErrorCode::INTERNAL);
    }
    return std::make_shared<proxy::UdpResponse>(std::move(state));
}



// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
[[nodiscard]] const ::app::ShadowsocksInboundSettings* GetSettings(
    const ::app::BuildRequest& req) noexcept {
    return req.settings ? std::get_if<::app::ShadowsocksInboundSettings>(req.settings.get()) : nullptr;
}

const bool kSsInboundRegistered = [] {
    ::app::ProxyRegistration reg;
    reg.user_protocol = ::app::UserProtocol::Shadowsocks;
    reg.datagram_transport =
        ::app::DatagramTransport::Packet;


    const auto create_handler =
        [](const ::app::AdmissionEnvironment& environment,
           const ::app::BuildRequest& req) -> std::unique_ptr<::proxy::Inbound> {
            const auto* settings = GetSettings(req);
            if (!settings) {
                return nullptr;
            }
            return std::make_unique<::proxy::SsInboundHandler>(
                environment,
                settings->cipher);
        };
    reg.create_tcp_handler = create_handler;
    reg.create_datagram_handler = create_handler;

    reg.prepare_settings =
        [](std::string_view tag, const ::infra::InboundProtocolSettings& config)
            -> std::optional<std::shared_ptr<
                const ::app::PreparedInboundSettings>> {
            const std::string_view method = config.method.empty()
                ? ::common::kAes256Gcm
                : std::string_view(config.method);
            auto cipher = ::proxy::ParseCipherMethod(method);
            if (!cipher) {
                LOG_WARN("Inbound '{}': unknown SS cipher '{}'", tag, method);
                return std::nullopt;
            }
            ::app::ShadowsocksInboundSettings settings;
            settings.cipher = *cipher;
            settings.uuid_derived_user_key =
                config.ss2022_user_key == ::infra::Ss2022UserKey::UuidDerived;
            if (::proxy::Is2022AesCipher(cipher->type)) {
                if (!config.identity_password.empty()) {
                    settings.identity_key =
                        ::proxy::BuildMasterKey(config.identity_password, *cipher);
                    if (settings.identity_key.empty()) {
                        LOG_WARN("Inbound '{}': invalid SS2022 identity password", tag);
                        return std::nullopt;
                    }
                } else if (settings.uuid_derived_user_key) {
                    LOG_WARN("Inbound '{}': SS2022 UUID users require server identity key", tag);
                    return std::nullopt;
                }
            }
            return std::make_shared<const ::app::PreparedInboundSettings>(std::move(settings));
        };

    reg.build_users =
        [](const ::app::BuildRequest& req,
           std::span<const ::infra::InboundUserSpec> specs)
            -> std::optional<::app::UserSet> {
            const auto* settings = GetSettings(req);
            if (!settings) {
                LOG_WARN("Inbound '{}': missing prepared SS settings", req.tag);
                return std::nullopt;
            }
            const auto& cipher_info = settings->cipher;
            const bool uuid_derived =
                ::proxy::Is2022Cipher(cipher_info.type) &&
                settings->uuid_derived_user_key;

            std::vector<::app::PreparedShadowsocksUser> users;
            users.reserve(specs.size());
            for (const auto& spec : specs) {
                if (spec.credential.empty()) {
                    LOG_WARN("Inbound '{}': SS password is empty", req.tag);
                    return std::nullopt;
                }
                ::app::PreparedShadowsocksUser info;
                info.profile = ::proxy::MakeUserProfile(spec);
                info.derived_key = uuid_derived
                    ? ::proxy::Build2022UserKeyFromUuid(spec.credential, cipher_info)
                    : ::proxy::BuildMasterKey(spec.credential, cipher_info);
                info.identity_key = settings->identity_key;
                if (info.derived_key.empty()) {
                    LOG_WARN("Inbound '{}': invalid SS password for user '{}'",
                             req.tag, spec.email);
                    return std::nullopt;
                }
                if (!info.identity_key.empty() &&
                    !::proxy::Hash2022Psk(info.derived_key.span(), info.psk_hash)) {
                    return std::nullopt;
                }
                users.push_back(std::move(info));
            }

            return ::app::UserSet{std::move(users)};
        };

    ::app::RegisterProxy(
        ::common::kShadowsocks, std::move(reg));
    return true;
}();
}  // namespace
}  // namespace proxy
