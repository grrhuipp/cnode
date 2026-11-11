#include "sniff/sniffer.hpp"

#include "common/allocator.hpp"
#include "common/byte_reader.hpp"
#include "common/domain_name.hpp"
#include "common/ip_utils.hpp"
#include "common/target_address.hpp"
#include "common/unsafe.hpp"
#include "core/constants.hpp"
#include "transport/internet/http_headers.hpp"
#include "transport/internet/tls_server_name.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

namespace sniff {

namespace {

constexpr uint8_t kContentTypeHandshake = 0x16;
constexpr uint8_t kHandshakeClientHello = 0x01;
constexpr uint16_t kExtensionServerName = 0x0000;
constexpr uint16_t kSsl30 = 0x0300;
constexpr uint16_t kTls10 = 0x0301;
constexpr uint16_t kTls13 = 0x0304;
constexpr size_t kTlsRecordHeaderBytes = 5;
constexpr size_t kMaxTlsSniffWireBytes = 4096;
constexpr size_t kMaxTlsSniffHandshakeBytes =
    kMaxTlsSniffWireBytes - kTlsRecordHeaderBytes;

[[nodiscard]] size_t ClientHelloSize(std::span<const uint8_t> handshake) noexcept {
    return 4 + common::LoadU24BE(handshake.data() + 1);
}

[[nodiscard]] bool FitsTlsSniffWireBudget(
    size_t record_headers_bytes,
    size_t committed_payload_bytes,
    std::span<const uint8_t> handshake_prefix) noexcept {
    if (record_headers_bytes > kMaxTlsSniffWireBytes ||
        committed_payload_bytes > kMaxTlsSniffWireBytes - record_headers_bytes) {
        return false;
    }
    if (handshake_prefix.size() >= 4) {
        const size_t hello_size = ClientHelloSize(handshake_prefix);
        const size_t extra_header =
            hello_size > committed_payload_bytes ? kTlsRecordHeaderBytes : 0;
        if (hello_size > kMaxTlsSniffWireBytes - record_headers_bytes ||
            extra_header >
                kMaxTlsSniffWireBytes - record_headers_bytes - hello_size) {
            return false;
        }
        return true;
    }
    if (committed_payload_bytes == handshake_prefix.size()) {
        const size_t min_remaining_hello = 4 - handshake_prefix.size();
        if (kTlsRecordHeaderBytes + min_remaining_hello >
            kMaxTlsSniffWireBytes - record_headers_bytes -
                committed_payload_bytes) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::optional<std::string_view> ExtractServerName(
    std::span<const uint8_t> extensions) {
    std::optional<std::string_view> server_name;
    common::ByteReader reader(extensions);
    while (!reader.Empty()) {
        const uint16_t extension_type = reader.ReadU16BE();
        const auto extension = reader.ReadBytes(reader.ReadU16BE());
        if (!reader.Ok()) return std::nullopt;
        if (extension_type != kExtensionServerName) continue;
        // RFC 8446 §4.2: duplicate extensions of one type are ambiguous.
        if (server_name) return std::nullopt;
        auto parsed =
            transport::internet::ParseTlsServerNameExtension(extension);
        if (!parsed ||
            !domain::IsValidDnsHostname(
                *parsed, domain::TrailingDotPolicy::Forbid) ||
            iputil::ParseLiteral(*parsed)) {
            return std::nullopt;
        }
        server_name = *parsed;
    }
    return server_name;
}

[[nodiscard]] std::optional<std::string_view> ParseClientHelloServerName(
    std::span<const uint8_t> handshake) {
    common::ByteReader reader(handshake);
    if (reader.ReadU8() != kHandshakeClientHello) return std::nullopt;
    const size_t body_size = reader.ReadU24BE();
    common::ByteReader body(reader.ReadBytes(body_size));
    if (!reader.Ok()) return std::nullopt;

    // legacy_version + random, then legacy_session_id.
    (void)body.Skip(2 + 32);
    const uint8_t session_id_size = body.ReadU8();
    if (session_id_size > 32) return std::nullopt;
    (void)body.Skip(session_id_size);
    const uint16_t cipher_suites_size = body.ReadU16BE();
    if (cipher_suites_size < 2 || (cipher_suites_size & 1u) != 0) {
        return std::nullopt;
    }
    (void)body.Skip(cipher_suites_size);
    const uint8_t compression_methods_size = body.ReadU8();
    if (compression_methods_size == 0) return std::nullopt;
    (void)body.Skip(compression_methods_size);
    const auto extensions = body.ReadBytes(body.ReadU16BE());
    if (!body.Ok() || !body.Empty()) return std::nullopt;
    return ExtractServerName(extensions);
}

[[nodiscard]] bool TryFinishClientHelloSniff(
    std::span<const uint8_t> handshake, SniffResult& result) {
    if (handshake.size() < 4) return false;
    const size_t hello_size = ClientHelloSize(handshake);
    if (hello_size > kMaxTlsSniffHandshakeBytes) return true;
    if (handshake.size() < hello_size) return false;
    if (auto server_name =
            ParseClientHelloServerName(handshake.first(hello_size))) {
        result.success = true;
        result.protocol = constants::protocol::kTls;
        result.domain.assign(*server_name);
    }
    return true;
}

[[nodiscard]] bool ReadRecordHeader(
    common::ByteReader& reader,
    bool& version_supports_need_more,
    uint16_t& record_len,
    SniffResult& result) noexcept {
    if (reader.ReadU8() != kContentTypeHandshake) return false;
    if (reader.Empty() ||
        (reader.Remaining() == 1 && reader.ReadU8() == 0x03)) {
        if (version_supports_need_more) {
            result.need_more = true;
            result.protocol = constants::protocol::kTls;
        }
        return false;
    }
    const uint16_t record_version = reader.ReadU16BE();
    if (!reader.Ok()) return false;
    if ((record_version < kTls10 || record_version > kTls13) &&
        record_version != kSsl30) {
        return false;
    }
    version_supports_need_more =
        version_supports_need_more &&
        record_version >= kTls10 && record_version <= kTls13;
    if (reader.Remaining() < 2) {
        if (version_supports_need_more) {
            result.need_more = true;
            result.protocol = constants::protocol::kTls;
        }
        return false;
    }
    record_len = reader.ReadU16BE();
    return record_len != 0;
}

struct HostPortView {
    std::string_view host;
    uint16_t port = 0;
};

static constexpr std::array<std::string_view, 9> kHttpMethods{
    "GET", "POST", "PUT", "DELETE", "HEAD",
    "OPTIONS", "PATCH", "CONNECT", "TRACE"};

[[nodiscard]] bool IsSupportedRequestLine(std::string_view line) noexcept {
    const size_t first_space = line.find(' ');
    if (first_space == std::string_view::npos || first_space == 0) return false;
    const size_t second_space = line.find(' ', first_space + 1);
    if (second_space == std::string_view::npos ||
        second_space == first_space + 1 ||
        line.find(' ', second_space + 1) != std::string_view::npos) {
        return false;
    }

    const std::string_view method = line.substr(0, first_space);
    if (std::ranges::find(kHttpMethods, method) == kHttpMethods.end()) return false;

    const std::string_view target =
        line.substr(first_space + 1, second_space - first_space - 1);
    for (const unsigned char character : target) {
        if (character <= 0x20 || character == 0x7f) return false;
    }

    const std::string_view version = line.substr(second_space + 1);
    return version == "HTTP/1.0" || version == "HTTP/1.1";
}

[[nodiscard]] bool IsValidRequestLinePrefix(std::string_view prefix) noexcept {
    if (prefix.empty()) return false;
    const bool trailing_cr = prefix.back() == '\r';
    if (trailing_cr) prefix.remove_suffix(1);
    if (prefix.empty()) return false;
    for (const unsigned char character : prefix) {
        if (character < 0x20 || character == 0x7f) return false;
    }
    if (trailing_cr) {
        return IsSupportedRequestLine(prefix);
    }

    const size_t first_space = prefix.find(' ');
    if (first_space == std::string_view::npos) {
        return std::ranges::any_of(kHttpMethods, [&](std::string_view method) {
            return method.starts_with(prefix);
        });
    }
    if (first_space == 0) return false;
    const std::string_view method = prefix.substr(0, first_space);
    if (std::ranges::find(kHttpMethods, method) == kHttpMethods.end()) return false;

    const size_t second_space = prefix.find(' ', first_space + 1);
    if (second_space == std::string_view::npos) {
        return true;
    }
    if (second_space == first_space + 1 ||
        prefix.find(' ', second_space + 1) != std::string_view::npos) {
        return false;
    }
    const std::string_view version_prefix = prefix.substr(second_space + 1);
    return std::string_view("HTTP/1.0").starts_with(version_prefix) ||
           std::string_view("HTTP/1.1").starts_with(version_prefix);
}

[[nodiscard]] bool IsValidHeaderLinePrefix(std::string_view prefix) noexcept {
    if (prefix.empty()) return true;
    const bool trailing_cr = prefix.back() == '\r';
    if (trailing_cr) prefix.remove_suffix(1);
    if (prefix.empty()) return true;
    if (prefix.front() == ' ' || prefix.front() == '\t') return false;

    if (prefix.find(':') == std::string_view::npos) {
        if (trailing_cr) return false;
        return transport::internet::IsValidHttpHeaderName(prefix);
    }
    std::string_view name;
    std::string_view value;
    return transport::internet::SplitAndValidateHttpHeaderLine(prefix, name, value);
}

[[nodiscard]] std::optional<HostPortView> ParseHostValue(
    std::string_view value) {
    if (value.empty() || !transport::internet::IsValidHttpAuthority(value)) {
        return std::nullopt;
    }

    HostPortView parsed;
    if (value.front() == '[') {
        const size_t close = value.find(']');
        if (close == std::string_view::npos || close == 1 ||
            value.substr(1, close - 1).find(':') == std::string_view::npos) {
            return std::nullopt;
        }
        parsed.host = value.substr(1, close - 1);
        const auto address = iputil::ParseLiteral(parsed.host);
        if (!address || !address->is_v6()) return std::nullopt;
        const std::string_view suffix = value.substr(close + 1);
        if (!suffix.empty() &&
            (suffix.front() != ':' ||
             !common::TargetAddress::ParsePort(suffix.substr(1), parsed.port))) {
            return std::nullopt;
        }
        return parsed;
    }

    if (value.find('[') != std::string_view::npos ||
        value.find(']') != std::string_view::npos) {
        return std::nullopt;
    }
    const size_t colon = value.find(':');
    if (colon == std::string_view::npos) {
        parsed.host = value;
    } else {
        if (value.rfind(':') != colon || colon == 0 ||
            !common::TargetAddress::ParsePort(value.substr(colon + 1), parsed.port)) {
            return std::nullopt;
        }
        parsed.host = value.substr(0, colon);
    }
    if (!domain::IsValidDnsHostname(
            parsed.host, domain::TrailingDotPolicy::Allow)) {
        return std::nullopt;
    }
    if (parsed.host.ends_with('.') &&
        iputil::ParseLiteral(domain::WithoutTrailingRootDot(parsed.host)).has_value()) {
        return std::nullopt;
    }
    return parsed;
}

struct QuicVersion {
    uint32_t ver = 0;
    uint8_t type_initial = 0;
    std::array<uint8_t, 20> salt{};
    std::string_view hp_label;
    std::string_view key_label;
    std::string_view iv_label;
};

constexpr QuicVersion kDraft29{
    0xff00001d,
    0,
    {0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
     0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99},
    "quic hp",
    "quic key",
    "quic iv",
};
constexpr QuicVersion kV1{
    0x1,
    0,
    {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
     0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
    "quic hp",
    "quic key",
    "quic iv",
};
constexpr QuicVersion kV2{
    0x6b3343cf,
    1,
    {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
     0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
    "quicv2 hp",
    "quicv2 key",
    "quicv2 iv",
};

[[nodiscard]] const QuicVersion* LookupVersion(uint32_t ver) noexcept {
    if (ver == kV1.ver) return &kV1;
    if (ver == kV2.ver) return &kV2;
    if (ver == kDraft29.ver) return &kDraft29;
    return nullptr;
}

bool HkdfExtract(std::span<const uint8_t> salt,
                 std::span<const uint8_t> ikm,
                 std::array<uint8_t, 32>& out) noexcept {
    unsigned int out_len = 0;
    return HMAC(EVP_sha256(), salt.data(), static_cast<int>(salt.size()),
                ikm.data(), ikm.size(), out.data(), &out_len) != nullptr &&
           out_len == out.size();
}

// TLS 1.3 HKDF-Expand-Label with SHA-256 for L <= 32 (single HMAC block T(1)).
bool HkdfExpandLabel(std::span<const uint8_t> secret,
                     std::string_view label,
                     std::span<uint8_t> out) noexcept {
    if (out.empty() || out.size() > 32 || label.size() > 16) {
        return false;
    }
    std::array<uint8_t, 2 + 1 + 6 + 16 + 1 + 1> info_buf{};
    const auto label_size = static_cast<uint8_t>(6 + label.size());
    info_buf[0] = static_cast<uint8_t>((out.size() >> 8) & 0xff);
    info_buf[1] = static_cast<uint8_t>(out.size() & 0xff);
    info_buf[2] = label_size;
    std::memcpy(info_buf.data() + 3, "tls13 ", 6);
    std::memcpy(info_buf.data() + 9, label.data(), label.size());
    const size_t info_len = 3 + static_cast<size_t>(label_size) + 1;
    info_buf[info_len] = 0x01;

    std::array<uint8_t, 32> digest{};
    unsigned int digest_len = 0;
    if (HMAC(EVP_sha256(),
             secret.data(),
             static_cast<int>(secret.size()),
             info_buf.data(),
             info_len + 1,
             digest.data(),
             &digest_len) == nullptr ||
        digest_len != digest.size()) {
        return false;
    }
    std::memcpy(out.data(), digest.data(), out.size());
    return true;
}

EVP_CIPHER_CTX* ThreadLocalQuicCipherCtx() noexcept {
    struct Holder {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        ~Holder() {
            if (ctx) EVP_CIPHER_CTX_free(ctx);
        }
    };
    thread_local Holder holder;
    if (holder.ctx) {
        EVP_CIPHER_CTX_reset(holder.ctx);
    }
    return holder.ctx;
}

bool AesEcbEncrypt(std::span<const uint8_t, 16> key,
                   std::span<const uint8_t, 16> in,
                   std::span<uint8_t, 16> out) noexcept {
    EVP_CIPHER_CTX* ctx = ThreadLocalQuicCipherCtx();
    if (!ctx) return false;
    int out_len = 0;
    return EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr) == 1 &&
           EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
           EVP_EncryptUpdate(ctx, out.data(), &out_len, in.data(), 16) == 1 &&
           out_len == 16;
}

constexpr size_t kMaxCrypto = 64 * 1024;
constexpr size_t kMaxInputs = 64;

// Explicit reservation prevents vector's geometric growth from exceeding the cap.
void Grow(memory::ByteVector& bytes, size_t size) {
    if (size > bytes.capacity()) {
        bytes.reserve(std::bit_ceil(std::max(size, size_t{256})));
    }
    bytes.resize(size);
}

bool AesGcmDecrypt(std::span<const uint8_t, 16> key,
                   std::span<const uint8_t, 12> nonce,
                   uint8_t unmasked_first_byte,
                   std::span<const uint8_t> aad_middle,
                   std::span<const uint8_t> unmasked_pn,
                   std::span<const uint8_t> ciphertext,
                   std::array<uint8_t, 1536>& stack_buf,
                   memory::ByteVector& heap_buf,
                   std::span<const uint8_t>& plaintext) {
    if (ciphertext.size() <= 16) return false; // A QUIC packet must contain a frame.
    const auto tag = ciphertext.subspan(ciphertext.size() - 16, 16);
    const auto body = ciphertext.first(ciphertext.size() - 16);
    uint8_t* out_ptr = nullptr;
    if (ciphertext.size() <= stack_buf.size()) {
        out_ptr = stack_buf.data();
    } else {
        heap_buf.resize(body.size());
        out_ptr = heap_buf.data();
    }

    EVP_CIPHER_CTX* ctx = ThreadLocalQuicCipherCtx();
    if (!ctx) return false;
    int aad_len = 0;
    int out_len = 0;
    int final_len = 0;
    const bool ok =
        EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
        EVP_DecryptUpdate(ctx, nullptr, &aad_len, &unmasked_first_byte, 1) == 1 &&
        EVP_DecryptUpdate(ctx, nullptr, &aad_len, aad_middle.data(),
                          static_cast<int>(aad_middle.size())) == 1 &&
        EVP_DecryptUpdate(ctx, nullptr, &aad_len, unmasked_pn.data(),
                          static_cast<int>(unmasked_pn.size())) == 1 &&
        EVP_DecryptUpdate(ctx, out_ptr, &out_len, body.data(),
                          static_cast<int>(body.size())) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            const_cast<uint8_t*>(tag.data())) == 1 &&
        EVP_DecryptFinal_ex(ctx, out_ptr + out_len, &final_len) == 1;
    if (!ok) {
        heap_buf.clear();
        plaintext = {};
        return false;
    }
    const auto plain_size = static_cast<size_t>(out_len + final_len);
    if (out_ptr != stack_buf.data()) {
        heap_buf.resize(plain_size);
    }
    plaintext = std::span<const uint8_t>(out_ptr, plain_size);
    return true;
}

}  // namespace

SniffResult SniffTls(std::span<const uint8_t> data) {
    SniffResult result;
    common::ByteReader reader(data);
    bool version_supports_need_more = true;
    uint16_t record_len = 0;
    if (!ReadRecordHeader(reader, version_supports_need_more, record_len, result) ||
        !FitsTlsSniffWireBudget(kTlsRecordHeaderBytes, record_len, {})) {
        return result;
    }
    const auto record = reader.ReadBytes(record_len);
    if (!reader.Ok()) {
        const auto partial_first = data.subspan(kTlsRecordHeaderBytes);
        if (version_supports_need_more &&
            (partial_first.empty() ||
             partial_first[0] == kHandshakeClientHello) &&
            FitsTlsSniffWireBudget(
                kTlsRecordHeaderBytes, record_len, partial_first)) {
            result.need_more = true;
            result.protocol = constants::protocol::kTls;
        }
        return result;
    }
    if (record[0] != kHandshakeClientHello) return result;
    if (!FitsTlsSniffWireBudget(kTlsRecordHeaderBytes, record.size(), record)) {
        return result;
    }

    if (TryFinishClientHelloSniff(record, result)) return result;
    if (reader.Empty()) {
        if (version_supports_need_more) {
            result.need_more = true;
            result.protocol = constants::protocol::kTls;
        }
        return result;
    }

    std::array<uint8_t, kMaxTlsSniffHandshakeBytes> reassembled;
    std::copy_n(record.data(), record.size(), reassembled.data());
    size_t reassembled_size = record.size();
    size_t record_headers_bytes = kTlsRecordHeaderBytes;

    while (!reader.Empty()) {
        record_headers_bytes += kTlsRecordHeaderBytes;
        if (record_headers_bytes + reassembled_size >= kMaxTlsSniffWireBytes) {
            return result;
        }
        if (reassembled_size >= 4 &&
            ClientHelloSize(
                std::span<const uint8_t>(reassembled.data(), reassembled_size)) >
                kMaxTlsSniffWireBytes - record_headers_bytes) {
            return result;
        }
        uint16_t next_len = 0;
        if (!ReadRecordHeader(reader, version_supports_need_more, next_len, result) ||
            next_len > kMaxTlsSniffHandshakeBytes - reassembled_size) {
            return result;
        }
        const size_t committed_payload_bytes = reassembled_size + next_len;
        if (reader.Remaining() < next_len) {
            const size_t avail = reader.Remaining();
            const auto partial = reader.ReadBytes(avail);
            std::copy_n(partial.data(), avail, reassembled.data() + reassembled_size);
            reassembled_size += avail;
            if (!FitsTlsSniffWireBudget(
                    record_headers_bytes,
                    committed_payload_bytes,
                    std::span<const uint8_t>(
                        reassembled.data(), reassembled_size))) {
                return result;
            }
            if (version_supports_need_more) {
                result.need_more = true;
                result.protocol = constants::protocol::kTls;
            }
            return result;
        }
        const auto next_record = reader.ReadBytes(next_len);
        std::copy_n(next_record.data(), next_len, reassembled.data() + reassembled_size);
        reassembled_size += next_len;
        const auto reassembled_span =
            std::span<const uint8_t>(reassembled.data(), reassembled_size);
        if (!FitsTlsSniffWireBudget(
                record_headers_bytes, committed_payload_bytes, reassembled_span)) {
            return result;
        }
        if (TryFinishClientHelloSniff(reassembled_span, result)) {
            return result;
        }
    }

    if (version_supports_need_more) {
        result.need_more = true;
        result.protocol = constants::protocol::kTls;
    }
    return result;
}

// Single pass over CRLF-terminated lines: the request line, then header fields
// until the empty line. An unterminated but valid prefix requests more bytes.
SniffResult SniffHttp(std::span<const uint8_t> data) {
    SniffResult result;
    const std::string_view request(
        unsafe::ptr_cast<const char>(data.data()), data.size());
    size_t line_end = request.find("\r\n");
    if (line_end == std::string_view::npos) {
        if (IsValidRequestLinePrefix(request)) {
            result.need_more = true;
            result.protocol = constants::protocol::kHttp;
        }
        return result;
    }
    if (!IsSupportedRequestLine(request.substr(0, line_end))) {
        return result;
    }

    std::optional<HostPortView> host;
    for (size_t position = line_end + 2;; position = line_end + 2) {
        line_end = request.find("\r\n", position);
        if (line_end == std::string_view::npos) {
            if (IsValidHeaderLinePrefix(request.substr(position))) {
                result.need_more = true;
                result.protocol = constants::protocol::kHttp;
            }
            return result;
        }
        const std::string_view line =
            request.substr(position, line_end - position);
        if (line.empty()) {
            if (host) {
                result.success = true;
                result.protocol = constants::protocol::kHttp;
                result.domain.assign(host->host);
                result.port = host->port;
            }
            return result;
        }
        // obs-fold is rejected (RFC 9112 §5.2).
        if (line.front() == ' ' || line.front() == '\t') return result;

        std::string_view name;
        std::string_view value;
        if (!transport::internet::SplitAndValidateHttpHeaderLine(line, name, value)) {
            return result;
        }
        if (!common::EqualsAsciiCI(name, "host")) continue;
        // RFC 9112 §3.2: more than one Host field is a bad request.
        if (host) return result;
        host = ParseHostValue(value);
        if (!host) return result;
    }
}

SniffResult QuicSniffer::Sniff(std::span<const uint8_t> data) {
    auto release_state = [&]() noexcept {
        stopped_ = true;
        crypto_.clear();
        crypto_.shrink_to_fit();
        coverage_.clear();
        coverage_.shrink_to_fit();
    };
    auto fail = [&]() {
        release_state();
        return SniffResult{};
    };
    if (stopped_) return {};
    // As in the read budget, consume one final datagram crossing the threshold.
    // Every individual buffer stays <=64 KiB and total input stays <128 KiB.
    if (data.empty() || input_count_ == kMaxInputs || data.size() > kMaxCrypto ||
        input_bytes_ >= kMaxCrypto) {
        return fail();
    }
    ++input_count_;
    input_bytes_ += data.size();

    // Released on return: no plaintext is held while waiting for the next datagram.
    std::array<uint8_t, 1536> stack_decrypted;
    memory::ByteVector heap_decrypted;
    std::span<const uint8_t> decrypted;
    size_t offset = 0;
    bool decrypted_initial = false;
    bool valid_long_packet = false;
    uint32_t datagram_version = version_;
    std::span<const uint8_t> datagram_dcid(dcid_.data(), dcid_size_);
    while (offset < data.size()) {
        const auto remaining = data.subspan(offset);
        // A coalesced short-header packet or datagram padding has no Initial
        // length to follow. Do not discard CRYPTO already authenticated here.
        if ((remaining[0] & 0xc0) != 0xc0) {
            if (decrypted_initial || valid_long_packet) break;
            return fail();
        }
        if (remaining.size() < 7) return fail();
        common::ByteReader header(remaining);
        (void)header.Skip(1);
        const uint32_t version = header.ReadU32BE();
        const auto* spec = LookupVersion(version);
        if (!spec) return fail();
        const uint8_t packet_type = (remaining[0] >> 4) & 3;
        const bool is_initial = packet_type == spec->type_initial;
        // Retry has no Length field and cannot contribute to this Initial.
        if (packet_type == (version == kV2.ver ? 0 : 3)) {
            if (decrypted_initial || valid_long_packet) break;
            return fail();
        }

        const uint8_t dcid_len = header.ReadU8();
        const auto dcid = header.ReadBytes(dcid_len);
        const uint8_t scid_len = header.ReadU8();
        if (!header.Ok() || dcid_len > dcid_.size() || scid_len > 20 ||
            !header.Skip(scid_len)) {
            return fail();
        }
        if (is_initial) {
            const auto token_len = header.ReadQuicVarint();
            if (!token_len || *token_len > header.Remaining() ||
                !header.Skip(static_cast<size_t>(*token_len))) {
                return fail();
            }
        }
        const auto packet_len_opt = header.ReadQuicVarint();
        if (!packet_len_opt || *packet_len_opt > header.Remaining()) return fail();
        const uint64_t packet_len = *packet_len_opt;
        const size_t hdr_len = header.Position();
        const size_t next_offset = offset + hdr_len + static_cast<size_t>(packet_len);
        // Protected packet numbers and tags require at least this much space
        // for a header-protection sample, even when the payload is opaque.
        if (packet_len < 20) return fail();
        if (datagram_version != 0 &&
            (version != datagram_version || dcid.size() != datagram_dcid.size() ||
             !std::equal(dcid.begin(), dcid.end(), datagram_dcid.begin()))) return fail();
        datagram_version = version;
        datagram_dcid = dcid;
        if (!is_initial) {
            valid_long_packet = true;
            offset = next_offset;
            continue;
        }
        if (version_ == 0) {
            std::array<uint8_t, 32> initial_secret{};
            std::array<uint8_t, 32> client_secret{};
            if (!HkdfExtract(spec->salt, dcid, initial_secret) ||
                !HkdfExpandLabel(initial_secret, "client in", client_secret) ||
                !HkdfExpandLabel(client_secret, spec->hp_label, hp_key_) ||
                !HkdfExpandLabel(client_secret, spec->key_label, key_) ||
                !HkdfExpandLabel(client_secret, spec->iv_label, iv_)) return fail();
        }

        std::array<uint8_t, 16> mask{};
        const std::span<const uint8_t, 16> sample(remaining.data() + hdr_len + 4, 16);
        if (!AesEcbEncrypt(hp_key_, sample, mask)) return fail();
        const uint8_t first = static_cast<uint8_t>(remaining[0] ^ (mask[0] & 0x0f));
        if ((first & 0x0c) != 0) return fail();
        const size_t pn_len = (first & 3) + 1;
        std::array<uint8_t, 4> pn_bytes{};
        uint64_t packet_number = 0;
        for (size_t i = 0; i < pn_len; ++i) {
            pn_bytes[i] = remaining[hdr_len + i] ^ mask[i + 1];
            packet_number = (packet_number << 8) | pn_bytes[i];
        }
        // RFC 9000 Appendix A.3: truncated packet numbers may wrap even in
        // Initial retransmissions; reordered packets use the same number space.
        const uint64_t expected = version_ == 0 ? 0 : largest_pn_ + 1;
        const uint64_t window = uint64_t{1} << (pn_len * 8);
        const uint64_t half_window = window / 2;
        packet_number |= expected & ~(window - 1);
        if (packet_number + half_window <= expected &&
            packet_number < (uint64_t{1} << 62) - window) {
            packet_number += window;
        } else if (packet_number > expected + half_window && packet_number >= window) {
            packet_number -= window;
        }
        auto nonce = iv_;
        for (size_t i = 0; i < 8; ++i)
            nonce[nonce.size() - 1 - i] ^= static_cast<uint8_t>(packet_number >> (8 * i));
        if (!AesGcmDecrypt(key_, nonce, first, remaining.subspan(1, hdr_len - 1),
                std::span<const uint8_t>(pn_bytes.data(), pn_len),
                remaining.subspan(hdr_len + pn_len,
                                  static_cast<size_t>(packet_len) - pn_len),
                stack_decrypted, heap_decrypted, decrypted)) return fail();
        if (version_ == 0) {
            version_ = version;
            dcid_size_ = dcid_len;
            std::copy(dcid.begin(), dcid.end(), dcid_.begin());
        }
        largest_pn_ = std::max(largest_pn_, packet_number);
        decrypted_initial = true;

        common::ByteReader frames(decrypted);
        auto consume = [&](uint64_t& value) {
            const auto parsed = frames.ReadQuicVarint();
            if (!parsed) return false;
            value = *parsed;
            return true;
        };
        while (!frames.Empty()) {
            uint64_t frame_type = 0;
            if (!consume(frame_type)) return fail();
            switch (frame_type) {
                case 0x00: // PADDING
                case 0x01: // PING
                    break;
                case 0x02:
                case 0x03: {
                    uint64_t ignored = 0;
                    uint64_t ranges = 0;
                    if (!consume(ignored) || !consume(ignored) ||
                        !consume(ranges) || !consume(ignored) ||
                        ranges > frames.Remaining() / 2) return fail();
                    for (uint64_t i = 0; i < ranges; ++i)
                        if (!consume(ignored) || !consume(ignored)) return fail();
                    if (frame_type == 0x03 &&
                        (!consume(ignored) || !consume(ignored) || !consume(ignored)))
                        return fail();
                    break;
                }
                case 0x06: {
                    uint64_t start = 0;
                    uint64_t length = 0;
                    if (!consume(start) || !consume(length) ||
                        start > kMaxCrypto || length > kMaxCrypto - start) return fail();
                    const auto chunk = frames.ReadBytes(static_cast<size_t>(length));
                    if (!frames.Ok()) return fail();
                    if (length == 0) break;
                    if (contiguous_ == 0 && crypto_.empty() && start == 0 && chunk.size() >= 4 &&
                        chunk[0] == 1 && 4 + common::LoadU24BE(chunk.data() + 1) <= chunk.size()) {
                        auto sni = ParseClientHelloServerName(
                            chunk.first(4 + common::LoadU24BE(chunk.data() + 1)));
                        if (!sni) return fail();
                        SniffResult result;
                        result.success = true;
                        result.protocol = constants::protocol::kQuic;
                        result.domain.assign(*sni);
                        release_state();
                        return result;
                    }
                    const size_t end = static_cast<size_t>(start + length);
                    if (contiguous_ >= 4 &&
                        end > 4 + static_cast<size_t>(common::LoadU24BE(crypto_.data() + 1))) {
                        return fail();
                    }
                    if (crypto_.size() < end) {
                        Grow(crypto_, end);
                        Grow(coverage_, (end + 7) / 8);
                    }
                    for (size_t i = 0; i < chunk.size(); ++i) {
                        const size_t pos = static_cast<size_t>(start) + i;
                        const uint8_t bit = static_cast<uint8_t>(1u << (pos & 7));
                        const uint8_t byte = chunk[i];
                        if ((coverage_[pos / 8] & bit) != 0) {
                            if (crypto_[pos] != byte) return fail();
                        } else {
                            crypto_[pos] = byte;
                            coverage_[pos / 8] |= bit;
                        }
                    }
                    while (contiguous_ < crypto_.size() &&
                           (coverage_[contiguous_ / 8] & (1u << (contiguous_ & 7))) != 0)
                        ++contiguous_;
                    break;
                }
                // CONNECTION_CLOSE and unsupported Initial frames are terminal.
                default:
                    return fail();
            }
        }

        if (contiguous_ != 0 && crypto_[0] != 1) return fail();
        if (contiguous_ >= 4) {
            const size_t handshake_size = common::LoadU24BE(crypto_.data() + 1);
            if (handshake_size > kMaxCrypto - 4 ||
                crypto_.size() > handshake_size + 4) return fail();
            if (contiguous_ >= handshake_size + 4) {
                auto sni = ParseClientHelloServerName(
                    std::span<const uint8_t>(crypto_).first(handshake_size + 4));
                if (!sni) return fail();
                SniffResult result;
                result.success = true;
                result.protocol = constants::protocol::kQuic;
                result.domain.assign(*sni);
                release_state();
                return result;
            }
        }
        offset = next_offset;
    }
    // A same-connection 0-RTT-only datagram may be reordered between Initial
    // fragments. It contributes no CRYPTO, but does not invalidate prior state.
    if (version_ == 0 || input_count_ == kMaxInputs || input_bytes_ >= kMaxCrypto)
        return fail();
    SniffResult result;
    result.need_more = true;
    result.protocol = constants::protocol::kQuic;
    return result;
}

}  // namespace sniff
