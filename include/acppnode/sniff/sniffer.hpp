#pragma once

#include "acppnode/common/network.hpp"

#include <array>
#include <memory_resource>
#include <vector>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace acpp {

// ============================================================================
// 嗅探结果
// ============================================================================
struct SniffResult {
    bool success = false;           // 是否嗅探成功
    bool need_more = false;         // 已识别协议，但还要更多字节（对齐 xray ErrProtoNeedMoreData）
    std::string_view protocol;      // 协议类型："tls", "http", "quic"（常量视图）
    std::string domain;             // 嗅探到的域名
    uint16_t port = 0;              // 嗅探到的端口（HTTP 可能有）
};

// ============================================================================
// TLS 嗅探（从 ClientHello SNI 扩展中提取域名）
// ============================================================================
class TlsSniffer {
public:
    SniffResult Sniff(std::span<const uint8_t> data);
    // QUIC CRYPTO 里是裸 handshake，没有 TLS record 头。
    std::optional<std::string_view> ParseHandshake(std::span<const uint8_t> data);

private:
    std::optional<std::string_view> ParseClientHello(std::span<const uint8_t> data);
    std::optional<std::string_view> ExtractSNI(std::span<const uint8_t> extensions);
};

class QuicSniffer {
public:
    SniffResult Sniff(std::span<const uint8_t> data);

private:
    // Stage-local, demand-grown storage; holes are tracked independently of bytes.
    std::pmr::vector<uint8_t> crypto_;
    std::pmr::vector<uint8_t> coverage_;
    std::pmr::vector<uint8_t> decrypted_;
    std::array<uint8_t, 20> dcid_{};
    std::array<uint8_t, 16> hp_key_{};
    std::array<uint8_t, 16> key_{};
    std::array<uint8_t, 12> iv_{};
    size_t contiguous_ = 0;
    size_t input_bytes_ = 0;
    size_t input_count_ = 0;
    uint64_t largest_pn_ = 0;
    uint32_t version_ = 0;
    uint8_t dcid_size_ = 0;
    bool stopped_ = false;
};

// ============================================================================
// HTTP 嗅探（从 Host 头提取域名）
// ============================================================================
class HttpSniffer {
public:
    SniffResult Sniff(std::span<const uint8_t> data);

private:
    struct HostPortView {
        std::string_view host;
        uint16_t port = 0;
    };

    std::optional<HostPortView> ParseHttpHost(std::span<const uint8_t> data);
};

// ============================================================================
// BitTorrent 嗅探（只识别协议，用于 routing.protocol）
// ============================================================================
class BittorrentSniffer {
public:
    SniffResult Sniff(std::span<const uint8_t> data);
};

// One instance per sniff stage. TCP consumes the cumulative prefix; UDP consumes
// individual datagrams and retains only bounded QUIC CRYPTO reassembly state.
class Sniffer {
public:
    [[nodiscard]] SniffResult Sniff(std::span<const uint8_t> data, Network network);

private:
    QuicSniffer quic_;
};

}  // namespace acpp
