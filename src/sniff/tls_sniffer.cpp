#include "acppnode/sniff/sniffer.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/unsafe.hpp"       // ISSUE-02-02: unsafe cast 收敛
#include <cstring>

namespace acpp {

// ============================================================================
// TLS 协议常量
// ============================================================================
namespace tls {
    constexpr uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
    constexpr uint8_t HANDSHAKE_CLIENT_HELLO = 0x01;
    constexpr uint16_t EXTENSION_SNI = 0x0000;
    constexpr uint8_t SNI_HOST_NAME = 0x00;
    
    // TLS 版本
    constexpr uint16_t TLS_1_0 = 0x0301;
    constexpr uint16_t TLS_1_3 = 0x0304;
}

// ============================================================================
// TLS Sniffer 实现
// ============================================================================

SniffResult TlsSniffer::Sniff(std::span<const uint8_t> data) {
    SniffResult result;
    
    auto sni = ParseClientHello(data);
    if (sni) {
        result.success = true;
        result.protocol = "tls";
        result.domain = *sni;
        result.port = 0;  // TLS 不包含端口信息
    }
    
    return result;
}

std::optional<std::string> TlsSniffer::ParseClientHello(std::span<const uint8_t> data) {
    // 最小 TLS ClientHello 长度检查
    // 5 (record header) + 4 (handshake header) + 2 (version) + 32 (random) + 1 (session id len)
    if (data.size() < 44) {
        return std::nullopt;
    }
    
    size_t pos = 0;
    
    // TLS Record Layer
    // Content Type (1 byte) = 0x16 (Handshake)
    if (data[pos] != tls::CONTENT_TYPE_HANDSHAKE) {
        return std::nullopt;
    }
    pos++;
    
    // Version (2 bytes)
    uint16_t record_version = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    if (record_version < tls::TLS_1_0 || record_version > tls::TLS_1_3) {
        // 不是有效的 TLS 版本，但允许一些变体
        if (record_version != 0x0300) {  // SSL 3.0
            return std::nullopt;
        }
    }
    pos += 2;
    
    // Length (2 bytes)
    uint16_t record_length = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    
    if (pos + record_length > data.size()) {
        // 数据不完整，但可以尝试继续解析
    }
    
    // Handshake Protocol
    // Handshake Type (1 byte) = 0x01 (ClientHello)
    if (data[pos] != tls::HANDSHAKE_CLIENT_HELLO) {
        return std::nullopt;
    }
    pos++;
    
    // Length (3 bytes)
    uint32_t handshake_length = (static_cast<uint32_t>(data[pos]) << 16) |
                                 (static_cast<uint32_t>(data[pos + 1]) << 8) |
                                 data[pos + 2];
    pos += 3;
    (void)handshake_length;  // 避免未使用警告
    
    // ClientHello
    // Version (2 bytes)
    pos += 2;
    
    // Random (32 bytes)
    pos += 32;
    
    // Session ID Length (1 byte) + Session ID
    if (pos >= data.size()) return std::nullopt;
    uint8_t session_id_len = data[pos++];
    pos += session_id_len;
    
    // Cipher Suites Length (2 bytes) + Cipher Suites
    if (pos + 2 > data.size()) return std::nullopt;
    uint16_t cipher_suites_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2 + cipher_suites_len;
    
    // Compression Methods Length (1 byte) + Compression Methods
    if (pos >= data.size()) return std::nullopt;
    uint8_t compression_len = data[pos++];
    pos += compression_len;
    
    // Extensions Length (2 bytes)
    if (pos + 2 > data.size()) return std::nullopt;
    uint16_t extensions_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    
    if (pos + extensions_len > data.size()) {
        // 扩展数据可能被截断，使用剩余数据
        extensions_len = static_cast<uint16_t>(data.size() - pos);
    }
    
    // 解析扩展
    return ExtractSNI(data.subspan(pos, extensions_len));
}

std::optional<std::string> TlsSniffer::ExtractSNI(std::span<const uint8_t> extensions) {
    size_t pos = 0;
    
    while (pos + 4 <= extensions.size()) {
        // Extension Type (2 bytes)
        uint16_t ext_type = (static_cast<uint16_t>(extensions[pos]) << 8) | extensions[pos + 1];
        pos += 2;
        
        // Extension Length (2 bytes)
        uint16_t ext_len = (static_cast<uint16_t>(extensions[pos]) << 8) | extensions[pos + 1];
        pos += 2;
        
        if (pos + ext_len > extensions.size()) {
            break;
        }
        
        if (ext_type == tls::EXTENSION_SNI) {
            // Server Name Indication Extension
            size_t sni_pos = pos;
            
            // SNI List Length (2 bytes)
            if (sni_pos + 2 > pos + ext_len) break;
            uint16_t sni_list_len = (static_cast<uint16_t>(extensions[sni_pos]) << 8) | 
                                     extensions[sni_pos + 1];
            sni_pos += 2;
            
            size_t sni_end = sni_pos + sni_list_len;
            if (sni_end > pos + ext_len) sni_end = pos + ext_len;
            
            while (sni_pos + 3 <= sni_end) {
                // Name Type (1 byte)
                uint8_t name_type = extensions[sni_pos++];
                
                // Name Length (2 bytes)
                uint16_t name_len = (static_cast<uint16_t>(extensions[sni_pos]) << 8) |
                                     extensions[sni_pos + 1];
                sni_pos += 2;
                
                if (sni_pos + name_len > sni_end) break;
                
                if (name_type == tls::SNI_HOST_NAME) {
                    // 提取主机名
                    // ISSUE-02-02: 使用 unsafe::ptr_cast 替代 reinterpret_cast
                    std::string hostname(
                        unsafe::ptr_cast<const char>(&extensions[sni_pos]),
                        name_len);
                    
                    // 验证主机名格式
                    if (!hostname.empty() && hostname.find('\0') == std::string::npos) {
                        return hostname;
                    }
                }
                
                sni_pos += name_len;
            }
        }
        
        pos += ext_len;
    }
    
    return std::nullopt;
}

}  // namespace acpp
