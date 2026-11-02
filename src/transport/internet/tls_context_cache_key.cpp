#include "tls_context_cache_key.hpp"

#include "acppnode/transport/internet/stream_settings.hpp"

#include <cstdint>
#include <utility>
#include <vector>

namespace acpp::transport::internet {
namespace {

class CacheKeyBuilder {
public:
    void AppendString(std::string_view value) {
        AppendUint64(static_cast<uint64_t>(value.size()));
        key_.append(value);
    }

    void AppendStrings(const std::vector<std::string>& values) {
        AppendUint64(static_cast<uint64_t>(values.size()));
        for (const auto& value : values) AppendString(value);
    }

    void AppendRealityVersion(
        const std::optional<RealityClientVersion>& version) {
        AppendByte(version ? 1 : 0);
        if (!version) return;
        for (const uint8_t component : *version) AppendByte(component);
    }

    void AppendRealityShortId(const RealityShortId& short_id) {
        for (const uint8_t value : short_id) AppendByte(value);
    }

    void AppendRealityShortIds(const std::vector<RealityShortId>& short_ids) {
        AppendUint64(static_cast<uint64_t>(short_ids.size()));
        for (const auto& short_id : short_ids) AppendRealityShortId(short_id);
    }

    void AppendRealityKey(const std::optional<RealityKey>& key) {
        AppendByte(key ? 1 : 0);
        if (!key) return;
        for (const uint8_t value : *key) AppendByte(value);
    }

    void AppendRealityMldsa65PublicKey(
        const std::shared_ptr<const RealityMldsa65PublicKey>& key) {
        AppendByte(key ? 1 : 0);
        if (!key) return;
        key_.append(
            reinterpret_cast<const char*>(key->data()),
            key->size());
    }
    void AppendByte(uint8_t value) {
        key_.push_back(static_cast<char>(value));
    }

    void AppendUint64(uint64_t value) {
        for (unsigned int shift = 0; shift < 64; shift += 8) {
            AppendByte(static_cast<uint8_t>(value >> shift));
        }
    }

    [[nodiscard]] std::string Finish() && {
        return std::move(key_);
    }

private:
    std::string key_;
};

}  // namespace

std::string MakeTlsContextCacheKey(
    std::string_view role,
    const TlsConfig& config) {
    CacheKeyBuilder key;
    key.AppendString(role);
    key.AppendString(config.cert_file);
    key.AppendString(config.key_file);
    key.AppendString(config.ca_file);
    key.AppendString(config.server_name);
    key.AppendByte(config.allow_insecure ? 1 : 0);
    key.AppendByte(static_cast<uint8_t>(config.min_version));
    key.AppendByte(static_cast<uint8_t>(config.max_version));
    key.AppendStrings(config.alpn);
    return std::move(key).Finish();
}

std::string MakeRealityServerContextCacheKey(
    const RealityConfig& reality,
    const TlsConfig& tls_config) {
    CacheKeyBuilder key;
    key.AppendString(MakeTlsContextCacheKey("server-reality", tls_config));
    key.AppendRealityKey(reality.private_key);
    key.AppendRealityKey(reality.mldsa65_seed);
    key.AppendString(reality.dest_host);
    key.AppendUint64(reality.dest_port);
    key.AppendByte(reality.xver);
    key.AppendRealityVersion(reality.min_client_version);
    key.AppendRealityVersion(reality.max_client_version);
    key.AppendUint64(reality.max_time_diff);
    key.AppendStrings(reality.server_names);
    key.AppendRealityShortIds(reality.short_ids);
    return std::move(key).Finish();
}

std::string MakeRealityClientContextCacheKey(
    const RealityConfig& reality,
    const TlsConfig& tls_config) {
    CacheKeyBuilder key;
    key.AppendString(MakeTlsContextCacheKey("client-reality", tls_config));
    key.AppendRealityKey(reality.public_key);
    key.AppendString(reality.server_name);
    key.AppendRealityShortId(reality.short_id);
    key.AppendString(reality.fingerprint);
    key.AppendString(reality.spider_x);
    key.AppendRealityMldsa65PublicKey(reality.mldsa65_verify);
    return std::move(key).Finish();
}

}  // namespace acpp::transport::internet
