#include "acppnode/transport/internet/stream_settings.hpp"
#include "tls_context_cache.hpp"
#include "tls_context_cache_key.hpp"

#include <cstdio>
#include <memory>
#include <string>
#include <unordered_map>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

int main() {
    using acpp::transport::internet::MakeRealityClientContextCacheKey;
    using acpp::transport::internet::MakeRealityServerContextCacheKey;
    using acpp::transport::internet::MakeTlsContextCacheKey;

    using TestMap = std::unordered_map<std::string, std::unique_ptr<int>>;
    acpp::transport::internet::BoundedTlsContextCache<int, TestMap> cache(2);

    acpp::TlsConfig mutable_config;
    const std::string original_key =
        MakeTlsContextCacheKey("client", mutable_config);
    int* original_context = cache.Insert(
        original_key, std::make_unique<int>(1));
    if (!Require(original_context && *original_context == 1 &&
                     cache.Find(original_key) == original_context,
                 "cache must reuse an unchanged content key")) {
        return 1;
    }

    mutable_config.allow_insecure = true;
    const std::string changed_key =
        MakeTlsContextCacheKey("client", mutable_config);
    if (!Require(cache.Find(changed_key) == nullptr,
                 "same-address config mutation must not hit a stale context")) {
        return 2;
    }
    int* changed_context = cache.Insert(
        changed_key, std::make_unique<int>(2));
    if (!Require(changed_context && changed_context != original_context &&
                     *changed_context == 2 &&
                     cache.Find(original_key) == original_context &&
                     cache.Find(changed_key) == changed_context,
                 "changed content key must create a distinct context")) {
        return 3;
    }

    acpp::TlsConfig joined_alpn;
    joined_alpn.alpn = {"h2|http/1.1"};
    acpp::TlsConfig split_alpn;
    split_alpn.alpn = {"h2", "http/1.1"};
    if (!Require(MakeTlsContextCacheKey("client", joined_alpn) !=
                     MakeTlsContextCacheKey("client", split_alpn),
                 "different ALPN sequences must not share a cache key")) {
        return 4;
    }

    acpp::TlsConfig joined_paths;
    joined_paths.cert_file = "a|b";
    joined_paths.key_file = "c";
    acpp::TlsConfig split_paths;
    split_paths.cert_file = "a";
    split_paths.key_file = "b|c";
    if (!Require(MakeTlsContextCacheKey("server", joined_paths) !=
                     MakeTlsContextCacheKey("server", split_paths),
                 "different certificate paths must not share a cache key")) {
        return 5;
    }

    acpp::RealityConfig joined_server_names;
    joined_server_names.server_names = {"a|b"};
    acpp::RealityConfig split_server_names;
    split_server_names.server_names = {"a", "b"};
    acpp::TlsConfig tls;
    if (!Require(MakeRealityServerContextCacheKey(joined_server_names, tls) !=
                     MakeRealityServerContextCacheKey(split_server_names, tls),
                 "different REALITY server-name lists must not share a cache key")) {
        return 6;
    }

    acpp::RealityConfig joined_short_ids;
    joined_short_ids.short_ids = {
        acpp::transport::internet::RealityShortId{1, 2}};
    acpp::RealityConfig split_short_ids;
    split_short_ids.short_ids = {
        acpp::transport::internet::RealityShortId{1},
        acpp::transport::internet::RealityShortId{2}};
    if (!Require(MakeRealityServerContextCacheKey(joined_short_ids, tls) !=
                     MakeRealityServerContextCacheKey(split_short_ids, tls),
                 "different REALITY short-ID lists must not share a cache key")) {
        return 7;
    }

    acpp::RealityConfig joined_client;
    joined_client.public_key =
        acpp::transport::internet::RealityKey{1, 2};
    joined_client.server_name = "c";
    acpp::RealityConfig split_client;
    split_client.public_key =
        acpp::transport::internet::RealityKey{1};
    split_client.server_name = "b|c";
    if (!Require(MakeRealityClientContextCacheKey(joined_client, tls) !=
                     MakeRealityClientContextCacheKey(split_client, tls),
                 "different REALITY client fields must not share a cache key")) {
        return 8;
    }
    return 0;
}
